package openapimcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/maximhq/bifrost/core/schemas"
)

// forbiddenArgHeaders can never be set from tool arguments or resolver output.
var forbiddenArgHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
}

// defaultAccept prefers JSON but accepts anything the upstream wants to send.
const defaultAccept = "application/json, text/*;q=0.9, */*;q=0.1"

// Executor turns tool calls into HTTP requests against one upstream.
type Executor struct {
	baseURL         string
	baseURLExplicit bool
	client          *http.Client
	headers         HeaderResolver
	creds           map[string]schemas.MCPOpenAPICredential
	doc             *Document
	maxBytes        int
	logger          schemas.Logger
}

// NewExecutor validates ServerOptions and returns the executor the synthesized
// tool handlers share.
func NewExecutor(opts ServerOptions) (*Executor, error) {
	if opts.Synthesis == nil || opts.Synthesis.Document == nil {
		return nil, errors.New("synthesis is required")
	}
	base := strings.TrimSpace(opts.BaseURL)
	// An empty base is fine when every operation carries its own server, which
	// BuildRequest then uses.
	servedPerOperation := base == "" && !opts.BaseURLExplicit && operationServersCover(opts.Synthesis)
	if !servedPerOperation && !isAbsoluteHTTPURL(base) {
		return nil, fmt.Errorf("base URL %q must be an absolute http(s) URL", base)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	return &Executor{
		baseURL:         strings.TrimSuffix(base, "/"),
		baseURLExplicit: opts.BaseURLExplicit,
		client:          client,
		headers:         opts.Headers,
		creds:           opts.Credentials,
		doc:             opts.Synthesis.Document,
		maxBytes:        maxBytes,
		logger:          opts.Logger,
	}, nil
}

// BuildRequest assembles the HTTP request for one tool call from its arguments.
func (e *Executor) BuildRequest(ctx context.Context, tool *Tool, args map[string]any) (*http.Request, error) {
	if tool == nil {
		return nil, errors.New("tool is nil")
	}
	if args == nil {
		args = map[string]any{}
	}
	op := tool.Operation

	base := e.baseURL
	if !e.baseURLExplicit && len(op.Servers) > 0 && isAbsoluteHTTPURL(op.Servers[0]) {
		base = strings.TrimSuffix(op.Servers[0], "/")
	}

	path := op.Path
	query := url.Values{}
	headers := http.Header{}
	argCookies := newCookieSet()
	rawQuerystring := ""

	for _, arg := range tool.Args {
		value, present := args[arg.ArgName]
		if !present || value == nil {
			if arg.Required {
				return nil, fmt.Errorf("missing required %s parameter %q", arg.Location, arg.Name)
			}
			continue
		}
		if isJSONMediaType(arg.ContentType) {
			// Declared through `content`: the whole value is one JSON document.
			data, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("encoding %s parameter %q as JSON: %w", arg.Location, arg.Name, err)
			}
			value = string(data)
		}
		switch arg.Location {
		case InPath:
			if scalar := stringify(value, ","); scalar == "" || scalar == "." || scalar == ".." {
				return nil, fmt.Errorf("invalid value %q for path parameter %q", scalar, arg.Name)
			}
			path = strings.ReplaceAll(path, "{"+arg.Name+"}", encodePathValue(arg, value))
		case InQuery:
			addQueryValue(query, arg, value)
		case InHeader:
			name := http.CanonicalHeaderKey(arg.Name)
			if forbiddenArgHeaders[name] {
				return nil, fmt.Errorf("header parameter %q cannot be set from tool arguments", arg.Name)
			}
			headers.Set(name, stringify(value, ","))
		case InCookie:
			argCookies.set(arg.Name, stringify(value, ","))
		case InQuerystring:
			rawQuerystring = strings.TrimPrefix(stringify(value, "&"), "?")
		}
	}
	if strings.Contains(path, "{") {
		return nil, fmt.Errorf("path %q has unresolved parameters", path)
	}

	bodyReader, contentType, err := e.encodeBody(tool, args)
	if err != nil {
		return nil, err
	}

	// Spec-mapped credentials: query/cookie ones must land before the URL is final.
	schemes := SelectSecurity(op, e.doc, e.creds)
	credHeaders := &http.Request{Header: http.Header{}}
	var credCookies []*http.Cookie
	InjectCredentials(credHeaders, query, &credCookies, schemes, e.creds)

	// The base URL is joined by component: its own query is kept alongside the
	// call's, its fragment is dropped, and the operation path extends its path.
	baseURL, err := url.Parse(base)
	if err != nil || base == "" {
		return nil, fmt.Errorf("base URL %q is not usable: %v", base, err)
	}
	for k, vals := range baseURL.Query() {
		for _, v := range vals {
			query.Add(k, v)
		}
	}
	baseURL.RawQuery, baseURL.Fragment, baseURL.RawFragment = "", "", ""
	target := strings.TrimSuffix(baseURL.String(), "/") + ensureLeadingSlash(path)
	encodedQuery := query.Encode()
	switch {
	case encodedQuery != "" && rawQuerystring != "":
		target += "?" + encodedQuery + "&" + rawQuerystring
	case encodedQuery != "":
		target += "?" + encodedQuery
	case rawQuerystring != "":
		target += "?" + rawQuerystring
	}

	req, err := http.NewRequestWithContext(ctx, op.Method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Cookies merge by name across the same layers as headers: the resolver's,
	// then declared cookie parameters, then spec-mapped credentials, the later
	// layer winning, so one name is sent once and the credential is authoritative.
	cookies := newCookieSet()
	// Layer 1: resolver headers (static config headers, credential store, extras).
	if e.headers != nil {
		resolved, err := e.headers(ctx)
		if err != nil {
			return nil, err
		}
		for name, values := range resolved {
			canonical := http.CanonicalHeaderKey(name)
			if forbiddenArgHeaders[canonical] || len(values) == 0 {
				continue
			}
			if canonical == "Cookie" {
				for _, v := range values {
					cookies.parse(v)
				}
				continue
			}
			req.Header[canonical] = append([]string(nil), values...)
		}
	}
	// Layer 2: declared header parameters carry the model's value.
	for name, values := range headers {
		req.Header[name] = values
	}
	// Layer 3: spec-mapped credentials win for the names they own.
	for name, values := range credHeaders.Header {
		req.Header[name] = values
	}
	cookies.merge(argCookies)
	for _, c := range credCookies {
		cookies.set(c.Name, c.Value)
	}
	if header, err := cookies.header(); err != nil {
		return nil, err
	} else if header != "" {
		req.Header.Set("Cookie", header)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", defaultAccept)
	}
	return req, nil
}

// encodeBody serializes the body arguments per the tool's binding.
func (e *Executor) encodeBody(tool *Tool, args map[string]any) (io.Reader, string, error) {
	binding := tool.Body
	if binding == nil {
		return nil, "", nil
	}
	required := tool.Operation.Body != nil && tool.Operation.Body.Required
	var payload any
	present := false
	switch binding.Mode {
	// Presence is the key, not the value: an explicit null is sent (it clears a
	// field in a PATCH) and only an absent argument is left out.
	case "flattened":
		m := map[string]any{}
		for _, name := range binding.ArgNames {
			if v, ok := args[name]; ok {
				m[name] = v
			}
		}
		present = len(m) > 0
		payload = m
	default:
		v, ok := args[binding.SingleArg]
		present = ok
		payload = v
	}
	if !present {
		if required {
			if binding.Mode == "flattened" {
				payload = map[string]any{}
			} else {
				return nil, "", fmt.Errorf("missing required request body argument %q", binding.SingleArg)
			}
		} else {
			return nil, "", nil
		}
	}
	switch binding.ContentType {
	case ContentTypeForm:
		values := url.Values{}
		obj, ok := payload.(map[string]any)
		if !ok {
			return nil, "", errors.New("form request body must be an object")
		}
		var delimiters map[string]string
		if tool.Operation.Body != nil {
			delimiters = tool.Operation.Body.FormDelimiters
		}
		for _, key := range sortedKeys(obj) {
			switch v := obj[key].(type) {
			case []any:
				if delim, ok := delimiters[key]; ok {
					parts := make([]string, len(v))
					for i, item := range v {
						parts[i] = stringify(item, ",")
					}
					values.Add(key, strings.Join(parts, delim))
					continue
				}
				for _, item := range v {
					values.Add(key, stringify(item, ","))
				}
			default:
				values.Add(key, stringify(v, ","))
			}
		}
		return strings.NewReader(values.Encode()), ContentTypeForm, nil
	case ContentTypeText:
		return strings.NewReader(stringify(payload, "\n")), "text/plain; charset=utf-8", nil
	default:
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, "", fmt.Errorf("encoding JSON body: %w", err)
		}
		contentType := ContentTypeJSON
		if isJSONMediaType(binding.ContentType) {
			contentType = binding.ContentType
		}
		return bytes.NewReader(data), contentType, nil
	}
}

// clientFor returns the client to send req with. A request carrying more than
// the default headers (spec-mapped credentials, resolver headers, declared
// header parameters) or any query must not follow a redirect to another host:
// Go strips only Authorization and Cookie there, so an API-key header would
// reach the new host. Nor may it follow one from https to plain http on the
// same host, which would send every credential unencrypted. Such a redirect
// is returned to the model as the 3xx instead. Any CheckRedirect already on the client still runs for same-host
// redirects.
func (e *Executor) clientFor(req *http.Request) *http.Client {
	carries := req.URL.RawQuery != ""
	for name := range req.Header {
		if name != "Accept" && name != "Content-Type" {
			carries = true
			break
		}
	}
	if !carries {
		return e.client
	}
	c := *e.client
	inner := e.client.CheckRedirect
	origin, secure := req.URL.Host, req.URL.Scheme == "https"
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !strings.EqualFold(next.URL.Host, origin) || (secure && next.URL.Scheme != "https") {
			return http.ErrUseLastResponse
		}
		if inner != nil {
			return inner(next, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &c
}

// Execute sends the tool call upstream and converts the response into a tool
// result. Transport failures and non-2xx statuses become error results (the
// model sees them); only argument/binding problems surface as Go errors.
func (e *Executor) Execute(ctx context.Context, tool *Tool, args map[string]any) (*mcp.CallToolResult, error) {
	req, err := e.BuildRequest(ctx, tool, args)
	if err != nil {
		return nil, err
	}
	if e.logger != nil {
		e.logger.Debug("[OpenAPI MCP] %s %s%s", req.Method, req.URL.Host, req.URL.Path)
	}
	resp, err := e.clientFor(req).Do(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("request to upstream failed: %v", sanitizeURLError(err))), nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(e.maxBytes)+1))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("reading upstream response failed: %v", err)), nil
	}
	truncated := len(body) > e.maxBytes
	if truncated {
		body = body[:e.maxBytes]
	}
	return formatResponse(resp, body, truncated, e.maxBytes), nil
}

// sanitizeURLError strips the query string from url.Error messages so a
// credential carried as a query parameter never reaches logs or the model.
func sanitizeURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if u, perr := url.Parse(uerr.URL); perr == nil && u.RawQuery != "" {
			u.RawQuery = ""
			return &url.Error{Op: uerr.Op, URL: u.String(), Err: uerr.Err}
		}
	}
	return err
}

// textualContentTypes lists response media types returned verbatim.
func isTextualContentType(ct string, body []byte) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	switch {
	case ct == "":
		return utf8.Valid(body)
	case strings.HasPrefix(ct, "text/"):
		return true
	case strings.Contains(ct, "json"), strings.Contains(ct, "xml"), strings.Contains(ct, "yaml"):
		return true
	case ct == ContentTypeForm, ct == "application/javascript", ct == "application/x-ndjson":
		return true
	}
	return false
}

func formatResponse(resp *http.Response, body []byte, truncated bool, limit int) *mcp.CallToolResult {
	ct := resp.Header.Get("Content-Type")
	var text string
	if isTextualContentType(ct, body) {
		text = string(body)
		if truncated {
			text += fmt.Sprintf("\n…[response truncated at %d bytes]", limit)
		}
	} else {
		size := strconv.Itoa(len(body))
		if truncated {
			size = "more than " + size
		}
		text = fmt.Sprintf("[binary response: %s, %s bytes]", ct, size)
	}
	status := fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if text == "" {
			return mcp.NewToolResultError(status)
		}
		return mcp.NewToolResultError(status + "\n" + text)
	}
	if len(body) == 0 {
		return mcp.NewToolResultText(status)
	}
	return mcp.NewToolResultText(text)
}

// addQueryValue serializes one query argument honoring explode/style.
func addQueryValue(q url.Values, arg ArgBinding, value any) {
	switch v := value.(type) {
	case []any:
		if arg.Explode {
			for _, item := range v {
				q.Add(arg.Name, stringify(item, ","))
			}
			return
		}
		q.Add(arg.Name, stringify(v, delimiterFor(arg.Style)))
	case map[string]any:
		switch {
		case arg.Style == "deepObject":
			for _, key := range sortedKeys(v) {
				q.Add(arg.Name+"["+key+"]", stringify(v[key], ","))
			}
		case arg.Explode:
			for _, key := range sortedKeys(v) {
				q.Add(key, stringify(v[key], ","))
			}
		case arg.Style == "" || arg.Style == "form":
			q.Add(arg.Name, strings.Join(objectPairs(v), ","))
		default:
			data, _ := json.Marshal(v)
			q.Add(arg.Name, string(data))
		}
	default:
		q.Add(arg.Name, stringify(v, ","))
	}
}

// objectPairs flattens an object to key,value,key,value in key order, the
// non-exploded form/simple/label/matrix serialization.
func objectPairs(v map[string]any) []string {
	out := make([]string, 0, 2*len(v))
	for _, key := range sortedKeys(v) {
		out = append(out, key, stringify(v[key], ","))
	}
	return out
}

// encodePathValue serializes a path parameter per its style (simple, label or
// matrix) and explode flag. Each value is escaped on its own; the separators
// the style adds are not.
func encodePathValue(arg ArgBinding, value any) string {
	var items []string // already escaped
	keyed := false     // items are key=value (exploded objects)
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			items = append(items, url.PathEscape(stringify(item, ",")))
		}
	case map[string]any:
		for _, key := range sortedKeys(v) {
			if arg.Explode {
				items = append(items, url.PathEscape(key)+"="+url.PathEscape(stringify(v[key], ",")))
				keyed = true
			} else {
				items = append(items, url.PathEscape(key), url.PathEscape(stringify(v[key], ",")))
			}
		}
	default:
		items = []string{url.PathEscape(stringify(v, ","))}
	}
	_, isList := value.([]any)
	switch arg.Style {
	case "label":
		if arg.Explode {
			return "." + strings.Join(items, ".")
		}
		return "." + strings.Join(items, ",")
	case "matrix":
		name := url.PathEscape(arg.Name)
		switch {
		case keyed:
			return ";" + strings.Join(items, ";")
		case isList && arg.Explode:
			return ";" + name + "=" + strings.Join(items, ";"+name+"=")
		default:
			return ";" + name + "=" + strings.Join(items, ",")
		}
	default:
		return strings.Join(items, ",")
	}
}

// cookieSet holds cookies by name in first-seen order; a later set wins.
type cookieSet struct {
	names  []string
	values map[string]string
}

func newCookieSet() *cookieSet { return &cookieSet{values: map[string]string{}} }

func (c *cookieSet) set(name, value string) {
	if _, seen := c.values[name]; !seen {
		c.names = append(c.names, name)
	}
	c.values[name] = value
}

// parse adds every name=value pair of a Cookie header value.
func (c *cookieSet) parse(header string) {
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" {
			c.set(name, value)
		}
	}
}

func (c *cookieSet) merge(other *cookieSet) {
	for _, name := range other.names {
		c.set(name, other.values[name])
	}
}

// header renders the Cookie header. Values are sent as given (cookie readers
// do not URL-decode), so a value carrying a character a cookie cannot hold is
// an error rather than a silently different value.
func (c *cookieSet) header() (string, error) {
	parts := make([]string, 0, len(c.names))
	for _, name := range c.names {
		value := c.values[name]
		if !validCookieValue(value) {
			return "", fmt.Errorf("cookie %q has a value that cannot be sent in a cookie (no whitespace, quotes, semicolons, backslashes or non-ASCII)", name)
		}
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; "), nil
}

func validCookieValue(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b <= 0x20 || b >= 0x7f || b == '"' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}

func delimiterFor(style string) string {
	switch style {
	case "spaceDelimited":
		return " "
	case "pipeDelimited":
		return "|"
	case "tabDelimited":
		return "\t"
	}
	return ","
}

// stringify renders an argument for the wire: scalars as text, arrays joined by
// sep, objects as JSON.
func stringify(v any, sep string) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, stringify(item, sep))
		}
		return strings.Join(parts, sep)
	case []string:
		return strings.Join(t, sep)
	case map[string]any:
		data, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(data)
	default:
		data, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return strings.Trim(string(data), `"`)
	}
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}
