import type {
	MCPOpenAPIConfig,
	MCPOpenAPICredential,
	MCPOpenAPIPreviewResponse,
	MCPOpenAPIPreviewTool,
	MCPOpenAPISecurityScheme,
	MCPOpenAPIUnsupportedOperation,
	SecretVar,
} from "@/lib/types/mcp";

/** How the user supplied the document in the create/replace sheet. */
export type OpenAPISourceMode = "paste" | "url" | "upload";

/** Client-side cap on a pasted or uploaded document, mirroring the server's 5 MiB limit. */
export const OPENAPI_MAX_SPEC_BYTES = 5 * 1024 * 1024;

/** Picks the editor language from the document's first non-blank character. */
export function detectSpecLanguage(text: string | undefined): "json" | "yaml" {
	const trimmed = (text ?? "").replace(/^﻿/, "").trimStart();
	if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json";
	return "yaml";
}

/**
 * Identity of the source the preview was computed from, so a later edit to the
 * text or URL invalidates the preview until the user parses again. The client
 * name is part of it because long tool names are shortened to fit beside it.
 */
export function specFingerprint(
	mode: OpenAPISourceMode,
	spec: string | undefined,
	specUrl: string | undefined,
	clientName?: string,
): string {
	const name = (clientName ?? "").trim();
	const source = mode === "url" ? `url:${(specUrl ?? "").trim()}` : `${mode}:${spec ?? ""}`;
	return name ? `${source}|${name}` : source;
}

/** One row of the operation picker: supported tools and unsupported operations, in one list. */
export interface OpenAPIPreviewRow {
	key: string;
	name: string;
	operationId?: string;
	method: string;
	path: string;
	description?: string;
	deprecated: boolean;
	supported: boolean;
	skipReason?: string;
	warnings: string[];
}

export function mergePreviewRows(
	tools: MCPOpenAPIPreviewTool[] | undefined,
	unsupported: MCPOpenAPIUnsupportedOperation[] | undefined,
): OpenAPIPreviewRow[] {
	const rows: OpenAPIPreviewRow[] = (tools ?? []).map((tool) => ({
		key: tool.name,
		name: tool.name,
		operationId: tool.operation_id,
		method: tool.method,
		path: tool.path,
		description: tool.summary || tool.description,
		deprecated: !!tool.deprecated,
		supported: true,
		warnings: tool.warnings ?? [],
	}));
	for (const op of unsupported ?? []) {
		rows.push({
			key: `${op.method} ${op.path}`,
			name: op.operation_id || `${op.method.toLowerCase()} ${op.path}`,
			operationId: op.operation_id,
			method: op.method,
			path: op.path,
			deprecated: /deprecated/i.test(op.reason),
			supported: false,
			skipReason: op.reason,
			warnings: [],
		});
	}
	return rows;
}

export function supportedToolNames(preview: MCPOpenAPIPreviewResponse | null | undefined): string[] {
	return (preview?.tools ?? []).map((tool) => tool.name);
}

/**
 * The wire form of a tool selection: `["*"]` when every supported tool is
 * picked, otherwise the picked names in preview order (unknown names dropped).
 */
export function collapseToolSelection(selected: string[], supported: string[]): string[] {
	const picked = new Set(selected);
	const kept = supported.filter((name) => picked.has(name));
	if (supported.length > 0 && kept.length === supported.length) return ["*"];
	return kept;
}

/** Expands a stored allow-list back into explicit names for the picker. */
export function expandToolSelection(stored: string[] | undefined, supported: string[]): string[] {
	if (!stored) return [];
	if (stored.includes("*")) return [...supported];
	const known = new Set(supported);
	return stored.filter((name) => known.has(name));
}

/**
 * Carries a selection across a re-parse: an "everything" selection stays
 * everything (new tools included); a partial selection keeps the names that
 * still exist, and leaves newly appeared tools unselected.
 */
export function reconcileToolSelection(previous: string[], previousAll: string[], nextSupported: string[]): string[] {
	const wasAll = previous.includes("*") || (previousAll.length > 0 && previousAll.every((name) => previous.includes(name)));
	if (wasAll) return [...nextSupported];
	const kept = new Set(previous);
	return nextSupported.filter((name) => kept.has(name));
}

export type OpenAPICredentialField = "value" | "username" | "password";

export interface OpenAPISecurityInput {
	scheme: MCPOpenAPISecurityScheme;
	label: string;
	fields: { field: OpenAPICredentialField; label: string; placeholder: string }[];
	helper?: string;
}

/** Renders a security scheme as the credential inputs it needs. Unsupported schemes get no fields. */
export function securitySchemeToInputs(scheme: MCPOpenAPISecurityScheme): OpenAPISecurityInput {
	if (!scheme.supported) {
		return { scheme, label: scheme.name, fields: [], helper: scheme.reason };
	}
	if (scheme.type === "apiKey") {
		const where = scheme.in ?? "header";
		return {
			scheme,
			label: `${scheme.name} · ${scheme.param_name ?? "API key"} (${where})`,
			fields: [{ field: "value", label: "API key", placeholder: `Value or env.${toEnvName(scheme.name)}` }],
			helper: scheme.description,
		};
	}
	if (scheme.type === "http" && scheme.scheme === "basic") {
		return {
			scheme,
			label: `${scheme.name} · Basic authentication`,
			fields: [
				{ field: "username", label: "Username", placeholder: "Username" },
				{ field: "password", label: "Password", placeholder: `Password or env.${toEnvName(scheme.name)}_PASSWORD` },
			],
			helper: scheme.description,
		};
	}
	return {
		scheme,
		label: `${scheme.name} · Bearer token`,
		fields: [{ field: "value", label: "Bearer token", placeholder: `Token or env.${toEnvName(scheme.name)}` }],
		helper: scheme.description,
	};
}

function toEnvName(name: string): string {
	return (
		name
			.replace(/[^A-Za-z0-9]+/g, "_")
			.replace(/^_+|_+$/g, "")
			.toUpperCase() || "API_KEY"
	);
}

function isSecretSet(v: SecretVar | undefined): boolean {
	return !!v && (!!v.value?.trim() || !!v.ref?.trim());
}

/** Drops credentials with no value set, so an untouched scheme is not sent as an empty secret. */
export function pruneCredentials(
	creds: Record<string, MCPOpenAPICredential> | undefined,
	schemes: MCPOpenAPISecurityScheme[] | undefined,
): Record<string, MCPOpenAPICredential> | undefined {
	if (!creds) return undefined;
	const declared = schemes ? new Set(schemes.filter((s) => s.supported).map((s) => s.name)) : undefined;
	const out: Record<string, MCPOpenAPICredential> = {};
	const basic = new Set((schemes ?? []).filter((s) => s.type === "http" && s.scheme === "basic").map((s) => s.name));
	for (const [name, cred] of Object.entries(creds)) {
		if (declared && !declared.has(name)) continue;
		// The server keeps a stored secret for a field left empty, so a Basic
		// credential with one field cleared is dropped whole; sending only the
		// other field would leave the old secret in place.
		if (basic.has(name) && !(isSecretSet(cred.username) && isSecretSet(cred.password))) continue;
		const kept: MCPOpenAPICredential = {};
		if (isSecretSet(cred.value)) kept.value = cred.value;
		if (isSecretSet(cred.username)) kept.username = cred.username;
		if (isSecretSet(cred.password)) kept.password = cred.password;
		if (Object.keys(kept).length > 0) out[name] = kept;
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * The openapi_config sent on create or replace: the document inline (URL mode
 * stores the text fetched for the preview, never older pasted or stored text,
 * and keeps the URL as provenance; paste and upload clear a stored URL), the
 * base URL as shown (empty clears a stored override), and the credentials
 * that were filled in. A provided credential map whose values were all cleared
 * is sent as {} so the server clears the stored secrets; leaving
 * security_credentials undefined keeps them.
 */
export function buildOpenAPIConfigPayload(
	cfg: MCPOpenAPIConfig | undefined,
	mode: OpenAPISourceMode,
	preview: MCPOpenAPIPreviewResponse | null | undefined,
): MCPOpenAPIConfig {
	const spec = mode === "url" ? preview?.spec : cfg?.spec?.trim() ? cfg.spec : preview?.spec;
	const specUrl = cfg?.spec_url?.trim();
	const out: MCPOpenAPIConfig = {};
	if (spec) out.spec = spec;
	if (mode === "url") {
		if (specUrl) out.spec_url = specUrl;
	} else {
		out.spec_url = "";
	}
	// The document's default server (its first absolute one) is sent as ""
	// rather than pinned: the backend resolves the same default, operation-level
	// servers keep applying, and on update "" clears an earlier override. The
	// preview's base_url is not the default: a re-parse echoes a chosen server.
	const base = cfg?.base_url?.trim() ?? "";
	const documentDefault = preview?.servers?.find((srv) => /^https?:\/\/[^/]/i.test(srv));
	const isDocumentDefault = !!documentDefault && trimSlash(documentDefault) === trimSlash(base);
	out.base_url = base && !isDocumentDefault ? base : "";
	if (cfg?.security_credentials !== undefined) {
		out.security_credentials = pruneCredentials(cfg.security_credentials, preview?.security_schemes) ?? {};
	}
	if (cfg?.include_deprecated) out.include_deprecated = true;
	if (cfg?.max_response_bytes) out.max_response_bytes = cfg.max_response_bytes;
	return out;
}

function trimSlash(url: string): string {
	return url.replace(/\/+$/, "");
}

export function formatBytes(n: number | undefined): string {
	if (!n || n <= 0) return "0 B";
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function isSpecTooLarge(bytes: number, max: number = OPENAPI_MAX_SPEC_BYTES): boolean {
	return bytes > max;
}

/** One-line description of a stored openapi_config for the edit sheet. */
export function summarizeSpecSource(cfg: MCPOpenAPIConfig | undefined): string {
	if (!cfg) return "-";
	const parts: string[] = [];
	const title = cfg.spec_title
		? `${cfg.spec_title}${cfg.openapi_version ? ` (OpenAPI ${cfg.openapi_version})` : ""}`
		: cfg.openapi_version
			? `OpenAPI ${cfg.openapi_version}`
			: "";
	if (title) parts.push(title);
	parts.push(cfg.spec_url ? cfg.spec_url : "inline spec");
	if (cfg.spec_size) parts.push(formatBytes(cfg.spec_size));
	if (cfg.operation_count !== undefined) parts.push(`${cfg.operation_count} operation${cfg.operation_count === 1 ? "" : "s"}`);
	return parts.join(" · ");
}
/** The form values a parse response is applied to. */
export interface OpenAPIParseState {
	selection: string[];
	baseUrl: string;
	baseUrlChoice: "server" | "custom";
	credentials: Record<string, MCPOpenAPICredential>;
}

/**
 * Applies a parse (preview) response to the form: the tool selection is
 * reconciled against the previous preview, the base URL follows the document
 * unless the user typed a custom one or picked a server the document still
 * lists, and credentials for schemes the document no longer declares are
 * dropped. current must be read when the response arrives, not when the parse
 * started, so edits made while it was in flight survive.
 */
export function applyParsedPreview(
	current: OpenAPIParseState,
	previousPreview: MCPOpenAPIPreviewResponse | null | undefined,
	response: MCPOpenAPIPreviewResponse,
): OpenAPIParseState {
	const nextSupported = supportedToolNames(response);
	const selection = previousPreview
		? reconcileToolSelection(current.selection, supportedToolNames(previousPreview), nextSupported)
		: nextSupported;
	let { baseUrl, baseUrlChoice } = current;
	const keepCustom = current.baseUrlChoice === "custom" && !!current.baseUrl.trim();
	const keepPicked = current.baseUrlChoice === "server" && !!current.baseUrl && !!response.servers?.includes(current.baseUrl);
	if (!keepCustom && !keepPicked) {
		if (response.operation_servers && !response.base_url) {
			// Every operation carries its own server: no base URL, nothing to pick.
			baseUrlChoice = "server";
			baseUrl = "";
		} else if (response.base_url && response.servers?.includes(response.base_url)) {
			baseUrlChoice = "server";
			baseUrl = response.base_url;
		} else {
			baseUrlChoice = "custom";
			baseUrl = response.base_url ?? "";
		}
	}
	const declared = new Set((response.security_schemes ?? []).filter((scheme) => scheme.supported).map((scheme) => scheme.name));
	const credentials: Record<string, MCPOpenAPICredential> = {};
	for (const [name, cred] of Object.entries(current.credentials)) {
		if (declared.has(name)) credentials[name] = cred;
	}
	return { selection, baseUrl, baseUrlChoice, credentials };
}

/** Reads an uploaded spec file, returning its text or the error to show. */
export async function readUploadedSpec(file: {
	size: number;
	text: () => Promise<string>;
}): Promise<{ text: string; error: string | null }> {
	if (isSpecTooLarge(file.size)) {
		return { text: "", error: `The file exceeds the ${formatBytes(OPENAPI_MAX_SPEC_BYTES)} limit for OpenAPI documents.` };
	}
	let text: string;
	try {
		text = await file.text();
	} catch (error) {
		return { text: "", error: `The file could not be read: ${error instanceof Error ? error.message : String(error)}` };
	}
	return { text, error: text.trim() ? null : "The file is empty." };
}
/**
 * Whether the form must have a base URL before the server can be created or
 * replaced: a custom choice needs its value, and so does a document with no
 * top-level server, unless every operation declares its own.
 */
export function openAPIBaseUrlRequired(choice: "server" | "custom", preview: MCPOpenAPIPreviewResponse | null | undefined): boolean {
	if (choice === "custom") return true;
	return (preview?.servers?.length ?? 0) === 0 && !preview?.operation_servers;
}