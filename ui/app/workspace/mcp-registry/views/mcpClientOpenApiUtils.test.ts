import { describe, expect, it } from "vitest";
import type { MCPOpenAPIPreviewResponse, MCPOpenAPISecurityScheme } from "@/lib/types/mcp";
import {
	applyParsedPreview,
	openAPIBaseUrlRequired,
	buildOpenAPIConfigPayload,
	collapseToolSelection,
	detectSpecLanguage,
	expandToolSelection,
	formatBytes,
	isSpecTooLarge,
	mergePreviewRows,
	pruneCredentials,
	readUploadedSpec,
	replacePreviewRequest,
	replacementAutoExecute,
	replacementIsDirty,
	reconcileToolSelection,
	securitySchemeToInputs,
	specFingerprint,
	summarizeSpecSource,
	supportedToolNames,
} from "./mcpClientOpenApiUtils";

const preview: MCPOpenAPIPreviewResponse = {
	title: "Petstore",
	version: "1.0.0",
	openapi_version: "3.0.3",
	servers: ["https://petstore.example.com/v1"],
	base_url: "https://petstore.example.com/v1",
	security_schemes: [
		{ name: "ApiKeyAuth", type: "apiKey", in: "header", param_name: "X-API-Key", supported: true },
		{ name: "OAuth", type: "oauth2", supported: false, reason: "oauth2 security schemes are not supported" },
	],
	tools: [
		{ name: "listPets", method: "GET", path: "/pets", summary: "List pets" },
		{ name: "createPet", method: "POST", path: "/pets" },
		{ name: "getPetById", method: "GET", path: "/pets/{petId}", description: "Info for a pet" },
	],
	unsupported: [
		{
			operation_id: "uploadPetPhoto",
			method: "POST",
			path: "/pets/{petId}/photo",
			reason: "multipart/form-data request body is not supported",
		},
	],
	warnings: [],
	tool_count: 3,
	spec_size: 1234,
	spec_hash: "abc",
};

describe("detectSpecLanguage", () => {
	it("recognizes JSON objects and arrays, defaults to YAML", () => {
		expect(detectSpecLanguage('{"openapi":"3.0.0"}')).toBe("json");
		expect(detectSpecLanguage("  \n[1]")).toBe("json");
		expect(detectSpecLanguage("﻿{")).toBe("json");
		expect(detectSpecLanguage("openapi: 3.0.0")).toBe("yaml");
		expect(detectSpecLanguage("")).toBe("yaml");
		expect(detectSpecLanguage(undefined)).toBe("yaml");
	});
});

describe("specFingerprint", () => {
	it("tracks the text for paste/upload and only the URL for url mode", () => {
		expect(specFingerprint("paste", "a", "u")).toBe("paste:a");
		expect(specFingerprint("upload", "a", "u")).toBe("upload:a");
		expect(specFingerprint("url", "a", " https://x ")).toBe("url:https://x");
		expect(specFingerprint("url", "changed text", "https://x")).toBe(specFingerprint("url", "a", "https://x"));
	});
	it("changes with the client name, which shortens long tool names", () => {
		expect(specFingerprint("paste", "a", "", "petstore")).not.toBe(specFingerprint("paste", "a", "", "zoo"));
		expect(specFingerprint("url", "a", "https://x", "petstore")).not.toBe(specFingerprint("url", "a", "https://x", "zoo"));
		expect(specFingerprint("paste", "a", "", " petstore ")).toBe(specFingerprint("paste", "a", "", "petstore"));
	});
});

describe("mergePreviewRows", () => {
	it("lists supported tools first and unsupported operations disabled with their reason", () => {
		const rows = mergePreviewRows(preview.tools, preview.unsupported);
		expect(rows.map((r) => r.name)).toEqual(["listPets", "createPet", "getPetById", "uploadPetPhoto"]);
		expect(rows[0].supported).toBe(true);
		expect(rows[0].description).toBe("List pets");
		expect(rows[2].description).toBe("Info for a pet");
		expect(rows[3].supported).toBe(false);
		expect(rows[3].skipReason).toContain("multipart");
		expect(rows[3].key).toBe("POST /pets/{petId}/photo");
	});
	it("flags deprecated skips and names anonymous operations by method and path", () => {
		const rows = mergePreviewRows([], [{ method: "DELETE", path: "/pets/{id}", reason: "deprecated (set include_deprecated)" }]);
		expect(rows[0].name).toBe("delete /pets/{id}");
		expect(rows[0].deprecated).toBe(true);
	});
});

describe("tool selection helpers", () => {
	const supported = supportedToolNames(preview);
	it("collapses a full selection to the wildcard and keeps preview order otherwise", () => {
		expect(supported).toEqual(["listPets", "createPet", "getPetById"]);
		expect(collapseToolSelection(["getPetById", "createPet", "listPets"], supported)).toEqual(["*"]);
		expect(collapseToolSelection(["getPetById", "listPets", "ghost"], supported)).toEqual(["listPets", "getPetById"]);
		expect(collapseToolSelection([], supported)).toEqual([]);
		expect(collapseToolSelection(["a"], [])).toEqual([]);
	});
	it("expands a stored allow-list for the picker", () => {
		expect(expandToolSelection(["*"], supported)).toEqual(supported);
		expect(expandToolSelection(["listPets", "ghost"], supported)).toEqual(["listPets"]);
		expect(expandToolSelection(undefined, supported)).toEqual([]);
	});
	it("reconciles a selection across a re-parse", () => {
		const next = ["listPets", "getPetById", "deletePet"];
		expect(reconcileToolSelection(["*"], supported, next)).toEqual(next);
		expect(reconcileToolSelection(supported, supported, next)).toEqual(next);
		expect(reconcileToolSelection(["listPets", "createPet"], supported, next)).toEqual(["listPets"]);
		expect(reconcileToolSelection([], supported, next)).toEqual([]);
	});
});

describe("securitySchemeToInputs", () => {
	it("maps apiKey, bearer and basic schemes to inputs and leaves unsupported ones without fields", () => {
		const apiKey = securitySchemeToInputs(preview.security_schemes[0]);
		expect(apiKey.label).toBe("ApiKeyAuth · X-API-Key (header)");
		expect(apiKey.fields.map((f) => f.field)).toEqual(["value"]);
		expect(apiKey.fields[0].placeholder).toContain("env.APIKEYAUTH");

		const bearer: MCPOpenAPISecurityScheme = { name: "Bearer-Token", type: "http", scheme: "bearer", supported: true };
		expect(securitySchemeToInputs(bearer).label).toBe("Bearer-Token · Bearer token");

		const basic: MCPOpenAPISecurityScheme = { name: "Basic", type: "http", scheme: "basic", supported: true };
		expect(securitySchemeToInputs(basic).fields.map((f) => f.field)).toEqual(["username", "password"]);

		const oauth = securitySchemeToInputs(preview.security_schemes[1]);
		expect(oauth.fields).toEqual([]);
		expect(oauth.helper).toContain("not supported");
	});
});

describe("pruneCredentials and buildOpenAPIConfigPayload", () => {
	it("drops empty credentials and undeclared schemes", () => {
		const pruned = pruneCredentials(
			{
				ApiKeyAuth: { value: { value: "k" } },
				Empty: { value: { value: "" } },
				Undeclared: { value: { value: "x" } },
			},
			preview.security_schemes,
		);
		expect(pruned).toEqual({ ApiKeyAuth: { value: { value: "k" } } });
		expect(pruneCredentials({ A: { value: { value: "" } } }, undefined)).toBeUndefined();
		expect(pruneCredentials(undefined, undefined)).toBeUndefined();
	});
	it("inlines the document, keeps the url as provenance in url mode, and omits untouched options", () => {
		const paste = buildOpenAPIConfigPayload(
			{ spec: "openapi: 3.0.0", spec_url: "https://ignored", base_url: " https://api.example.com " },
			"paste",
			preview,
		);
		expect(paste).toEqual({ spec: "openapi: 3.0.0", spec_url: "", base_url: "https://api.example.com" });

		const url = buildOpenAPIConfigPayload(
			{ spec: "", spec_url: "https://x/openapi.json", include_deprecated: true, max_response_bytes: 10 },
			"url",
			{
				...preview,
				spec: "fetched text",
			},
		);
		expect(url).toEqual({
			spec: "fetched text",
			spec_url: "https://x/openapi.json",
			base_url: "",
			include_deprecated: true,
			max_response_bytes: 10,
		});

		const withCreds = buildOpenAPIConfigPayload(
			{ spec: "x", security_credentials: { ApiKeyAuth: { value: { value: "k" } }, OAuth: { value: { value: "nope" } } } },
			"upload",
			preview,
		);
		expect(withCreds.security_credentials).toEqual({ ApiKeyAuth: { value: { value: "k" } } });
	});
	it("sends the fetched document in url mode, never stale pasted or stored text", () => {
		const url = buildOpenAPIConfigPayload({ spec: "old stored document", spec_url: "https://x/v2.json" }, "url", {
			...preview,
			spec: "new fetched document",
		});
		expect(url.spec).toBe("new fetched document");
		expect(url.spec_url).toBe("https://x/v2.json");
	});
	it("clears a stored spec_url when the document is pasted or uploaded", () => {
		for (const mode of ["paste", "upload"] as const) {
			const out = buildOpenAPIConfigPayload({ spec: "new text", spec_url: "https://old/openapi.json" }, mode, preview);
			expect(out.spec_url).toBe("");
		}
		expect(buildOpenAPIConfigPayload({ spec: "x", spec_url: "https://x/v2.json" }, "url", { ...preview, spec: "f" }).spec_url).toBe(
			"https://x/v2.json",
		);
	});
	it("sends an empty base_url when the override is cleared, so the stored one does not stay", () => {
		expect(buildOpenAPIConfigPayload({ spec: "x", base_url: "" }, "paste", preview)).toHaveProperty("base_url", "");
		expect(buildOpenAPIConfigPayload({ spec: "x" }, "paste", preview)).toHaveProperty("base_url", "");
	});
	it("drops a basic credential with a cleared field, so the server removes it instead of keeping the old secret", () => {
		const schemes: MCPOpenAPISecurityScheme[] = [{ name: "Basic", type: "http", scheme: "basic", supported: true }];
		expect(pruneCredentials({ Basic: { username: { value: "u" }, password: { value: "" } } }, schemes)).toBeUndefined();
		expect(pruneCredentials({ Basic: { username: { value: "" }, password: { value: "p" } } }, schemes)).toBeUndefined();
		expect(pruneCredentials({ Basic: { username: { value: "u" }, password: { value: "p" } } }, schemes)).toEqual({
			Basic: { username: { value: "u" }, password: { value: "p" } },
		});
		const cleared = buildOpenAPIConfigPayload(
			{ spec: "x", security_credentials: { Basic: { username: { value: "u" }, password: { value: "" } } } },
			"paste",
			{ ...preview, security_schemes: schemes },
		);
		expect(cleared.security_credentials).toEqual({});
	});
	it("sends an explicit empty credential map when every provided credential was cleared", () => {
		const cleared = buildOpenAPIConfigPayload(
			{ spec: "x", security_credentials: { ApiKeyAuth: { value: { value: "" } } } },
			"paste",
			preview,
		);
		expect(cleared.security_credentials).toEqual({});
		const untouched = buildOpenAPIConfigPayload({ spec: "x" }, "paste", preview);
		expect(untouched).not.toHaveProperty("security_credentials");
	});
});

describe("formatting helpers", () => {
	it("formats sizes and detects oversized documents", () => {
		expect(formatBytes(0)).toBe("0 B");
		expect(formatBytes(512)).toBe("512 B");
		expect(formatBytes(12 * 1024 + 410)).toBe("12.4 KB");
		expect(formatBytes(2 * 1024 * 1024)).toBe("2.0 MB");
		expect(isSpecTooLarge(5 * 1024 * 1024)).toBe(false);
		expect(isSpecTooLarge(5 * 1024 * 1024 + 1)).toBe(true);
	});
	it("summarizes a stored openapi_config", () => {
		expect(summarizeSpecSource({ spec_title: "Petstore", openapi_version: "3.0.3", spec_size: 12 * 1024 + 410, operation_count: 14 })).toBe(
			"Petstore (OpenAPI 3.0.3) · inline spec · 12.4 KB · 14 operations",
		);
		expect(summarizeSpecSource({ spec_url: "https://x/openapi.json", operation_count: 1 })).toBe("https://x/openapi.json · 1 operation");
		expect(summarizeSpecSource(undefined)).toBe("-");
	});
});
describe("applyParsedPreview", () => {
	const twoServers: MCPOpenAPIPreviewResponse = {
		...preview,
		servers: ["https://petstore.example.com/v1", "https://staging.petstore.example.com/v1"],
		base_url: "https://petstore.example.com/v1",
	};
	it("keeps a server the user picked from the list when the re-parsed document still lists it", () => {
		const next = applyParsedPreview(
			{ selection: ["listPets"], baseUrl: "https://staging.petstore.example.com/v1", baseUrlChoice: "server", credentials: {} },
			twoServers,
			twoServers,
		);
		expect(next.baseUrl).toBe("https://staging.petstore.example.com/v1");
		expect(next.baseUrlChoice).toBe("server");
	});
	it("falls back to the document default when the picked server is gone", () => {
		const next = applyParsedPreview(
			{ selection: [], baseUrl: "https://removed.example.com", baseUrlChoice: "server", credentials: {} },
			null,
			twoServers,
		);
		expect(next.baseUrl).toBe("https://petstore.example.com/v1");
	});
	it("keeps a custom base URL and reconciles the latest selection", () => {
		const next = applyParsedPreview(
			{
				selection: ["listPets"],
				baseUrl: "https://mine.example.com",
				baseUrlChoice: "custom",
				credentials: { ApiKeyAuth: { value: { value: "k" } }, Gone: { value: { value: "x" } } },
			},
			preview,
			preview,
		);
		expect(next.baseUrl).toBe("https://mine.example.com");
		expect(next.selection).toEqual(["listPets"]);
		expect(next.credentials).toEqual({ ApiKeyAuth: { value: { value: "k" } } });
	});
});

describe("readUploadedSpec", () => {
	const file = (size: number, text: () => Promise<string>) => ({ size, text });
	it("reads a document", async () => {
		expect(await readUploadedSpec(file(10, async () => "openapi: 3.0.0"))).toEqual({ text: "openapi: 3.0.0", error: null });
	});
	it("refuses an oversized file without reading it", async () => {
		const result = await readUploadedSpec(
			file(6 * 1024 * 1024, async () => {
				throw new Error("must not read");
			}),
		);
		expect(result.error).toContain("exceeds");
	});
	it("says an empty file is empty, not too large", async () => {
		const result = await readUploadedSpec(file(0, async () => ""));
		expect(result.error).toContain("empty");
		expect(result.error).not.toContain("exceeds");
	});
	it("reports a failed read instead of rejecting", async () => {
		const result = await readUploadedSpec(
			file(10, async () => {
				throw new Error("permission denied");
			}),
		);
		expect(result.text).toBe("");
		expect(result.error).toContain("permission denied");
	});
});
describe("document and operation servers", () => {
	const opServers: MCPOpenAPIPreviewResponse = { ...preview, servers: [], base_url: undefined, operation_servers: true };
	it("needs no base URL when every operation declares its own server", () => {
		expect(openAPIBaseUrlRequired("server", opServers)).toBe(false);
		expect(openAPIBaseUrlRequired("custom", opServers)).toBe(true);
		expect(openAPIBaseUrlRequired("server", { ...preview, servers: [] })).toBe(true);
		expect(openAPIBaseUrlRequired("server", preview)).toBe(false);
	});
	it("keeps the document-servers choice after parsing an operation-servers document", () => {
		const next = applyParsedPreview({ selection: [], baseUrl: "", baseUrlChoice: "server", credentials: {} }, null, opServers);
		expect(next.baseUrlChoice).toBe("server");
		expect(next.baseUrl).toBe("");
	});
	it("does not pin the document's default server as an explicit base URL", () => {
		const payload = buildOpenAPIConfigPayload({ spec: "x", base_url: "https://petstore.example.com/v1" }, "paste", preview);
		expect(payload.base_url).toBe("");
		const custom = buildOpenAPIConfigPayload({ spec: "x", base_url: "https://staging.example.com" }, "paste", preview);
		expect(custom.base_url).toBe("https://staging.example.com");
	});
	it("keeps a chosen server that is not the document's first, even after a re-parse echoes it back", () => {
		const reparsed: MCPOpenAPIPreviewResponse = {
			...preview,
			servers: ["https://prod.example.com", "https://staging.example.com"],
			base_url: "https://staging.example.com",
		};
		expect(buildOpenAPIConfigPayload({ spec: "x", base_url: "https://staging.example.com" }, "paste", reparsed).base_url).toBe(
			"https://staging.example.com",
		);
		expect(buildOpenAPIConfigPayload({ spec: "x", base_url: "https://prod.example.com/" }, "paste", reparsed).base_url).toBe("");
	});
});

describe("edit sheet replacement helpers", () => {
	it("counts an open replacement with a parsed preview or edited credentials as dirty", () => {
		expect(replacementIsDirty({ open: true, preview, credentialsDirty: false })).toBe(true);
		expect(replacementIsDirty({ open: true, preview: null, credentialsDirty: true })).toBe(true);
		expect(replacementIsDirty({ open: true, preview: null, credentialsDirty: false })).toBe(false);
		expect(replacementIsDirty({ open: false, preview, credentialsDirty: true })).toBe(false);
	});
	it("keeps auto-execute entries only for selected tools, and '*' only with a full selection", () => {
		const supported = ["listPets", "createPet", "getPetById"];
		expect(replacementAutoExecute(["listPets", "createPet"], supported, ["listPets"])).toEqual(["listPets"]);
		expect(replacementAutoExecute(["*"], supported, ["listPets"])).toEqual([]);
		expect(replacementAutoExecute(["*"], supported, ["*"])).toEqual(["*"]);
		expect(replacementAutoExecute(["gone"], supported, ["*"])).toEqual([]);
	});
	it("sends the stored include_deprecated with either source", () => {
		expect(replacePreviewRequest("paste", "doc", "", undefined, true)).toEqual({
			spec: "doc",
			base_url: undefined,
			include_deprecated: true,
		});
		expect(replacePreviewRequest("url", "ignored", " https://x/o.json ", "https://b", true)).toEqual({
			spec_url: "https://x/o.json",
			base_url: "https://b",
			include_deprecated: true,
		});
		expect(replacePreviewRequest("upload", "doc", "", undefined, undefined)).toEqual({ spec: "doc", base_url: undefined });
	});
});
describe("replace preview naming", () => {
	it("sends the client name so replaced tool names match what an update accepts", () => {
		expect(replacePreviewRequest("paste", "doc", "", undefined, false, "petstore")).toEqual({
			spec: "doc",
			base_url: undefined,
			client_name: "petstore",
		});
	});
});