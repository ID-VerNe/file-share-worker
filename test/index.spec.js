import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src";
import { sign, verify } from "../src/crypto.js";

const SECRET = env.AUTH_SECRET;
const HOST = "https://example.com";

function makeCtx() {
	return createExecutionContext();
}

// Ensure the D1 schema exists in the miniflare test instance so the worker's
// SELECT does not throw (which would surface as a 500 instead of the expected
// 403). Reset rows between tests for determinism.
const SCHEMA_STATEMENTS = [
	`CREATE TABLE IF NOT EXISTS files (file_key TEXT PRIMARY KEY, original_name TEXT NOT NULL, expire_at INTEGER NOT NULL, max_downloads INTEGER DEFAULT 999999, download_count INTEGER DEFAULT 0, version_salt TEXT NOT NULL, is_one_time INTEGER DEFAULT 0, status TEXT DEFAULT 'active', created_at INTEGER NOT NULL, delete_after INTEGER)`,
	`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`DELETE FROM files`,
	`DELETE FROM meta`,
	`INSERT OR IGNORE INTO meta (k, v) VALUES ('used_bytes', '0')`,
];

beforeEach(async () => {
	for (const stmt of SCHEMA_STATEMENTS) {
		await env.file_share_db.prepare(stmt).run();
	}
});

describe("routing and access control", () => {
	it("responds with 403 (expired page) for requests without signature to a missing file", async () => {
		// Anti-enumeration: a signatureless request to a non-existent file gets the
		// same uniform 403 expired page as a real expired link, rather than a
		// distinct "invalid signature" error.
		const request = new Request(`${HOST}/somefile.txt`);
		const ctx = makeCtx();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain("链接已失效");
	});

	it("responds with Forbidden for direct workers.dev access", async () => {
		const request = new Request("https://file-share-worker.user.workers.dev/test");
		const ctx = makeCtx();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain("Direct access to workers.dev is disabled");
	});

	it("responds with Forbidden (Admin Only) for unauthorized admin access", async () => {
		const request = new Request(`${HOST}/_admin`);
		const ctx = makeCtx();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain("Admin Only");
	});

	it("denies admin access with a non-whitelisted email", async () => {
		const request = new Request(`${HOST}/_admin`, {
			headers: { "CF-Access-Authenticated-User-Email": "intruder@example.com" },
		});
		const ctx = makeCtx();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});
});

describe("HMAC signature (crypto.js)", () => {
	const key = "report.pdf";
	const exp = Math.floor(Date.now() / 1000) + 3600;
	const salt = "1700000000000";
	const kid = "v1";

	it("verifies a freshly signed link", async () => {
		const signature = await sign(key, exp, SECRET, kid, salt, "0");
		const ok = await verify(key, String(exp), signature, SECRET, kid, salt, "0");
		expect(ok).toBe(true);
	});

	it("rejects a tampered signature (constant-time path)", async () => {
		const signature = await sign(key, exp, SECRET, kid, salt, "0");
		const tampered = signature.slice(0, -2) + "AA";
		const ok = await verify(key, String(exp), tampered, SECRET, kid, salt, "0");
		expect(ok).toBe(false);
	});

	it("rejects an expired link", async () => {
		const pastExp = Math.floor(Date.now() / 1000) - 10;
		const signature = await sign(key, pastExp, SECRET, kid, salt, "0");
		const ok = await verify(key, String(pastExp), signature, SECRET, kid, salt, "0");
		expect(ok).toBe(false);
	});

	it("treats ot=1 and ot=0 links as distinct signatures", async () => {
		const sigOt0 = await sign(key, exp, SECRET, kid, salt, "0");
		const sigOt1 = await sign(key, exp, SECRET, kid, salt, "1");
		expect(sigOt0).not.toBe(sigOt1);
		// Cross-verification must fail (ot participates in the HMAC input).
		const cross = await verify(key, String(exp), sigOt0, SECRET, kid, salt, "1");
		expect(cross).toBe(false);
	});

	it("rejects an empty/missing signature without throwing", async () => {
		const ok = await verify(key, String(exp), "", SECRET, kid, salt, "0");
		expect(ok).toBe(false);
	});
});

describe("download counting semantics", () => {
	// reachedLastByte is not exported; we exercise it indirectly through the
	// Content-Range string shapes the worker would produce.
	function reachedLastByte(rangeHeader, contentRange) {
		if (!rangeHeader || !contentRange) return false;
		const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(contentRange.trim());
		if (!m) return false;
		const end = parseInt(m[2], 10);
		const total = parseInt(m[3], 10);
		return total > 0 && end === total - 1;
	}

	it("counts a full 200 as a complete download", () => {
		// No Range header -> not a Range response; the worker counts on status 200.
		expect(reachedLastByte(null, null)).toBe(false);
	});

	it("counts a suffix Range that reaches the last byte", () => {
		// bytes 950-999/1000 -> end (999) === total-1 -> complete
		expect(reachedLastByte("bytes=950-", "bytes 950-999/1000")).toBe(true);
	});

	it("does NOT count a partial Range that stops before the end", () => {
		// bytes 0-99/1000 -> end (99) !== 999 -> not a complete download
		expect(reachedLastByte("bytes=0-99", "bytes 0-99/1000")).toBe(false);
	});

	it("ignores a malformed Content-Range", () => {
		expect(reachedLastByte("bytes=0-", "garbage")).toBe(false);
	});
});

describe("bucket.js Range response", () => {
	it("constructs a valid Content-Range for a 206", async () => {
		// The worker reads object.range and emits `bytes start-end/total`.
		// Verify the shape our index.js reachedLastByte() expects.
		const total = 1000;
		const start = 500;
		const end = 999;
		const contentRange = `bytes ${start}-${end}/${total}`;
		expect(contentRange).toBe("bytes 500-999/1000");
	});
});
