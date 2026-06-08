import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src";

describe("File Share Worker", () => {
	it("responds with Forbidden for requests without signature", async () => {
		const request = new Request("https://example.com/somefile.txt");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(403);
		expect(await response.text()).toContain("Forbidden");
	});

	it("responds with Forbidden for direct workers.dev access", async () => {
		const request = new Request("https://file-share-worker.user.workers.dev/test");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(403);
		expect(await response.text()).toContain("Direct access to workers.dev is disabled");
	});

	it("responds with Forbidden for unauthorized admin access", async () => {
		const request = new Request("https://example.com/_admin");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(403);
		expect(await response.text()).toContain("Admin Only");
	});
});
