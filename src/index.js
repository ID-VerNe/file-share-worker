import { verify } from "./crypto.js";
import { handleAdminRequest } from "./admin.js";
import { getFile } from "./bucket.js";
import { logEvent } from "./logger.js";

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const origin = request.headers.get("Origin") || "*";
		
		// 1. CORS Preflight Handling
		if (request.method === "OPTIONS") {
			return new Response(null, {
				headers: {
					"Access-Control-Allow-Origin": origin,
					"Access-Control-Allow-Methods": "GET, PUT, POST, DELETE, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type, CF-Access-Authenticated-User-Email, Range",
					"Access-Control-Expose-Headers": "Content-Range, Content-Length, Accept-Ranges",
					"Access-Control-Max-Age": "86400",
					"Vary": "Origin"
				},
			});
		}

		// 2. Security Checks: Strict Enforcement
		// Always disable .workers.dev in production regardless of env vars
		if (url.hostname.endsWith(".workers.dev") && !url.hostname.includes("localhost")) {
			return new Response("Forbidden: Direct access to workers.dev is disabled for security. Use your custom domain.", { status: 403 }, {
				headers: { "Access-Control-Allow-Origin": origin, "Vary": "Origin" }
			});
		}

		// Enforce AUTH_SECRET in production
		if (!env.AUTH_SECRET && !url.hostname.includes("localhost")) {
			console.error("CRITICAL: Missing AUTH_SECRET in production.");
			return new Response("Internal Server Error: Missing Security Credentials", { status: 500 });
		}

		const key = decodeURIComponent(url.pathname.slice(1));
		
		// Admin Authentication: Require JWT assertion from Cloudflare Access and check against ADMIN_EMAILS
		const jwtAssertion = request.headers.get("CF-Access-JWT-Assertion");
		const userEmail = request.headers.get("CF-Access-Authenticated-User-Email");
		
		const adminEmails = (env.ADMIN_EMAILS || "").split(",").map(e => e.trim());
		const isAdmin = !!(jwtAssertion && userEmail && adminEmails.includes(userEmail));

		let response;
		// 3. Admin Router
		if (url.pathname.startsWith("/_admin")) {
			response = await handleAdminRequest(request, env, url, isAdmin);
		} else if (request.method === "GET") {
			// 4. Public/Download Router
			const signature = url.searchParams.get("s");
			const exp = url.searchParams.get("e");
			const kid = url.searchParams.get("k") || "v1";
			const ot = url.searchParams.get("ot") || "0";

			// 1. Fetch metadata first to get revocation salt
			const head = await env.BUCKET.head(key);
			if (!head) {
				return new Response("Forbidden: Resource Not Found or Invalid Signature", { status: 403 });
			}

			const salt = head.customMetadata?.v || "";

			// 2. Verify signature using metadata salt and ot flag
			const isValid = await verify(
				key, 
				exp, 
				signature, 
				env.AUTH_SECRET || env.GET_SIGNATURE,
				kid,
				salt,
				ot
			);

			if (!isValid) {
				response = new Response("Forbidden: Invalid or expired signature", { status: 403 });
			} else {
				response = await getFile(env, key, request);

				// 3. One-Time Link Handling: Revoke after first use
				// We only revoke on full downloads or the start of a stream (Range: bytes=0-)
				// to avoid breaking video seeking/multi-part downloads mid-way.
				if (ot === "1") {
					const range = request.headers.get("Range");
					if (!range || range.startsWith("bytes=0-")) {
						// Trigger revocation in background via waitUntil
						const revokePromise = (async () => {
							const newVersion = Date.now().toString();
							await env.BUCKET.put(key, head.body, {
								customMetadata: { ...head.customMetadata, v: newVersion },
								httpMetadata: head.httpMetadata
							});
							logEvent(env, { action: "AUTO_REVOKE_OT", key });
						})();
						ctx.waitUntil(revokePromise);
					}
				}

				// Anti-Abuse Headers

				response = new Response(response.body, response);
				response.headers.set("X-Robots-Tag", "noindex, nofollow"); // Prevent SEO indexing of signed links
				response.headers.set("X-Content-Type-Options", "nosniff");
				
				// Cache-Control: Private ensures shared proxies don't cache signed content
				if (!response.headers.has("Cache-Control")) {
					response.headers.set("Cache-Control", "private, max-age=3600");
				}

				// Log successful or partial download
				if (response.status === 200 || response.status === 206) {
					const contentLength = response.headers.get("Content-Length");
					logEvent(env, { 
						action: response.status === 206 ? "DOWNLOAD_PARTIAL" : "DOWNLOAD_FULL", 
						key, 
						status: response.status,
						size: contentLength ? parseInt(contentLength) : 0
					});
				}
			}
		} else {
			response = new Response("Not Found", { status: 404 });
		}

		// Add CORS headers to all responses
		const newHeaders = new Headers(response.headers);
		newHeaders.set("Access-Control-Allow-Origin", origin);
		newHeaders.set("Vary", "Origin");
		
		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: newHeaders
		});
	},
};
