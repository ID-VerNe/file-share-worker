import { verify } from "./crypto.js";
import { handleAdminRequest } from "./admin.js";
import { getFile } from "./bucket.js";
import { logEvent } from "./logger.js";

export default {
	async scheduled(event, env, ctx) {
		const now = Math.floor(Date.now() / 1000);

		const toDelete = await env.file_share_db.prepare(`
			SELECT file_key FROM files 
			WHERE (status = 'pending_delete' AND delete_after <= ?)
			   OR (status = 'active' AND expire_at <= ?)
			LIMIT 100
		`).bind(now, now).all();

		if (toDelete.results && toDelete.results.length > 0) {
			const keys = toDelete.results.map(r => r.file_key);
			await env.BUCKET.delete(keys);
			const placeholders = keys.map(() => '?').join(',');
			await env.file_share_db.prepare(`
				UPDATE files SET status = 'deleted' WHERE file_key IN (${placeholders})
			`).bind(...keys).run();
			logEvent(env, { action: "CRON_CLEANUP", count: keys.length });
		}
	},

	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const requestOrigin = request.headers.get("Origin");
		const allowedOrigins = (env.SHARD_DOMAINS || "").split(",").map(d => d.trim()).filter(Boolean);
		const isAllowedOrigin = requestOrigin && allowedOrigins.includes(requestOrigin);
		
		// Helper to add CORS to any response — only whitelisted origins
		const corsify = (res) => {
			const newRes = new Response(res.body, res);
			if (isAllowedOrigin) {
				newRes.headers.set("Access-Control-Allow-Origin", requestOrigin);
				newRes.headers.set("Access-Control-Allow-Credentials", "true");
			}
			newRes.headers.set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS");
			newRes.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, CF-Access-JWT-Assertion, Range");
			newRes.headers.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, CF-Cache-Status");
			newRes.headers.set("Vary", "Origin");
			return newRes;
		};

		try {
			if (request.method === "OPTIONS") {
				const headers = {
					"Access-Control-Allow-Methods": "GET, PUT, POST, DELETE, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type, Authorization, CF-Access-JWT-Assertion, Range",
					"Access-Control-Expose-Headers": "Content-Length, Content-Range, CF-Cache-Status",
					"Access-Control-Max-Age": "86400",
					"Vary": "Origin"
				};
				if (isAllowedOrigin) {
					headers["Access-Control-Allow-Origin"] = requestOrigin;
					headers["Access-Control-Allow-Credentials"] = "true";
				}
				return new Response(null, { headers });
			}

			if (url.hostname.endsWith(".workers.dev") && !url.hostname.includes("localhost")) {
				return corsify(new Response("Forbidden: Direct access to workers.dev is disabled for security.", { status: 403 }));
			}

			if (!env.AUTH_SECRET && !url.hostname.includes("localhost")) {
				return corsify(new Response("Internal Server Error: Missing Security Credentials", { status: 500 }));
			}

			const key = decodeURIComponent(url.pathname.slice(1));
			
			const jwtAssertion = request.headers.get("CF-Access-JWT-Assertion");
			const userEmail = request.headers.get("CF-Access-Authenticated-User-Email");
			const adminEmails = (env.ADMIN_EMAILS || "").split(",").map(e => e.trim()).filter(e => e !== "");
			
			// isAdmin check: 
			// 1. Must have an email from Cloudflare Access
			// 2. That email must be in the whitelist
			// 3. Or if in development (localhost), allow if any email is present
			const isLocal = url.hostname.includes("localhost");
			const isAdmin = !!(userEmail && (adminEmails.includes(userEmail) || isLocal));

			if (url.pathname.startsWith("/_admin")) {
				const res = await handleAdminRequest(request, env, url, isAdmin);
				return corsify(res);
			} 
			
			if (request.method !== "GET") {
				return corsify(new Response("Method Not Allowed", { status: 405 }));
			}

			const signature = url.searchParams.get("s");
			const exp = url.searchParams.get("e");
			const kid = url.searchParams.get("k") || "v1";
			const ot = url.searchParams.get("ot") || "0";
			const now = Math.floor(Date.now() / 1000);

			let file = await env.file_share_db.prepare(
				"SELECT version_salt, status, expire_at, max_downloads, download_count, is_one_time FROM files WHERE file_key = ?"
			).bind(key).first();

			// --- Lazy Cleanup ---
			if (file && file.status === 'active' && file.expire_at <= now) {
				ctx.waitUntil((async () => {
					await env.BUCKET.delete(key);
					await env.file_share_db.prepare("UPDATE files SET status = 'deleted' WHERE file_key = ?").bind(key).run();
				})());
				file.status = 'expired'; 
			}

			// --- Self-Healing & Inactive Handling ---
			if (!file || file.status !== 'active') {
				if (!file) {
					const head = await env.BUCKET.head(key);
					if (head && head.customMetadata?.v) {
						const salt = head.customMetadata.v;
						const exp_at = parseInt(head.customMetadata.e || (now + 86400).toString());
						const max_dl = parseInt(head.customMetadata.m || "999999");
						const ot_flag = parseInt(head.customMetadata.ot || "0");
						await env.file_share_db.prepare(`
							INSERT INTO files (file_key, original_name, expire_at, max_downloads, download_count, version_salt, is_one_time, status, created_at)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
						`).bind(key, key, exp_at, max_dl, 0, salt, ot_flag, 'active', now).run();
						file = { version_salt: salt, status: 'active', expire_at: exp_at, max_downloads: max_dl, download_count: 0, is_one_time: ot_flag };
					}
				}

				if (!file || file.status !== 'active') {
					return corsify(new Response(`
					<!DOCTYPE html>
					<html>
					<head>
						<meta charset="UTF-8">
						<title>链接已失效 / Link Expired</title>
						<style>
							body { font-family: -apple-system, system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f9fafb; color: #374151; }
							.card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
							h2 { margin: 0 0 10px; color: #111827; }
							p { line-height: 1.5; margin: 0 0 20px; color: #6b7280; }
							.contact { font-size: 0.9em; border-top: 1px solid #eee; padding-top: 20px; }
						</style>
					</head>
					<body>
						<div class="card">
							<h2>链接已失效</h2>
							<p>该链接已达到下载次数上限或已过期。<br>请联系发送者重新获取链接。</p>
							<div class="contact">Link Expired or Limit Reached.</div>
						</div>
					</body>
					</html>`, { status: 403, headers: { "Content-Type": "text/html;charset=UTF-8" } }));
				}
			}

			// 2. Verify signature
			const isValid = await verify(key, exp, signature, env.AUTH_SECRET || env.GET_SIGNATURE, kid, file.version_salt, ot);
			if (!isValid) return corsify(new Response("Forbidden: Invalid or expired signature", { status: 403 }));

			// --- Atomic Pre-Download Counting (count ALL requests, not just full downloads) ---
			const range = request.headers.get("Range");

			{
				const result = await env.file_share_db.prepare(`
					UPDATE files 
					SET download_count = download_count + 1 
					WHERE file_key = ? AND status = 'active' AND download_count < max_downloads
					RETURNING download_count, max_downloads, is_one_time
				`).bind(key).first();

				if (!result) {
					return corsify(new Response(`
					<!DOCTYPE html>
					<html>
					<head>
						<meta charset="UTF-8">
						<title>链接已失效 / Link Expired</title>
						<style>
							body { font-family: -apple-system, system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f9fafb; color: #374151; }
							.card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
							h2 { margin: 0 0 10px; color: #111827; }
							p { line-height: 1.5; margin: 0 0 20px; color: #6b7280; }
						</style>
					</head>
					<body>
						<div class="card">
							<h2>链接已失效</h2>
							<p>下载次数已达上限。<br>Limit reached.</p>
						</div>
					</body>
					</html>`, { status: 403, headers: { "Content-Type": "text/html;charset=UTF-8" } }));
				}

				if (result.download_count >= result.max_downloads || result.is_one_time === 1) {
					const newSalt = Date.now().toString();
					const deleteBuffer = Math.floor(Date.now() / 1000) + 600;
					ctx.waitUntil(env.file_share_db.prepare(`
						UPDATE files SET status = 'pending_delete', version_salt = ?, delete_after = ?
						WHERE file_key = ?
					`).bind(newSalt, deleteBuffer, key).run());
					logEvent(env, { action: "AUTO_REVOKE_LIMIT", key });
				}
			}

			let response = await getFile(env, key, request);

			if (response.status === 404) {
				ctx.waitUntil(env.file_share_db.prepare("UPDATE files SET status = 'deleted' WHERE file_key = ?").bind(key).run());
				return corsify(new Response("Forbidden: Resource missing", { status: 403 }));
			}

			const finalHeaders = new Headers(response.headers);
			finalHeaders.set("X-Robots-Tag", "noindex, nofollow");
			finalHeaders.set("X-Content-Type-Options", "nosniff");
			finalHeaders.set("X-Frame-Options", "DENY");
			finalHeaders.set("Referrer-Policy", "no-referrer");
			finalHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
			
			// --- NEW: Kill Caching to force counting ---
			finalHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
			finalHeaders.set("Pragma", "no-cache");
			finalHeaders.set("Expires", "0");

			if (response.status === 200 || response.status === 206) {
				const size = response.headers.get("Content-Length");
				logEvent(env, { 
					action: response.status === 206 ? "DOWNLOAD_PARTIAL" : "DOWNLOAD_FULL", 
					key, size: size ? parseInt(size) : 0 
				});
			}

			return corsify(new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: finalHeaders
			}));

		} catch (e) {
			console.error("Worker Error:", e);
			return corsify(new Response("Error: 500 | Internal Server Error", { 
				status: 500,
				headers: { "Content-Type": "text/plain;charset=UTF-8" }
			}));
		}
	},
};
