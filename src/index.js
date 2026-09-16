import { verify } from "./crypto.js";
import { handleAdminRequest } from "./admin.js";
import { getFile } from "./bucket.js";
import { logEvent } from "./logger.js";
import { verifyAccessJwt, verifyAccessEmail } from "./access.js";

export default {
	async scheduled(event, env, ctx) {
		const now = Math.floor(Date.now() / 1000);

		// Branch on the cron trigger: the 30-minute cleanup job deletes expired
		// / pending_delete objects; the hourly reconcile job recalculates the
		// used_bytes counter from a full bucket scan so it cannot drift away
		// from reality when objects change out-of-band (R2 lifecycle rules,
		// direct API access, failed increments).
		if (event.cron === "0 * * * *") {
			await reconcileUsedBytes(env, ctx);
			return;
		}

		const toDelete = await env.file_share_db.prepare(`
			SELECT file_key FROM files
			WHERE (status = 'pending_delete' AND delete_after <= ?)
			   OR (status = 'active' AND expire_at <= ?)
			LIMIT 100
		`).bind(now, now).all();

		if (toDelete.results && toDelete.results.length > 0) {
			const keys = toDelete.results.map(r => r.file_key);
			// R2 delete is strongly consistent and idempotent for missing keys; if it
			// rejects, the UPDATE below never runs and rows stay pending for the next
			// cron tick (eventual consistency). No orphan risk from silent partial fail.
			await env.BUCKET.delete(keys);
			const placeholders = keys.map(() => '?').join(',');
			await env.file_share_db.prepare(`
				UPDATE files SET status = 'deleted' WHERE file_key IN (${placeholders})
			`).bind(...keys).run();
			// used_bytes is not decremented here — the hourly reconcile job
			// recalculates it from a full bucket scan, which also corrects any
			// drift from lifecycle rules or out-of-band changes.
			logEvent(env, { action: "CRON_CLEANUP", key: keys.join(","), count: keys.length });
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

			if (url.hostname.endsWith(".workers.dev")) {
				return corsify(new Response("Forbidden: Direct access to workers.dev is disabled for security.", { status: 403 }));
			}

			if (!env.AUTH_SECRET && !url.hostname.includes("localhost")) {
				return corsify(new Response("Internal Server Error: Missing Security Credentials", { status: 500 }));
			}

			const key = decodeURIComponent(url.pathname.slice(1));

			const jwtAssertion = request.headers.get("CF-Access-JWT-Assertion");
			const adminEmails = (env.ADMIN_EMAILS || "").split(",").map(e => e.trim()).filter(e => e !== "");

			// isAdmin check:
			// 1. In production: the CF-Access-JWT-Assertion must verify against the team JWKS,
			//    and the JWT's email claim must be in the whitelist.
			// 2. On localhost: the CF-Access-Authenticated-User-Email header is trusted
			//    (no Access in front of the dev server).
			const isLocal = url.hostname.includes("localhost");
			let adminEmail = null;
			if (isLocal) {
				const devEmail = request.headers.get("CF-Access-Authenticated-User-Email");
				if (devEmail && (adminEmails.includes(devEmail) || adminEmails.length === 0)) {
					adminEmail = devEmail;
				}
			} else {
				adminEmail = await verifyAccessEmail(jwtAssertion, env, adminEmails);
			}
			const isAdmin = !!adminEmail;

			if (url.pathname.startsWith("/_admin")) {
				const res = await handleAdminRequest(request, env, url, isAdmin, adminEmail || "unknown");
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
						// Self-heal: D1 row is missing but R2 object exists. Generate a
						// FRESH salt rather than trusting R2 customMetadata.v, because that
						// field is never updated by revoke/invalidate (which only touch D1).
						// Using the stale R2 salt would resurrect signatures revoked before
						// the D1 row was lost.
						const salt = Date.now().toString() + Math.random().toString(36).slice(2, 8);
						const exp_at = parseInt(head.customMetadata.e || (now + 86400).toString());
						const max_dl = parseInt(head.customMetadata.m || "999999");
						const ot_flag = parseInt(head.customMetadata.ot || "0");
						await env.file_share_db.prepare(`
							INSERT INTO files (file_key, original_name, expire_at, max_downloads, download_count, version_salt, is_one_time, status, created_at)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
							ON CONFLICT(file_key) DO NOTHING
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
			const isValid = await verify(key, exp, signature, env.AUTH_SECRET, kid, file.version_salt, ot);
			if (!isValid) return corsify(new Response("Forbidden: Invalid or expired signature", { status: 403 }));

			// --- Fetch first, count only on a complete download (H1 + C2 fix) ---
			// Get the R2 object BEFORE touching the counter, so a 404 or a thrown
			// exception does not burn a download slot. Counting happens only after we
			// know the request will actually serve bytes.
			const response = await getFile(env, key, request);

			if (response.status === 404) {
				ctx.waitUntil(env.file_share_db.prepare("UPDATE files SET status = 'deleted' WHERE file_key = ?").bind(key).run());
				return corsify(new Response("Forbidden: Resource missing", { status: 403 }));
			}

			// Count a download only when this request delivers a complete object: a
			// full 200, or a Range that reaches the final byte. Partial Range fetches
			// (streaming media seeking) do NOT consume a slot, so max_downloads is
			// meaningful for media playback. (C2 fix)
			const isCompleteDownload = response.status === 200 ||
				(response.status === 206 && reachedLastByte(request.headers.get("Range"), response.headers.get("Content-Range")));

			if (isCompleteDownload) {
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
					const newSalt = Date.now().toString() + Math.random().toString(36).slice(2, 8);
					const deleteBuffer = Math.floor(Date.now() / 1000) + 600;
					ctx.waitUntil(env.file_share_db.prepare(`
						UPDATE files SET status = 'pending_delete', version_salt = ?, delete_after = ?
						WHERE file_key = ?
					`).bind(newSalt, deleteBuffer, key).run());
					logEvent(env, { action: "AUTO_REVOKE_LIMIT", key, ot: result.is_one_time === 1 });
				}
			}

			const finalHeaders = new Headers(response.headers);
			finalHeaders.set("X-Robots-Tag", "noindex, nofollow");
			finalHeaders.set("X-Content-Type-Options", "nosniff");
			finalHeaders.set("X-Frame-Options", "DENY");
			finalHeaders.set("Referrer-Policy", "no-referrer");
			finalHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

			// Kill caching so the counter path runs on every download request.
			finalHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
			finalHeaders.set("Pragma", "no-cache");
			finalHeaders.set("Expires", "0");

			logEvent(env, {
				action: response.status === 206 ? "DOWNLOAD_PARTIAL" : "DOWNLOAD_FULL",
				key,
				size: parseInt(finalHeaders.get("Content-Length")) || 0,
				ot: file.is_one_time === 1
			});

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

/**
 * Determine whether a 206 Range response reaches the final byte of the object,
 * i.e. it constitutes a complete download for counting purposes.
 * Content-Range is `bytes <start>-<end>/<total>`; the request reaches the end
 * when end === total - 1.
 */
function reachedLastByte(rangeHeader, contentRange) {
	if (!rangeHeader || !contentRange) return false;
	const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(contentRange.trim());
	if (!m) return false;
	const end = parseInt(m[2], 10);
	const total = parseInt(m[3], 10);
	return total > 0 && end === total - 1;
}

/**
 * Recalculate used_bytes from a full bucket scan and overwrite the meta
 * counter. Run on the hourly cron so the quota check stays accurate even
 * when objects are added/removed outside the worker (R2 lifecycle rules,
 * direct S3 API, failed increments). A bucket with many objects paginates.
 */
async function reconcileUsedBytes(env, ctx) {
	let totalUsed = 0;
	let cursor = undefined;
	let truncated = true;
	while (truncated) {
		const opts = cursor ? { cursor } : {};
		const list = await env.BUCKET.list(opts);
		for (const obj of list.objects) totalUsed += obj.size;
		truncated = list.truncated;
		cursor = list.cursor;
	}
	await env.file_share_db.prepare(`
		INSERT INTO meta (k, v) VALUES ('used_bytes', ?)
			ON CONFLICT(k) DO UPDATE SET v = excluded.v
	`).bind(totalUsed).run();
	logEvent(env, { action: "RECONCILE", size: totalUsed });
}

