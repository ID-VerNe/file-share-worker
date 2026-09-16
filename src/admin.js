/**
 * Admin dashboard and API logic
 */
import { sign } from "./crypto.js";
import { logEvent } from "./logger.js";

/** Paginated R2 bucket size calculation — handles >1000 objects.
 *  Only used for the occasional full reconciliation; hot paths read the meta
 *  counter row instead (see getUsedBytes / addUsedBytes). */
async function getBucketTotalSize(bucket, excludeKey = null) {
  let totalUsed = 0;
  let cursor = undefined;
  let truncated = true;
  while (truncated) {
    const opts = cursor ? { cursor } : {};
    const list = await bucket.list(opts);
    for (const obj of list.objects) {
      if (obj.key !== excludeKey) totalUsed += obj.size;
    }
    truncated = list.truncated;
    cursor = list.cursor;
  }
  return totalUsed;
}

/** Used-bytes counter maintained as a single D1 row in the meta table.
 *  Replaces the per-request full-bucket list() with a single-row read,
 *  so opening the dashboard no longer burns R2 Class A operations. */
async function getUsedBytes(env) {
  const row = await env.file_share_db.prepare(
    "SELECT v FROM meta WHERE k = 'used_bytes'"
  ).first();
  return row ? parseInt(row.v, 10) || 0 : 0;
}

/** Atomically add (delta may be negative) to the used_bytes counter. */
async function addUsedBytes(env, delta) {
  await env.file_share_db.prepare(`
    INSERT INTO meta (k, v) VALUES ('used_bytes', ?)
      ON CONFLICT(k) DO UPDATE SET v = v + excluded.v
  `).bind(delta).run();
}

export async function handleAdminRequest(request, env, url, isAdmin, userEmail) {
  if (!isAdmin) {
    return Response.json({
      error: "Forbidden: Admin Only"
    }, { status: 403 });
  }

  userEmail = userEmail || "unknown";

  // Robust path matching for admin dashboard
  if (url.pathname === "/_admin" || url.pathname === "/_admin/") {
    return renderDashboard(env, url);
  }

  if (url.pathname.startsWith("/_admin/api/")) {
    const pathParts = url.pathname.split("/");
    const action = pathParts[3];

    // Multipart Upload API
    if (action === "multipart") {
      return handleMultipartUpload(request, env, url, userEmail);
    }

    // Delete API
    if (action === "delete" && request.method === "DELETE") {
      const deleteKey = decodeURIComponent(url.pathname.replace("/_admin/api/delete/", ""));
      const head = await env.BUCKET.head(deleteKey);
      const removedSize = head ? head.size : 0;
      await env.BUCKET.delete(deleteKey);
      await env.file_share_db.prepare("UPDATE files SET status = 'deleted' WHERE file_key = ?").bind(deleteKey).run();
      if (removedSize) await addUsedBytes(env, -removedSize);
      logEvent(env, { action: "DELETE", key: deleteKey, email: userEmail });
      return new Response("Deleted");
    }

    // New: Invalidate API (Force Expire/Soft Delete)
    if (action === "invalidate" && request.method === "POST") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("Key required", { status: 400 });

      const newSalt = Date.now().toString();
      const deleteBuffer = Math.floor(Date.now() / 1000) + 600; // 10 min buffer

      await env.file_share_db.prepare(`
        UPDATE files
        SET status = 'pending_delete',
            version_salt = ?,
            delete_after = ?
        WHERE file_key = ?
      `).bind(newSalt, deleteBuffer, key).run();

      logEvent(env, { action: "INVALIDATE", key, email: userEmail });
      return new Response("Invalidated");
    }

    // Reconcile the used_bytes counter against a full bucket scan.
    // The counter is maintained incrementally on upload/delete/cron, but it
    // drifts if objects are added or removed outside the worker (lifecycle
    // rules, direct R2 API, failed increments). Call this after any
    // out-of-band change, or periodically to keep the quota check honest.
    if (action === "reconcile" && request.method === "POST") {
      const actual = await getBucketTotalSize(env.BUCKET);
      await env.file_share_db.prepare(`
        INSERT INTO meta (k, v) VALUES ('used_bytes', ?)
          ON CONFLICT(k) DO UPDATE SET v = excluded.v
      `).bind(actual).run();
      const stored = await getUsedBytes(env);
      logEvent(env, { action: "RECONCILE", email: userEmail, size: actual });
      return Response.json({ used_bytes: actual, stored });
    }

    // New: Signature API (for Copy Link)
    if (action === "sign") {
      const key = url.searchParams.get("key");
      const kid = url.searchParams.get("k") || "v1";
      const ot = url.searchParams.get("ot") === "1" ? "1" : "0";
      if (!key) return new Response("Key required", { status: 400 });
      
      const requestedExp = parseInt(url.searchParams.get("exp") || "0");
      const now = Math.floor(Date.now() / 1000);
      const maxExp = now + (30 * 24 * 60 * 60); // 30 days cap
      
      // 1. Fetch metadata from D1 (Authoritative)
      const file = await env.file_share_db.prepare(
        "SELECT version_salt, status, expire_at, is_one_time FROM files WHERE file_key = ?"
      ).bind(key).first();

      if (!file || file.status !== 'active') {
        return new Response("Forbidden: File is inactive or expired", { status: 403 });
      }

      // 2. Expiration logic
      let exp = requestedExp || file.expire_at;
      if (exp > maxExp) exp = maxExp;

      // One-time links: persist is_one_time=1 in D1 so the auto-revoke path
      // (index.js) actually triggers after the first complete download. Without
      // this, ot=1 links were never revoked (C1 fix).
      if (ot === "1" && file.is_one_time !== 1) {
        await env.file_share_db.prepare(
          "UPDATE files SET is_one_time = 1 WHERE file_key = ? AND status = 'active'"
        ).bind(key).run();
      }

      const signature = await sign(key, exp, env.AUTH_SECRET, kid, file.version_salt, ot);

      logEvent(env, { action: "SIGN", key, email: userEmail, ot: ot === "1" });
      
      return Response.json({
        key,
        exp,
        signature,
        kid,
        ot,
        url: `${url.origin}/${encodeURIComponent(key)}?s=${signature}&e=${exp}&k=${kid}${ot === "1" ? "&ot=1" : ""}`
      });
    }

    // New: Revoke API — invalidate signatures by rotating version_salt in D1
    if (action === "revoke" && request.method === "POST") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("Key required", { status: 400 });
      
      const newVersion = Date.now().toString();
      await env.file_share_db.prepare(
        "UPDATE files SET version_salt = ? WHERE file_key = ? AND status = 'active'"
      ).bind(newVersion, key).run();

      logEvent(env, { action: "REVOKE", key, email: userEmail });
      return new Response("Revoked");
    }
  }

  return new Response("Not Found", { status: 404 });
}

async function handleMultipartUpload(request, env, url, userEmail) {
  const pathParts = url.pathname.split("/");
  const subAction = pathParts[4];
  const uploadId = url.searchParams.get("uploadId");
  const partNumber = parseInt(url.searchParams.get("partNumber"));
  const fileKey = url.searchParams.get("key");

  // Configuration
  const ALLOWED_EXTENSIONS = [
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mov', 'avi', 'mp3', 'wav', 
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 
    'gz', 'tar', 'txt', 'md', 'json'
  ];
  const TOTAL_QUOTA_GB = env.TOTAL_QUOTA_GB ? parseFloat(env.TOTAL_QUOTA_GB) : 10;

  switch (subAction) {
    case "start": {
      // 1. File Type Check
      const ext = fileKey.split('.').pop().toLowerCase();
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return new Response(`Forbidden: File type .${ext} is not in the allowed list.`, { status: 403 });
      }

      const fileSize = parseInt(url.searchParams.get("size") || "0");
      const MAX_SIZE = 8 * 1024 * 1024 * 1024; // 8GB Single File
      if (fileSize > MAX_SIZE) return new Response(`File too large. Max 8GB.`, { status: 400 });

      // 2. Storage Quota Check (counter row, not full-bucket list)
      const totalUsed = await getUsedBytes(env);

      const quotaBytes = TOTAL_QUOTA_GB * 1024 * 1024 * 1024;
      if (totalUsed + fileSize > quotaBytes) {
        return new Response(`Quota Exceeded: Total storage limit is ${TOTAL_QUOTA_GB}GB. Currently used: ${(totalUsed / 1024 / 1024 / 1024).toFixed(2)}GB.`, { status: 403 });
      }

      // 3. Initialize Metadata for D1 consistency
      const now = Math.floor(Date.now() / 1000);
      const salt = Date.now().toString();
      const exp = now + 24 * 60 * 60; // Default 24h
      const maxDownloads = url.searchParams.get("max") || "999999";

      const upload = await env.BUCKET.createMultipartUpload(fileKey, {
        customMetadata: {
          v: salt,
          e: exp.toString(),
          m: maxDownloads, 
          ot: "0"      
        }
      });
      logEvent(env, { action: "UPLOAD_START", key: fileKey, email: userEmail, size: fileSize });
      return Response.json({ uploadId: upload.uploadId });
    }
    case "upload": {
      const upload = env.BUCKET.resumeMultipartUpload(fileKey, uploadId);
      const part = await upload.uploadPart(partNumber, request.body);
      return Response.json(part);
    }
    case "abort": {
      const upload = env.BUCKET.resumeMultipartUpload(fileKey, uploadId);
      await upload.abort();
      logEvent(env, { action: "UPLOAD_ABORT", key: fileKey, email: userEmail });
      return new Response("Aborted");
    }
    case "complete": {
      const upload = env.BUCKET.resumeMultipartUpload(fileKey, uploadId);
      const parts = await request.json();

      // Validate parts structure before handing to R2 (avoids opaque 500s)
      if (!Array.isArray(parts) || parts.length === 0) {
        return new Response("Bad Request: parts must be a non-empty array", { status: 400 });
      }
      const seen = new Set();
      for (const p of parts) {
        if (!p || typeof p !== "object" || typeof p.partNumber !== "number" || typeof p.etag !== "string") {
          return new Response("Bad Request: each part must be {partNumber:number, etag:string}", { status: 400 });
        }
        if (p.partNumber < 1 || seen.has(p.partNumber)) {
          return new Response("Bad Request: invalid or duplicate partNumber", { status: 400 });
        }
        seen.add(p.partNumber);
      }

      // Final Quota Check before completing (counter row + this upload's size,
      // so "this upload tips it over" is actually caught — the old paginated
      // check excluded the file's own size and missed the boundary case).
      const priorUsed = await getUsedBytes(env);
      const head = await env.BUCKET.head(fileKey);
      const finalSize = head ? head.size : 0;
      const quotaBytes = TOTAL_QUOTA_GB * 1024 * 1024 * 1024;
      if (priorUsed + finalSize > quotaBytes) {
         await upload.abort();
         return new Response("Quota Exceeded at completion stage.", { status: 403 });
      }

      await upload.complete(parts);

      // Authoritative D1 write after successful R2 completion, and bump the
      // used_bytes counter by the final object size.
      if (head) {
        const now = Math.floor(Date.now() / 1000);
        const salt = head.customMetadata?.v || Date.now().toString();
        const exp = parseInt(head.customMetadata?.e || (now + 24 * 60 * 60).toString());
        const max_dl = parseInt(head.customMetadata?.m || "999999");
        const ot = parseInt(head.customMetadata?.ot || "0");

        await env.file_share_db.prepare(`
          INSERT INTO files (file_key, original_name, expire_at, max_downloads, download_count, version_salt, is_one_time, status, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(file_key) DO UPDATE SET
            original_name = excluded.original_name,
            expire_at = excluded.expire_at,
            max_downloads = excluded.max_downloads,
            download_count = 0,
            version_salt = excluded.version_salt,
            is_one_time = excluded.is_one_time,
            status = 'active',
            created_at = excluded.created_at,
            delete_after = NULL
        `).bind(fileKey, fileKey, exp, max_dl, 0, salt, ot, 'active', now).run();
        await addUsedBytes(env, finalSize);
      }

      logEvent(env, { action: "UPLOAD_COMPLETE", key: fileKey, email: userEmail });
      return new Response("OK");
    }
  }
}

async function renderDashboard(env, url) {
  // XSS prevention: escape all user-supplied values before inserting into HTML
  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (m) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[m]));
  }

  const { results: d1Files } = await env.file_share_db.prepare(
    "SELECT * FROM files WHERE status != 'deleted' ORDER BY created_at DESC"
  ).all();

  const now = Math.floor(Date.now() / 1000);
  
  const files = d1Files.map(o => {
    const safeKey = escapeHtml(o.file_key);
    const remains = o.expire_at - now;
    const remainsText = remains > 0 
      ? `${(remains / 3600).toFixed(1)}h` 
      : '<span style="color:red">Expired</span>';
      
    const statusColor = o.status === 'active' ? '#28a745' : '#ffc107';
    const isInactive = o.status !== 'active';

    return `
    <tr>
      <td>${safeKey}</td>
      <td>${o.download_count} / ${o.max_downloads >= 999999 ? '∞' : o.max_downloads}</td>
      <td>${remainsText}</td>
      <td><span style="background:${statusColor}; color:white; padding:2px 6px; border-radius:4px; font-size:0.85em">${escapeHtml(o.status)}</span></td>
      <td>
        <button data-action="delete" data-key="${safeKey}" style="color:red" title="Physical Delete">Delete</button>
        <button data-action="invalidate" data-key="${safeKey}" style="color:orange" ${isInactive ? 'disabled' : ''} title="Revoke and mark for deletion">Invalidate</button>
        <button data-action="copy" data-key="${safeKey}" ${isInactive ? 'disabled' : ''}>Copy</button>
        <button data-action="copy-ot" data-key="${safeKey}" style="border-style:dashed" ${isInactive ? 'disabled' : ''}>One-Time</button>
      </td>
    </tr>
    `;
  }).join("");

  const FREE_LIMIT = 10 * 1024 * 1024 * 1024; // 10GB
  const totalUsed = await getUsedBytes(env);

  const usedPercent = ((totalUsed / FREE_LIMIT) * 100).toFixed(2);
  const remainingGB = ((FREE_LIMIT - totalUsed) / 1024 / 1024 / 1024).toFixed(2);

  const SHARD_DOMAINS_JS = JSON.stringify(
    (env.SHARD_DOMAINS || url.origin).split(",").map(d => d.trim()).filter(Boolean)
  );

  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>R2 Admin (D1 Enhanced)</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; max-width: 1000px; margin: 0 auto; line-height: 1.6; background: #f4f7f9; }
      .card { background: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
      table { width: 100%; border-collapse: collapse; margin-top: 10px; }
      th, td { padding: 12px; border-bottom: 1px solid #eee; text-align: left; font-size: 0.95em; }
      th { background: #f8f9fa; color: #666; font-weight: 600; }
      .progress-container { height: 12px; background: #eee; border-radius: 6px; overflow: hidden; margin: 10px 0; }
      .progress-fill { height: 100%; background: #007bff; transition: width 0.3s; }
      .usage-info { display: flex; justify-content: space-between; font-size: 0.85em; color: #666; }
      .upload-progress { height: 20px; background: #eee; border-radius: 10px; display: none; margin: 10px 0; overflow: hidden; }
      .upload-bar { height: 100%; background: #28a745; width: 0%; transition: width 0.3s; }
      button { padding: 5px 10px; cursor: pointer; border: 1px solid #ddd; border-radius: 4px; background: #fff; font-size: 0.9em; transition: 0.2s; }
      button:hover:not(:disabled) { background: #f0f0f0; border-color: #ccc; }
      button:disabled { opacity: 0.5; cursor: not-allowed; }
      h1 { color: #333; margin-bottom: 30px; }
    </style>
  </head>
  <body>
    <h1>R2/D1 File Manager</h1>
    
    <div class="card">
      <h3 style="margin-top:0">Storage Usage (Free Tier: 10GB)</h3>
      <div class="progress-container">
        <div class="progress-fill" style="width: ${usedPercent}%"></div>
      </div>
      <div class="usage-info">
        <span>Used: ${usedPercent}% (${(totalUsed / 1024 / 1024 / 1024).toFixed(2)} GB)</span>
        <span>Remaining: ${remainingGB} GB</span>
      </div>
      <div style="margin-top:10px; font-size:0.8em; color:#888;">
        Counter is incremental; an hourly cron reconciles it. You can also
        <button data-action="reconcile" style="font-size:0.85em; padding:2px 8px;">Reconcile now</button>
        (runs a full bucket scan).
      </div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Upload File (Max 8GB)</h3>
      <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 10px;">
        <input type="file" id="fileInput" style="flex: 1">
        <div style="display: flex; flex-direction: column; gap: 2px;">
          <label style="font-size: 0.75em; color: #666;">Max Downloads</label>
          <input type="number" id="maxDownloads" value="999999" style="width: 80px; padding: 4px;">
        </div>
        <button onclick="startUpload()" style="background: #28a745; color: white; border: none; padding: 8px 16px; align-self: flex-end;">Upload</button>
      </div>
      <div class="upload-progress" id="pBox"><div class="upload-bar" id="pBar"></div></div>
      <p id="status" style="color: #666; font-size: 0.9em;"></p>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Active Files</h3>
      <table>
        <thead><tr><th>Key</th><th>DL Count</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>${files}</tbody>
      </table>
    </div>

    <script>
      const CHUNK_SIZE = 10 * 1024 * 1024;
      const SHARD_DOMAINS = ${SHARD_DOMAINS_JS};
      const MAX_PART_RETRIES = 5;

      // All admin API calls rely on the Cloudflare Access session cookie set on
      // the dashboard domain (credentials:'include'). The CF-Access-JWT-Assertion
      // header is short-lived; rather than inline it into page JS (where any XSS
      // or extension could read it), we let the Access cookie carry auth and the
      // server re-verifies the JWT on each request.


      async function adminFetch(path, options = {}) {
        return fetch(path, {
          ...options,
          credentials: 'include'
        });
      }

      async function startUpload() {
        const file = document.getElementById('fileInput').files[0];
        if (!file) return;
        const status = document.getElementById('status');
        const pBox = document.getElementById('pBox');
        const pBar = document.getElementById('pBar');
        status.innerText = 'Initializing...';
        pBox.style.display = 'block';

        let uploadId = null;
        try {
          const maxDl = document.getElementById('maxDownloads').value;
          const startRes = await adminFetch('/_admin/api/multipart/start?key=' + encodeURIComponent(file.name) + '&size=' + file.size + '&max=' + maxDl);

          if (!startRes.ok) {
            const errData = await startRes.json().catch(() => ({ error: 'Unknown server error' }));
            throw new Error(errData.error || errData.details || 'Forbidden');
          }

          const startData = await startRes.json();
          uploadId = startData.uploadId;

          const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
          const uploadedParts = new Array(totalChunks);
          let uploadedCount = 0;
          const CONCURRENCY = 6; // Standard browser limit per domain

          const queue = Array.from({ length: totalChunks }, (_, i) => ({ i, retries: 0 }));
          const uploadWorker = async (workerIndex) => {
            while (queue.length > 0) {
              const item = queue.shift();
              if (item === undefined) break;
              const { i, retries } = item;

              const start = i * CHUNK_SIZE;
              const end = Math.min(file.size, start + CHUNK_SIZE);
              const chunk = file.slice(start, end);
              const partNumber = i + 1;

              const domain = SHARD_DOMAINS.length > 0 ? SHARD_DOMAINS[partNumber % SHARD_DOMAINS.length] : window.location.origin;

              try {
                const upRes = await fetch(domain + '/_admin/api/multipart/upload?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId + '&partNumber=' + partNumber, {
                  method: 'PUT',
                  body: chunk,
                  credentials: 'include'
                });

                if (!upRes.ok) {
                  const errData = await upRes.json().catch(() => ({ error: 'Part upload failed' }));
                  const errMsg = errData.error || ('Part ' + partNumber + ' failed: ' + upRes.status);
                  throw Object.assign(new Error(errMsg), { status: upRes.status });
                }

                const partData = await upRes.json();
                uploadedParts[i] = partData;
                uploadedCount++;

                status.innerText = 'Uploading: ' + Math.round((uploadedCount/totalChunks)*100) + '% (' + uploadedCount + '/' + totalChunks + ')';
                pBar.style.width = Math.round((uploadedCount / totalChunks) * 100) + '%';
              } catch (err) {
                // Fail fast on 4xx (auth/quota/abort): retrying a permanent error
                // would loop forever and starve the queue (the original hang bug).
                if (err.status >= 400 && err.status < 500) {
                  throw new Error('Upload aborted: ' + err.message);
                }
                if (retries + 1 >= MAX_PART_RETRIES) {
                  throw new Error('Part ' + partNumber + ' failed after ' + MAX_PART_RETRIES + ' retries: ' + err.message);
                }
                console.error(err);
                // Exponential backoff with jitter before re-queueing.
                const backoff = Math.min(2000 * Math.pow(2, retries), 30000) * (0.5 + Math.random());
                status.innerText = 'Retrying part ' + partNumber + ' (attempt ' + (retries + 2) + '/' + MAX_PART_RETRIES + ')... (' + err.message + ')';
                await new Promise(r => setTimeout(r, backoff));
                queue.push({ i, retries: retries + 1 });
              }
            }
          };

          await Promise.all(Array.from({ length: Math.min(CONCURRENCY, totalChunks) }, (_, idx) => uploadWorker(idx)));

          status.innerText = 'Finalizing...';
          const completeRes = await adminFetch('/_admin/api/multipart/complete?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, {
            method: 'POST',
            body: JSON.stringify(uploadedParts)
          });

          if (!completeRes.ok) {
            const errData = await completeRes.json().catch(() => ({ error: 'Completion failed' }));
            throw new Error(errData.error || 'Completion failed');
          }

          location.reload();
        } catch (e) {
          alert('Upload failed: ' + e.message);
          if (uploadId) adminFetch('/_admin/api/multipart/abort?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, { method: 'DELETE' });
        }
      }

      async function deleteFile(k) {
        if(confirm('Permanently delete from R2 and D1?')) {
          await adminFetch('/_admin/api/delete/' + encodeURIComponent(k), { method: 'DELETE' });
          location.reload();
        }
      }

      async function invalidateFile(k) {
        if(confirm('Immediately invalidate all links and schedule for deletion? (Soft Delete)')) {
          await adminFetch('/_admin/api/invalidate?key=' + encodeURIComponent(k), { method: 'POST' });
          location.reload();
        }
      }

      async function copyLink(k, isOneTime = false) {
        try {
          const res = await adminFetch('/_admin/api/sign?key=' + encodeURIComponent(k) + (isOneTime ? '&ot=1' : ''));
          const data = await res.json();
          if (data.url) {
            navigator.clipboard.writeText(data.url);
            alert('Link copied!');
          } else { throw new Error('No URL'); }
        } catch (e) { alert('Error: ' + e.message); }
      }

      async function reconcileUsage() {
        try {
          const res = await adminFetch('/_admin/api/reconcile', { method: 'POST' });
          if (!res.ok) throw new Error('Reconcile failed');
          const data = await res.json();
          alert('Reconciled. Used bytes: ' + (data.used_bytes || 0));
          location.reload();
        } catch (e) { alert('Error: ' + e.message); }
      }

      // Event delegation: handle data-action buttons safely (XSS-proof).
      // Reconcile lives outside the tbody, so listen on document.
      document.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn || btn.disabled) return;
        const action = btn.dataset.action;
        if (action === 'reconcile') { reconcileUsage(); return; }
        // File-row actions carry data-key.
        const key = btn.dataset.key;
        if (key === undefined) return;
        if (action === 'delete') deleteFile(key);
        else if (action === 'invalidate') invalidateFile(key);
        else if (action === 'copy') copyLink(key);
        else if (action === 'copy-ot') copyLink(key, true);
      });
    </script>
  </body>
  </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}
