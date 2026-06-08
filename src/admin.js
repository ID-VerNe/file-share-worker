/**
 * Admin dashboard and API logic
 */
import { sign } from "./crypto.js";
import { logEvent } from "./logger.js";

export async function handleAdminRequest(request, env, url, isAdmin) {
  if (!isAdmin) return new Response("Forbidden: Admin Only", { status: 403 });

  const userEmail = request.headers.get("CF-Access-Authenticated-User-Email") || "admin";

  if (url.pathname === "/_admin") {
    return renderDashboard(env);
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
      await env.BUCKET.delete(deleteKey);
      await env.file_share_db.prepare("UPDATE files SET status = 'deleted' WHERE file_key = ?").bind(deleteKey).run();
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
        "SELECT version_salt, status, expire_at FROM files WHERE file_key = ?"
      ).bind(key).first();

      if (!file || file.status !== 'active') {
        return new Response("Forbidden: File is inactive or expired", { status: 403 });
      }

      // 2. Expiration logic
      let exp = requestedExp || file.expire_at;
      if (exp > maxExp) exp = maxExp;
      
      const signature = await sign(key, exp, env.AUTH_SECRET || env.GET_SIGNATURE, kid, file.version_salt, ot);
      
      logEvent(env, { action: "SIGN", key, email: userEmail });
      
      return Response.json({
        key,
        exp,
        signature,
        kid,
        ot,
        url: `${url.origin}/${encodeURIComponent(key)}?s=${signature}&e=${exp}&k=${kid}${ot === "1" ? "&ot=1" : ""}`
      });
    }

    // New: Revoke API
    if (action === "revoke" && request.method === "POST") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("Key required", { status: 400 });
      
      const newVersion = Date.now().toString();
      const head = await env.BUCKET.head(key);
      if (!head) return new Response("Not Found", { status: 404 });

      // Use copyObject to update metadata
      await env.BUCKET.put(key, head.body, {
        customMetadata: { ...head.customMetadata, v: newVersion },
        httpMetadata: head.httpMetadata
      });

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
        return new Response(`Forbidden: File type .${ext} is not allowed for security reasons.`, { status: 403 });
      }

      const fileSize = parseInt(url.searchParams.get("size") || "0");
      const MAX_SIZE = 5 * 1024 * 1024 * 1024; // 5GB Single File
      if (fileSize > MAX_SIZE) return new Response(`File too large. Max 5GB.`, { status: 400 });

      // 2. Storage Quota Check
      const list = await env.BUCKET.list();
      let totalUsed = 0;
      for (const obj of list.objects) {
        totalUsed += obj.size;
      }
      
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
      
      // Final Quota Check before completing (Defense in Depth)
      const list = await env.BUCKET.list();
      let totalUsed = 0;
      for (const obj of list.objects) {
        if (obj.key !== fileKey) totalUsed += obj.size; // Don't count old version of same file
      }
      
      // We don't have the exact final size yet easily, but we can approximate or use the start size.
      // Multipart complete is the point of no return.
      const quotaBytes = TOTAL_QUOTA_GB * 1024 * 1024 * 1024;
      if (totalUsed > quotaBytes) {
         await upload.abort();
         return new Response("Quota Exceeded at completion stage.", { status: 403 });
      }

      await upload.complete(parts);
      
      // 2. NEW: Authoritative D1 Write after successful R2 completion
      const head = await env.BUCKET.head(fileKey);
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
      }

      logEvent(env, { action: "UPLOAD_COMPLETE", key: fileKey, email: userEmail });
      return new Response("OK");
    }
  }
}

async function renderDashboard(env) {
  const { results: d1Files } = await env.file_share_db.prepare(
    "SELECT * FROM files WHERE status != 'deleted' ORDER BY created_at DESC"
  ).all();

  const now = Math.floor(Date.now() / 1000);
  
  const files = d1Files.map(o => {
    const remains = o.expire_at - now;
    const remainsText = remains > 0 
      ? `${(remains / 3600).toFixed(1)}h` 
      : '<span style="color:red">Expired</span>';
      
    const statusColor = o.status === 'active' ? '#28a745' : '#ffc107';
    const isInactive = o.status !== 'active';

    return `
    <tr>
      <td>${o.file_key}</td>
      <td>${o.download_count} / ${o.max_downloads >= 999999 ? '∞' : o.max_downloads}</td>
      <td>${remainsText}</td>
      <td><span style="background:${statusColor}; color:white; padding:2px 6px; border-radius:4px; font-size:0.85em">${o.status}</span></td>
      <td>
        <button onclick="deleteFile('${o.file_key}')" style="color:red" title="Physical Delete">Delete</button>
        <button onclick="invalidateFile('${o.file_key}')" style="color:orange" ${isInactive ? 'disabled' : ''} title="Revoke and mark for deletion">Invalidate</button>
        <button onclick="copyLink('${o.file_key}')" ${isInactive ? 'disabled' : ''}>Copy</button>
        <button onclick="copyLink('${o.file_key}', true)" style="border-style:dashed" ${isInactive ? 'disabled' : ''}>One-Time</button>
      </td>
    </tr>
    `;
  }).join("");

  const list = await env.BUCKET.list();
  const FREE_LIMIT = 10 * 1024 * 1024 * 1024; // 10GB
  let totalUsed = 0;
  list.objects.forEach(o => totalUsed += o.size);

  const usedPercent = ((totalUsed / FREE_LIMIT) * 100).toFixed(2);
  const remainingGB = ((FREE_LIMIT - totalUsed) / 1024 / 1024 / 1024).toFixed(2);

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
    </div>

    <div class="card">
      <h3 style="margin-top:0">Upload File (Max 5GB)</h3>
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
      const CHUNK_SIZE = 40 * 1024 * 1024; 

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
          const startRes = await fetch('/_admin/api/multipart/start?key=' + encodeURIComponent(file.name) + '&size=' + file.size + '&max=' + maxDl);
          const startData = await startRes.json();
          uploadId = startData.uploadId;

          const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
          const uploadedParts = [];

          for (let i = 0; i < totalChunks; i++) {
            const start = i * CHUNK_SIZE;
            const end = Math.min(file.size, start + CHUNK_SIZE);
            const chunk = file.slice(start, end);
            const partNumber = i + 1;
            status.innerText = 'Uploading: ' + Math.round((i/totalChunks)*100) + '%';
            const upRes = await fetch('/_admin/api/multipart/upload?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId + '&partNumber=' + partNumber, {
              method: 'PUT',
              body: chunk
            });
            const partData = await upRes.json();
            uploadedParts.push(partData);
            pBar.style.width = Math.round((partNumber / totalChunks) * 100) + '%';
          }

          status.innerText = 'Finalizing...';
          await fetch('/_admin/api/multipart/complete?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, {
            method: 'POST',
            body: JSON.stringify(uploadedParts)
          });
          location.reload();
        } catch (e) {
          alert('Upload failed: ' + e.message);
          if (uploadId) fetch('/_admin/api/multipart/abort?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, { method: 'DELETE' });
        }
      }

      async function deleteFile(k) {
        if(confirm('Permanently delete from R2 and D1?')) {
          await fetch('/_admin/api/delete/' + encodeURIComponent(k), { method: 'DELETE' });
          location.reload();
        }
      }

      async function invalidateFile(k) {
        if(confirm('Immediately invalidate all links and schedule for deletion? (Soft Delete)')) {
          await fetch('/_admin/api/invalidate?key=' + encodeURIComponent(k), { method: 'POST' });
          location.reload();
        }
      }
      
      async function copyLink(k, isOneTime = false) {
        try {
          const res = await fetch('/_admin/api/sign?key=' + encodeURIComponent(k) + (isOneTime ? '&ot=1' : ''));
          const data = await res.json();
          if (data.url) {
            navigator.clipboard.writeText(data.url);
            alert('Link copied!');
          } else { throw new Error('No URL'); }
        } catch (e) { alert('Error: ' + e.message); }
      }
    </script>
  </body>
  </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}
