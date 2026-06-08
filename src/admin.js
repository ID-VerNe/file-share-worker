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
      logEvent(env, { action: "DELETE", key: deleteKey, email: userEmail });
      return new Response("Deleted");
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
      
      // Default expiration: 24 hours, max: 30 days
      let exp = requestedExp || (now + 24 * 60 * 60);
      if (exp > maxExp) exp = maxExp;

      // Fetch revocation salt from metadata
      const head = await env.BUCKET.head(key);
      const salt = head?.customMetadata?.v || "";
      
      const signature = await sign(key, exp, env.AUTH_SECRET || env.GET_SIGNATURE, kid, salt, ot);
      
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

      const upload = await env.BUCKET.createMultipartUpload(fileKey);
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
      logEvent(env, { action: "UPLOAD_COMPLETE", key: fileKey, email: userEmail });
      return new Response("OK");
    }
  }
}

async function renderDashboard(env) {
  const list = await env.BUCKET.list();
  
  const FREE_LIMIT = 10 * 1024 * 1024 * 1024; // 10GB
  let totalUsed = 0;
  
  const files = list.objects.map(o => {
    totalUsed += o.size;
    return `
    <tr>
      <td>${o.key}</td>
      <td>${(o.size / 1024 / 1024).toFixed(2)} MB</td>
      <td>${new Date(o.uploaded).toLocaleString()}</td>
      <td>
        <button onclick="deleteFile('${o.key}')" style="color:red">Delete</button>
        <button onclick="revokeFile('${o.key}')" style="color:orange">Revoke Links</button>
        <button onclick="copyLink('${o.key}')">Copy Link</button>
        <button onclick="copyLink('${o.key}', true)" style="border-style:dashed">One-Time Link</button>
      </td>
    </tr>
    `;
  }).join("");

  const usedPercent = ((totalUsed / FREE_LIMIT) * 100).toFixed(2);
  const remainingGB = ((FREE_LIMIT - totalUsed) / 1024 / 1024 / 1024).toFixed(2);

  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>R2 Admin</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
      body { font-family: sans-serif; padding: 20px; max-width: 900px; margin: 0 auto; line-height: 1.6; background: #f4f7f9; }
      .card { background: #fff; border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: 12px; border-bottom: 1px solid #eee; text-align: left; }
      .progress-container { height: 12px; background: #eee; border-radius: 6px; overflow: hidden; margin: 10px 0; }
      .progress-fill { height: 100%; background: #007bff; transition: width 0.3s; }
      .usage-info { display: flex; justify-content: space-between; font-size: 0.9em; color: #555; }
      .upload-progress { height: 20px; background: #eee; border-radius: 10px; display: none; margin: 10px 0; overflow: hidden; }
      .upload-bar { height: 100%; background: #28a745; width: 0%; transition: width 0.3s; }
      button { padding: 6px 12px; cursor: pointer; border: 1px solid #ddd; border-radius: 4px; background: #fff; }
      button:hover { background: #f0f0f0; }
      h1 { color: #333; }
    </style>
  </head>
  <body>
    <h1>R2 Manager</h1>
    
    <div class="card">
      <h3 style="margin-top:0">R2 Storage Usage (Free Tier: 10GB)</h3>
      <div class="progress-container">
        <div class="progress-fill" style="width: ${usedPercent}%"></div>
      </div>
      <div class="usage-info">
        <span>Used: ${usedPercent}% (${(totalUsed / 1024 / 1024 / 1024).toFixed(2)} GB)</span>
        <span>Remaining: ${remainingGB} GB</span>
      </div>
    </div>

    <div class="card">
      <h3>Upload File (Max 5GB)</h3>
      <input type="file" id="fileInput">
      <button onclick="startUpload()" style="background: #28a745; color: white; border: none;">Upload</button>
      <div class="upload-progress" id="pBox"><div class="upload-bar" id="pBar"></div></div>
      <p id="status" style="color: #666;"></p>
    </div>

    <div class="card">
      <table>
        <thead><tr><th>Name</th><th>Size</th><th>Date</th><th>Actions</th></tr></thead>
        <tbody>${files}</tbody>
      </table>
    </div>

    <script>
      const CHUNK_SIZE = 40 * 1024 * 1024; 

      async function startUpload() {
        const file = document.getElementById('fileInput').files[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024 * 1024) return alert('File too large (Max 5GB)');

        const status = document.getElementById('status');
        const pBox = document.getElementById('pBox');
        const pBar = document.getElementById('pBar');
        
        status.innerText = 'Initializing...';
        pBox.style.display = 'block';

        let uploadId = null;
        try {
          const startRes = await fetch('/_admin/api/multipart/start?key=' + encodeURIComponent(file.name) + '&size=' + file.size);
          const startData = await startRes.json();
          uploadId = startData.uploadId;

          const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
          const uploadedParts = [];

          for (let i = 0; i < totalChunks; i++) {
            const start = i * CHUNK_SIZE;
            const end = Math.min(file.size, start + CHUNK_SIZE);
            const chunk = file.slice(start, end);
            const partNumber = i + 1;
            status.innerText = 'Uploading part ' + partNumber + '/' + totalChunks + '...';
            const upRes = await fetch('/_admin/api/multipart/upload?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId + '&partNumber=' + partNumber, {
              method: 'PUT',
              body: chunk
            });
            if (!upRes.ok) throw new Error('Failed to upload part ' + partNumber);
            const partData = await upRes.json();
            uploadedParts.push(partData);
            pBar.style.width = Math.round((partNumber / totalChunks) * 100) + '%';
          }

          status.innerText = 'Finalizing...';
          const completeRes = await fetch('/_admin/api/multipart/complete?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, {
            method: 'POST',
            body: JSON.stringify(uploadedParts)
          });
          if (!completeRes.ok) throw new Error('Failed to complete upload');

          alert('Upload Complete!');
          location.reload();
        } catch (e) {
          console.error(e);
          status.innerText = 'Error: ' + e.message;
          if (uploadId) {
            status.innerText += ' (Aborting upload...)';
            await fetch('/_admin/api/multipart/abort?key=' + encodeURIComponent(file.name) + '&uploadId=' + uploadId, { method: 'DELETE' });
            status.innerText += ' Done.';
          }
          alert('Upload failed: ' + e.message);
        }
      }

      async function deleteFile(k) {
        if(confirm('Delete?')) {
          await fetch('/_admin/api/delete/' + encodeURIComponent(k), { method: 'DELETE' });
          location.reload();
        }
      }

      async function revokeFile(k) {
        if(confirm('Revoke all current links for this file? All existing shared links will immediately become invalid.')) {
          await fetch('/_admin/api/revoke?key=' + encodeURIComponent(k), { method: 'POST' });
          alert('Links revoked!');
        }
      }
      
      async function copyLink(k, isOneTime = false) {
        try {
          const res = await fetch('/_admin/api/sign?key=' + encodeURIComponent(k) + (isOneTime ? '&ot=1' : ''));
          const data = await res.json();
          navigator.clipboard.writeText(data.url);
          alert(isOneTime ? 'One-Time Link copied! (Valid for 24h, invalidates after first access)' : 'Link copied to clipboard! (Valid for 24h)');
        } catch (e) {
          alert('Failed to get signed link');
        }
      }
    </script>
  </body>
  </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}
