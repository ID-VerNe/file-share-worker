/**
 * R2 Bucket operations
 */

export async function getFile(env, key, request) {
  if (!key) {
    return new Response("Bad Request: Missing file key", { status: 400 });
  }
  
  const rangeHeader = request.headers.get("Range");
  const options = {};
  if (rangeHeader) {
    options.range = request.headers;
  }

  const object = await env.BUCKET.get(key, options);
  if (object === null) {
    return new Response("Resource Not Found", { status: 404 });
  }
  
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  
  const encodedKey = encodeURIComponent(key)
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
    
  const safeFilename = key.replace(/"/g, '\\"');
  headers.set("Content-Disposition", `attachment; filename="${safeFilename}"; filename*=UTF-8''${encodedKey}`);
  
  const status = object.body ? (rangeHeader ? 206 : 200) : 304;
  return new Response(object.body, { 
    status,
    headers 
  });
}
