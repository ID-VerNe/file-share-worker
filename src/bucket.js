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

  // R2 returns object.range when a Range was requested. The header set must
  // include Content-Range and the partial Content-Length for a valid 206; the
  // client (players, resumable downloaders) needs both to seek correctly.
  if (rangeHeader && object.range) {
    const r = object.range;
    // R2Range is one of {offset,length}, {offset}, {suffix}. Compute the
    // concrete [start,end] the server actually returned.
    let start, end;
    if (typeof r.suffix === "number") {
      start = Math.max(0, object.size - r.suffix);
      end = object.size - 1;
    } else {
      start = typeof r.offset === "number" ? r.offset : 0;
      const len = typeof r.length === "number" ? r.length : (object.size - start);
      end = Math.min(start + len - 1, object.size - 1);
    }
    headers.set("Content-Range", `bytes ${start}-${end}/${object.size}`);
    headers.set("Content-Length", String(end - start + 1));
    return new Response(object.body, { status: 206, headers });
  }

  // No Range: full object. body is undefined only when an onlyIf precondition
  // fails, which we never set (we don't pass onlyIf), so this is the full body.
  if (object.body) {
    headers.set("Content-Length", String(object.size));
    return new Response(object.body, { status: 200, headers });
  }

  // Defensive: no body and no range — treat as not found rather than emit an
  // unreachable 304 that nothing in the request flow can produce.
  return new Response("Resource Not Found", { status: 404 });
}
