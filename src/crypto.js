/**
 * HMAC-SHA256 Signature module
 */

export async function sign(key, exp, secretMap, kid = "v1", salt = "", ot = "0") {
  const secret = getSecret(secretMap, kid);
  if (!secret) throw new Error(`Secret not found for kid: ${kid}`);

  const data = `GET:${key}:${exp}:${salt}:${ot}`;
  const cryptoKey = await crypto.subtle.importKey(
    "raw", 
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, 
    false, 
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
  return toBase64(new Uint8Array(sig))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export async function verify(key, exp, signature, secretMap, kid = "v1", salt = "", ot = "0") {
  // Always compute the expected HMAC before deciding, then compare in constant
  // time. Avoids leaking (via early-return timing) whether the signature is
  // missing or the link has expired.
  const now = Math.floor(Date.now() / 1000);
  const expInt = parseInt(exp);
  const expired = !(Number.isInteger(expInt) && expInt >= now);

  let expectedSignature = "";
  try {
    expectedSignature = await sign(key, exp, secretMap, kid, salt, ot);
  } catch (e) {
    console.error(`Verification error: ${e.message}`);
    return false;
  }

  return !expired && safeCompare(signature || "", expectedSignature);
}

function toBase64(bytes) {
  // Chunked base64: avoids the call-stack limit of spreading large buffers.
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function getSecret(secretMap, kid) {
  if (!secretMap) return null;
  if (typeof secretMap === "string") {
    try {
      const parsed = JSON.parse(secretMap);
      return parsed[kid] || null;
    } catch {
      // If not JSON, treat the string as the secret for "v1"
      return kid === "v1" ? secretMap : null;
    }
  }
  return null;
}

function safeCompare(a, b) {
  const maxLen = Math.max(a.length, b.length);
  let result = a.length ^ b.length; // non-zero if lengths differ
  for (let i = 0; i < maxLen; i++) {
    result |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return result === 0;
}
