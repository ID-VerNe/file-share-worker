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
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export async function verify(key, exp, signature, secretMap, kid = "v1", salt = "", ot = "0") {
  // 1. Check if signature and exp are present
  if (!signature || !exp) {
    return false;
  }

  // 2. Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (parseInt(exp) < now) {
    return false;
  }

  // 3. Generate expected signature
  try {
    const expectedSignature = await sign(key, exp, secretMap, kid, salt, ot);
    // 4. Constant-time comparison
    return safeCompare(signature, expectedSignature);
  } catch (e) {
    console.error(`Verification error: ${e.message}`);
    return false;
  }
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
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
