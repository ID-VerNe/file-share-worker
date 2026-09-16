/**
 * Logging and Analytics utility
 */

export function logEvent(env, { action, key, email = "public", status = 200, size = 0, ot = false, count = 0 }) {
  const timestamp = new Date().toISOString();
  
  // Desensitize email: yuu_seeing@foxmail.com -> y***g@foxmail.com
  let maskedEmail = email;
  if (email && email.includes("@")) {
    const [user, domain] = email.split("@");
    if (user.length <= 2) {
      maskedEmail = `${user[0]}***@${domain}`;
    } else {
      maskedEmail = `${user[0]}***${user[user.length - 1]}@${domain}`;
    }
  }

  const logData = {
    timestamp,
    action,
    key,
    email: maskedEmail,
    status,
    size,
    ot,
    count
  };

  // 1. Structured Console Logging (visible in Cloudflare Dashboard)
  // We NEVER log the full signature URL or the HMAC secret.
  console.log(JSON.stringify(logData));

  // 2. Cloudflare Analytics Engine (if binding is present)
  if (env.ANALYTICS) {
    try {
      env.ANALYTICS.writeDataPoint({
        blobs: [
          action,        // blob1
          key,           // blob2
          maskedEmail,   // blob3
          status.toString() // blob4
        ],
        doubles: [
          size           // double1
        ],
        indexes: [key]   // index by key
      });
    } catch (e) {
      console.error(`Failed to write to Analytics Engine: ${e.message}`);
    }
  }
}
