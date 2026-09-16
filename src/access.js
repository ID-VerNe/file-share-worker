/**
 * Cloudflare Access JWT verification.
 *
 * Verifies the CF-Access-JWT-Assertion RS256 token against the team's JWKS
 * and reads the email from the verified payload. Uses the jose library
 * (vendored at vendor/jose.mjs) — the Cloudflare-documented approach — rather
 * than a hand-rolled WebCrypto verifier, so all JWK/PEM/kid edge cases are
 * handled by the reference implementation.
 *
 * Requires two secrets: TEAM_DOMAIN (https://<team>.cloudflareaccess.com)
 * and POLICY_AUD (the Access application audience tag).
 */
import { jwtVerify, createRemoteJWKSet } from "../vendor/jose.mjs";

let remoteJwks = null;
let remoteTeam = null;

function getJwks(teamDomain) {
	if (remoteJwks && remoteTeam === teamDomain) return remoteJwks;
	remoteTeam = teamDomain;
	remoteJwks = createRemoteJWKSet(new URL("/cdn-cgi/access/certs", teamDomain));
	return remoteJwks;
}

/**
 * Verify a CF-Access-JWT-Assertion and return its payload, or null on failure.
 * Checks signature (RS256 against team JWKS), iss, aud, exp.
 */
export async function verifyAccessJwt(token, env) {
	if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
		console.log("[access] reject: missing TEAM_DOMAIN or POLICY_AUD");
		return null;
	}
	if (!token) {
		console.log("[access] reject: no CF-Access-JWT-Assertion header — request did not pass through Cloudflare Access");
		return null;
	}
	let teamDomain = env.TEAM_DOMAIN;
	if (!teamDomain.startsWith("http")) teamDomain = `https://${teamDomain}`;

	const jwks = getJwks(teamDomain);
	try {
		const { payload } = await jwtVerify(token, jwks, {
			issuer: teamDomain,
			audience: env.POLICY_AUD,
		});
		console.log("[access] OK: verified, email =", payload.email);
		return payload;
	} catch (e) {
		console.log("[access] reject:", e.code || e.name, "-", e.message);
		return null;
	}
}

/**
 * Verify the Access JWT and confirm the email claim is in the admin whitelist.
 * Returns the email if authorized, null otherwise.
 */
export async function verifyAccessEmail(token, env, adminEmails) {
	const payload = await verifyAccessJwt(token, env);
	if (!payload || !payload.email) return null;
	return adminEmails.includes(payload.email) ? payload.email : null;
}
