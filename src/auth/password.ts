// Cloudflare Workers WebCrypto rejects PBKDF2 counts above 100,000.
const ITERATIONS = 100_000;
const encoder = new TextEncoder();

function encode(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decode(value: string): Uint8Array {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
	return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}

export async function hashPassword(password: string): Promise<string> {
	if (password.length < 8 || password.length > 256) {
		throw new TypeError("Password must be between 8 and 256 characters");
	}

	const salt = crypto.getRandomValues(new Uint8Array(16));

	return `pbkdf2-sha256$${ITERATIONS}$${encode(salt)}$${encode(await derive(password, salt, ITERATIONS))}`;
}

async function equal(left: Uint8Array, right: Uint8Array): Promise<boolean> {
	if (left.length !== right.length) return false;
	const key = await crypto.subtle.importKey("raw", left, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = await crypto.subtle.sign("HMAC", key, new Uint8Array());
	const candidate = await crypto.subtle.importKey("raw", right, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
	return crypto.subtle.verify("HMAC", candidate, signature, new Uint8Array());
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
	try {
		const [algorithm, count, salt, expected, extra] = encoded.split("$");
		if (algorithm !== "pbkdf2-sha256" || extra) return false;
		const iterations = Number(count);
		if (!Number.isInteger(iterations) || iterations !== ITERATIONS) return false;
		return equal(await derive(password, decode(salt), iterations), decode(expected));
	} catch { return false; }
}

let dummyHash: Promise<string> | undefined;

export async function verifyPasswordOrDummy(password: string, encoded?: string): Promise<boolean> {
	const valid = await verifyPassword(password, encoded ?? await (dummyHash ??= hashPassword("invalid account password")));
	return Boolean(encoded) && valid;
}
