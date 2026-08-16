import { argon2 } from "node:crypto";

const ITERATIONS = 600_000;
const ARGON2_MEMORY = 19_456;
const ARGON2_PASSES = 2;
const ARGON2_PARALLELISM = 1;
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

function deriveArgon2(password: string, salt: Uint8Array, memory: number, passes: number, parallelism: number): Promise<Uint8Array> {
	if (typeof argon2 !== "function") return Promise.reject(new Error("Argon2id is unavailable in this Workers runtime"));
	return new Promise((resolve, reject) => argon2("argon2id", { message: encoder.encode(password), nonce: salt, memory, passes, parallelism, tagLength: 32 }, (error, key) => error ? reject(error) : resolve(key)));
}

async function equal(left: Uint8Array, right: Uint8Array): Promise<boolean> {
	if (left.length !== right.length) return false;
	const key = await crypto.subtle.importKey("raw", left, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signature = await crypto.subtle.sign("HMAC", key, new Uint8Array());
	const candidate = await crypto.subtle.importKey("raw", right, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
	return crypto.subtle.verify("HMAC", candidate, signature, new Uint8Array());
}

export async function hashPassword(password: string): Promise<string> {
	if (password.length < 8 || password.length > 256) throw new TypeError("Password must be between 8 and 256 characters");
	const salt = crypto.getRandomValues(new Uint8Array(16));
	if (typeof argon2 !== "function") return `pbkdf2-sha256$${ITERATIONS}$${encode(salt)}$${encode(await derive(password, salt, ITERATIONS))}`;
	return `argon2id$v=19$m=${ARGON2_MEMORY},t=${ARGON2_PASSES},p=${ARGON2_PARALLELISM}$${encode(salt)}$${encode(await deriveArgon2(password, salt, ARGON2_MEMORY, ARGON2_PASSES, ARGON2_PARALLELISM))}`;
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
	try {
		if (encoded.startsWith("argon2id$")) {
			const [algorithm, version, parameters, salt, expected, extra] = encoded.split("$");
			const match = /^m=(\d+),t=(\d+),p=(\d+)$/.exec(parameters);
			if (algorithm !== "argon2id" || version !== "v=19" || !match || extra) return false;
			const [memory, passes, parallelism] = match.slice(1).map(Number);
			if (memory < 19_456 || memory > 262_144 || passes < 2 || passes > 10 || parallelism < 1 || parallelism > 16) return false;
			return equal(await deriveArgon2(password, decode(salt), memory, passes, parallelism), decode(expected));
		}
		const [algorithm, count, salt, expected, extra] = encoded.split("$");
		if (algorithm !== "pbkdf2-sha256" || extra) return false;
		const iterations = Number(count);
		if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) return false;
		return equal(await derive(password, decode(salt), iterations), decode(expected));
	} catch { return false; }
}

let dummyHash: Promise<string> | undefined;

export async function verifyPasswordOrDummy(password: string, encoded?: string): Promise<boolean> {
	const valid = await verifyPassword(password, encoded ?? await (dummyHash ??= hashPassword("invalid account password")));
	return Boolean(encoded) && valid;
}
