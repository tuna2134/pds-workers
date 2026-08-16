function decode(value: string): Uint8Array {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
	return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encode(value: Uint8Array): string {
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function wrappingKey(secret: string): Promise<CryptoKey> {
	const bytes = decode(secret);
	if (bytes.length !== 32) throw new Error("SIGNING_KEY_WRAPPING_SECRET must be 32 bytes encoded as base64url");
	return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function wrapKey(privateKey: Uint8Array, secret: string): Promise<string> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, await wrappingKey(secret), privateKey));
	return `${encode(nonce)}.${encode(ciphertext)}`;
}

export async function unwrapKey(wrapped: string, secret: string): Promise<Uint8Array> {
	const [nonce, ciphertext, extra] = wrapped.split(".");
	if (!nonce || !ciphertext || extra) throw new Error("Invalid wrapped key");
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(nonce) }, await wrappingKey(secret), decode(ciphertext)));
}
