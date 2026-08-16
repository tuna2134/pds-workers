import { timingSafeEqual } from "node:crypto";

export async function constantTimeEqual(left: string, right: string) {
	const digest = async (value: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
	return timingSafeEqual(await digest(left), await digest(right));
}
