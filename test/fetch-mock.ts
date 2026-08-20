import { expect, vi } from "vitest";

type Match = { method?: string; path: string | RegExp; body?: string; headers?: Record<string, string | RegExp> };
type Reply = { statusCode: number; data?: BodyInit | object; responseOptions?: { headers?: HeadersInit } };
type ReplyFactory = (request: { headers: Headers }) => Reply;
type Pending = { origin: string; match: Match; reply?: Reply | ReplyFactory; remaining: number };

const pending: Pending[] = [];
let restore: (() => void) | undefined;

async function matches(entry: Pending, request: Request) {
	const url = new URL(request.url);
	if (url.origin !== entry.origin || request.method !== (entry.match.method ?? "GET")) return false;
	if (typeof entry.match.path === "string" ? `${url.pathname}${url.search}` !== entry.match.path : !entry.match.path.test(`${url.pathname}${url.search}`)) return false;
	if (entry.match.body !== undefined && entry.match.body !== await request.clone().text()) return false;
	return Object.entries(entry.match.headers ?? {}).every(([name, expected]) => {
		const actual = request.headers.get(name) ?? "";
		return typeof expected === "string" ? actual === expected : expected.test(actual);
	});
}

export const fetchMock = {
	activate() {
		if (restore) return;
		const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const request = new Request(input, init);
			let entry: Pending | undefined;
			for (const candidate of pending) if (candidate.remaining > 0 && await matches(candidate, request)) { entry = candidate; break; }
			if (!entry?.reply) throw new Error(`Unexpected fetch: ${request.method} ${request.url}`);
			entry.remaining--;
			const reply = typeof entry.reply === "function" ? entry.reply({ headers: request.headers }) : entry.reply;
			const body = reply.data === undefined || typeof reply.data === "string" ? reply.data : JSON.stringify(reply.data);
			return new Response(body, { status: reply.statusCode, headers: reply.responseOptions?.headers });
		});
		restore = () => spy.mockRestore();
	},
	disableNetConnect() {},
	deactivate() {
		restore?.();
		restore = undefined;
		pending.length = 0;
	},
	get(origin: string) {
		return { intercept(match: Match) {
			const entry: Pending = { origin, match, remaining: 1 };
			pending.push(entry);
			return { reply(statusOrFactory: number | ReplyFactory, data?: BodyInit | object, options?: { headers?: HeadersInit }) {
				entry.reply = typeof statusOrFactory === "function" ? statusOrFactory : { statusCode: statusOrFactory, data, responseOptions: options };
				return { times(count: number) { entry.remaining = count; } };
			} };
		} };
	},
	assertNoPendingInterceptors() {
		expect(pending.filter(({ remaining }) => remaining > 0)).toEqual([]);
	},
};
