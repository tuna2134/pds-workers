import { DurableObject } from "cloudflare:workers";
import { asc, desc, eq, gte, lte } from "drizzle-orm";
import { drizzle, type DrizzleSqliteDODatabase } from "drizzle-orm/durable-sqlite";
import { migrate } from "drizzle-orm/durable-sqlite/migrator";
import { CID } from "multiformats/cid";
import migrations from "../db/firehose-migrations";
import * as schema from "../db/schema/firehose";
import { streamError, streamFrame } from "../sync/frame";
import { decodeCar, encodeCar } from "../repo/car";
import { notifyCrawlers } from "../sync/crawler";

const RETAIN_EVENTS = 10_000;

export interface CommitEventInput {
	id: string;
	repo: string;
	rev: string;
	since: string | null;
	commit: string;
	blocks: Uint8Array<ArrayBufferLike>;
	prevData?: string;
	ops: { action: "create" | "update" | "delete"; path: string; cid: string | null; prev?: string }[];
	time: string;
}

export class Firehose extends DurableObject<Env> {
	readonly #db: DrizzleSqliteDODatabase<typeof schema>;
	#writeTail: Promise<void> = Promise.resolve();

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.#db = drizzle(ctx.storage, { schema });
		ctx.blockConcurrencyWhile(() => migrate(this.#db, migrations));
	}

	async publishCommit(input: CommitEventInput): Promise<number> {
		return this.#serialize(async () => {
			if (input.ops.length > 200 || input.blocks.length > 2_000_000) {
				const car = await decodeCar(input.blocks);
				const commit = CID.parse(input.commit);
				const block = car.blocks.find(({ cid }) => cid.equals(commit));
				if (!car.roots[0]?.equals(commit) || !block) throw new TypeError("Commit diff does not contain its root commit block");
				const blocks = encodeCar(commit, [block]);
				if (blocks.length > 10_000) throw new RangeError("Sync commit block exceeds 10 KB");
				return this.#publish(input.id, "#sync", (seq) => ({ seq, did: input.repo, rev: input.rev, blocks, time: input.time }));
			}
			return this.#publish(input.id, "#commit", (seq) => ({
				seq, rebase: false, tooBig: false, repo: input.repo,
				commit: CID.parse(input.commit), rev: input.rev, since: input.since,
				blocks: input.blocks,
				ops: input.ops.map((op) => ({ action: op.action, path: op.path, cid: op.cid ? CID.parse(op.cid) : null, ...(op.prev ? { prev: CID.parse(op.prev) } : {}) })),
				blobs: [], ...(input.prevData ? { prevData: CID.parse(input.prevData) } : {}), time: input.time,
			}));
		});
	}

	publishIdentity(id: string, did: string, handle?: string): Promise<number> {
		return this.#publishAndNotify(() => this.#serialize(() => this.#publish(id, "#identity", (seq) => ({ seq, did, time: new Date().toISOString(), ...(handle ? { handle } : {}) }))));
	}

	publishAccount(id: string, did: string, active: boolean, status?: string): Promise<number> {
		return this.#publishAndNotify(() => this.#serialize(() => this.#publish(id, "#account", (seq) => ({ seq, did, time: new Date().toISOString(), active, ...(status ? { status } : {}) }))));
	}

	async #publishAndNotify(publish: () => Promise<number>): Promise<number> {
		const seq = await publish();
		this.ctx.waitUntil(notifyCrawlers(this.env.CRAWLERS, this.env.PDS_URL).catch((error) => console.error(JSON.stringify({ error: error instanceof Error ? error.message : "Crawler notification failed" }))));
		return seq;
	}

	pitrBookmark(at?: number) {
		return at === undefined ? this.ctx.storage.getCurrentBookmark() : this.ctx.storage.getBookmarkForTime(at);
	}

	schedulePitrRestore(bookmark: string) {
		return this.ctx.storage.onNextSessionRestoreBookmark(bookmark);
	}

	async #publish(id: string, type: string, payload: (seq: number) => object): Promise<number> {
		const duplicate = await this.#db.select().from(schema.firehoseEvents).where(eq(schema.firehoseEvents.id, id)).get();
		if (duplicate) return duplicate.seq;
		let frame!: Uint8Array;
		const seq = await this.#db.transaction(async (tx) => {
			const [inserted] = await tx.insert(schema.firehoseEvents).values({ id, type, frame: Buffer.alloc(0), createdAt: new Date() }).returning({ seq: schema.firehoseEvents.seq });
			frame = streamFrame(type, payload(inserted.seq));
			if (frame.length > 5_000_000) throw new RangeError("Firehose frame exceeds 5 MB");
			await tx.update(schema.firehoseEvents).set({ frame: Buffer.from(frame) }).where(eq(schema.firehoseEvents.seq, inserted.seq));
			await tx.delete(schema.firehoseEvents).where(lte(schema.firehoseEvents.seq, inserted.seq - RETAIN_EVENTS));
			return inserted.seq;
		});
		for (const socket of this.ctx.getWebSockets()) {
			try { socket.send(frame); } catch { socket.close(1008, "ConsumerTooSlow"); }
		}
		console.log(JSON.stringify({ event: "firehose.publish", type, seq, ...(type === "#commit" || type === "#sync" ? { commit: id } : {}) }));
		return seq;
	}

	async fetch(request: Request): Promise<Response> {
		if (request.method !== "GET") return Response.json({ error: "MethodNotAllowed" }, { status: 405 });
		if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return Response.json({ error: "UpgradeRequired" }, { status: 426 });
		const cursorText = new URL(request.url).searchParams.get("cursor");
		const cursor = cursorText === null ? null : Number(cursorText);
		if (cursor !== null && (!Number.isSafeInteger(cursor) || cursor < 0)) return Response.json({ error: "InvalidRequest", message: "cursor must be a non-negative safe integer" }, { status: 400 });
		return this.#serialize(() => this.#subscribe(cursor));
	}

	async #subscribe(cursor: number | null): Promise<Response> {
		const latest = await this.#db.select().from(schema.firehoseEvents).orderBy(desc(schema.firehoseEvents.seq)).limit(1).get();
		const oldest = await this.#db.select().from(schema.firehoseEvents).orderBy(asc(schema.firehoseEvents.seq)).limit(1).get();
		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		this.ctx.acceptWebSocket(server);
		if (cursor !== null && latest && cursor > latest.seq) {
			server.send(streamError("FutureCursor"));
			server.close(1008, "FutureCursor");
		} else if (cursor !== null) {
			if (oldest && cursor !== 0 && cursor < oldest.seq) server.send(streamFrame("#info", { name: "OutdatedCursor", message: "Cursor is outside the retained backfill window" }));
			const start = !oldest ? 1 : cursor === 0 || cursor < oldest.seq ? oldest.seq : cursor + 1;
			for (const event of await this.#db.select().from(schema.firehoseEvents).where(gte(schema.firehoseEvents.seq, start)).orderBy(asc(schema.firehoseEvents.seq)).all()) server.send(event.frame);
		}
		return new Response(null, { status: 101, webSocket: client });
	}

	webSocketMessage(_socket: WebSocket, _message: ArrayBuffer | string) {}
	webSocketClose(socket: WebSocket, code: number, reason: string, _wasClean: boolean) { socket.close(code, reason); }
	webSocketError(socket: WebSocket) { socket.close(1011, "WebSocket error"); }

	#serialize<T>(operation: () => Promise<T>): Promise<T> {
		const result = this.#writeTail.then(operation);
		this.#writeTail = result.then(() => undefined, () => undefined);
		return result;
	}
}
