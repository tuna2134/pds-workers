import { jsonToLex, type RecordSchema } from "@atproto/lex";
import { main as profile } from "./generated/app/bsky/actor/profile.defs";
import { main as status } from "./generated/app/bsky/actor/status.defs";
import { main as generator } from "./generated/app/bsky/feed/generator.defs";
import { main as like } from "./generated/app/bsky/feed/like.defs";
import { main as post } from "./generated/app/bsky/feed/post.defs";
import { main as postgate } from "./generated/app/bsky/feed/postgate.defs";
import { main as repost } from "./generated/app/bsky/feed/repost.defs";
import { main as threadgate } from "./generated/app/bsky/feed/threadgate.defs";
import { main as block } from "./generated/app/bsky/graph/block.defs";
import { main as follow } from "./generated/app/bsky/graph/follow.defs";
import { main as list } from "./generated/app/bsky/graph/list.defs";
import { main as listitem } from "./generated/app/bsky/graph/listitem.defs";
import { main as lexicon } from "./generated/com/atproto/lexicon/schema.defs";

const records = new Map<string, RecordSchema>([
	profile,
	status,
	generator,
	like,
	post,
	postgate,
	repost,
	threadgate,
	block,
	follow,
	list,
	listitem,
	lexicon,
].map((schema) => [schema.$type, schema]));

export type ValidationStatus = "valid" | "unknown";

export function validateRecord(collection: string, rkey: string, record: Record<string, unknown>, validate?: boolean): ValidationStatus {
	const value = jsonToLex(record as never, { strict: true });
	if (validate === false) return "unknown";
	const schema = records.get(collection);
	if (!schema) {
		if (validate === true) throw new TypeError(`No Lexicon available for ${collection}`);
		return "unknown";
	}
	const key = schema.keySchema.safeParse(rkey);
	if (!key.success) throw new TypeError(key.reason.message);
	const result = schema.safeParse(value);
	if (!result.success) throw new TypeError(result.reason.message);
	return "valid";
}
