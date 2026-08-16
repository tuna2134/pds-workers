import type { CID } from "multiformats/cid";
import { encodeCar } from "./car";
import { createCommit } from "./commit";
import { buildMst } from "./mst";

export interface RepoEntry { cid: CID; bytes: Uint8Array<ArrayBufferLike> }
export interface RepoOperation { action: "create" | "update" | "delete"; path: string; cid: string | null; prev?: string }

async function diff(commit: RepoEntry, tree: Awaited<ReturnType<typeof buildMst>>, entries: [string, RepoEntry][], previousEntries: [string, RepoEntry][], operations: RepoOperation[]) {
	const oldTree = await buildMst(previousEntries.map(([key, record]) => ({ key, value: record.cid })));
	const oldCids = new Set(oldTree.blocks.map((block) => block.cid.toString()));
	const newCids = new Set(tree.blocks.map((block) => block.cid.toString()));
	const changedNodes = [...tree.blocks.filter((block) => !oldCids.has(block.cid.toString())), ...oldTree.blocks.filter((block) => !newCids.has(block.cid.toString()))];
	const changedRecords = entries.filter(([, record]) => operations.some((operation) => operation.cid === record.cid.toString())).map(([, record]) => record);
	const seen = new Set<string>();
	const blocks = [commit, ...changedNodes, ...changedRecords].filter((block) => {
		const cid = block.cid.toString();
		if (seen.has(cid)) return false;
		seen.add(cid);
		return true;
	});
	return { tree, commit, diff: encodeCar(commit.cid, blocks) };
}

export async function buildRepoDiff(input: { commit: RepoEntry; entries: [string, RepoEntry][]; previousEntries: [string, RepoEntry][]; operations: RepoOperation[] }) {
	const tree = await buildMst(input.entries.map(([key, record]) => ({ key, value: record.cid })));
	return diff(input.commit, tree, input.entries, input.previousEntries, input.operations);
}

export async function buildRepoCommit(input: {
	did: string;
	rev: string;
	privateKey: Uint8Array;
	entries: [string, RepoEntry][];
	previousEntries?: [string, RepoEntry][];
	operations?: RepoOperation[];
}) {
	const tree = await buildMst(input.entries.map(([key, record]) => ({ key, value: record.cid })));
	const commit = await createCommit({ did: input.did, version: 3, data: tree.root, rev: input.rev, prev: null }, input.privateKey);
	return input.previousEntries ? diff(commit, tree, input.entries, input.previousEntries, input.operations ?? []) : { tree, commit, diff: encodeCar(commit.cid, [commit, ...tree.blocks, ...input.entries.map(([, record]) => record)]) };
}
