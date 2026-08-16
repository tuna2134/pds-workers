import { CID } from "multiformats/cid";
import type { AccountRepo } from "../durable/account-repo";
import { validDid } from "../identity/did";

export interface BlobCleanupMessage { did: string; cid: string }

export async function cleanupBlob(env: Env, message: BlobCleanupMessage): Promise<void> {
	if (!validDid(message.did) || CID.parse(message.cid).code !== 0x55) throw new TypeError("Invalid blob cleanup message");
	const repo = env.ACCOUNT_REPO.getByName(message.did) as unknown as AccountRepo;
	if (!await repo.isBlobReferenced(message.cid)) await env.BLOBS.delete(`blobs/${message.did}/${message.cid}`);
}
