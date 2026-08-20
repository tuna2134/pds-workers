import { cidForBytes } from "../repo/cid";
import { readBody } from "../utils/body";
import { sha256 } from "@noble/hashes/sha2.js";
import { CID } from "multiformats/cid";
import * as digest from "multiformats/hashes/digest";

const RAW_CODEC = 0x55;
const MIME = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

export class BlobStorage {
	constructor(private readonly bucket: R2Bucket, private readonly maximumSize: number, private readonly cleanup?: Queue) {}

	async upload(did: string, request: Request) {
		const declared = request.headers.get("content-length");
		const length = declared === null ? undefined : Number(declared);
		if (length !== undefined && (!Number.isSafeInteger(length) || length < 0)) throw new TypeError("Invalid Content-Length");
		if (length !== undefined && length > this.maximumSize) throw new RangeError("Blob exceeds upload limit");
		const mimeType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
		if (!mimeType || !MIME.test(mimeType)) throw new TypeError("A valid Content-Type is required");
		if (length !== undefined && request.body) return this.#uploadStream(did, request.body, length, mimeType);
		const bytes = await readBody(request, Math.min(this.maximumSize, 50_000_000));
		const cid = await cidForBytes(bytes, RAW_CODEC);
		const key = `blobs/${did}/${cid}`;
		await this.bucket.put(key, bytes, { httpMetadata: { contentType: mimeType }, customMetadata: { uploadedAt: new Date().toISOString() } });
		try { await this.cleanup?.send({ did, cid: cid.toString() }, { delaySeconds: 86_400 }); }
		catch (error) { await this.bucket.delete(key); throw error; }
		return { $type: "blob", ref: { $link: cid.toString() }, mimeType, size: bytes.length };
	}

	async #uploadStream(did: string, body: ReadableStream<Uint8Array>, length: number, mimeType: string) {
		const temporary = `blobs/${did}/upload-${crypto.randomUUID()}`;
		const fixed = new FixedLengthStream(length);
		const writer = fixed.writable.getWriter();
		const reader = body.getReader();
		const hash = sha256.create();
		let size = 0;
		const upload = this.bucket.put(temporary, fixed.readable, { httpMetadata: { contentType: mimeType } });
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				size += value.length;
				if (size > length) throw new TypeError("Content-Length does not match body");
				hash.update(value);
				await writer.write(value);
			}
			if (size !== length) throw new TypeError("Content-Length does not match body");
			await writer.close();
			await upload;
			const cid = CID.createV1(RAW_CODEC, digest.create(0x12, hash.digest()));
			const object = await this.bucket.get(temporary);
			if (!object) throw new Error("Temporary blob upload is unavailable");
			const key = `blobs/${did}/${cid}`;
			await this.bucket.put(key, object.body, { httpMetadata: { contentType: mimeType }, customMetadata: { uploadedAt: new Date().toISOString() } });
			try { await this.cleanup?.send({ did, cid: cid.toString() }, { delaySeconds: 86_400 }); }
			catch (error) { await this.bucket.delete(key); throw error; }
			return { $type: "blob", ref: { $link: cid.toString() }, mimeType, size };
		} catch (error) {
			await writer.abort(error).catch(() => undefined);
			await upload.catch(() => undefined);
			throw error;
		} finally {
			reader.releaseLock();
			await this.bucket.delete(temporary);
		}
	}

	get(did: string, cid: string) { return this.bucket.get(`blobs/${did}/${cid}`); }

	async deleteAccount(did: string) {
		let cursor: string | undefined;
		do {
			const page = await this.bucket.list({ prefix: `blobs/${did}/`, cursor });
			if (page.objects.length) await this.bucket.delete(page.objects.map(({ key }) => key));
			cursor = page.truncated ? page.cursor : undefined;
		} while (cursor);
	}
}
