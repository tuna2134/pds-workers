import { cidForBytes } from "../repo/cid";
import { readBody } from "../utils/body";

const RAW_CODEC = 0x55;
const MIME = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

export class BlobStorage {
	constructor(private readonly bucket: R2Bucket, private readonly maximumSize: number, private readonly cleanup?: Queue) {}

	async upload(did: string, request: Request) {
		const declared = request.headers.get("content-length");
		if (declared && Number(declared) > this.maximumSize) throw new RangeError("Blob exceeds upload limit");
		const mimeType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
		if (!mimeType || !MIME.test(mimeType)) throw new TypeError("A valid Content-Type is required");
		const bytes = await readBody(request, this.maximumSize);
		const cid = await cidForBytes(bytes, RAW_CODEC);
		const key = `blobs/${did}/${cid}`;
		await this.bucket.put(key, bytes, { httpMetadata: { contentType: mimeType }, customMetadata: { uploadedAt: new Date().toISOString() } });
		try { await this.cleanup?.send({ did, cid: cid.toString() }, { delaySeconds: 86_400 }); }
		catch (error) { await this.bucket.delete(key); throw error; }
		return { $type: "blob", ref: { $link: cid.toString() }, mimeType, size: bytes.length };
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
