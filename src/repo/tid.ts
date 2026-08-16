const ALPHABET = "234567abcdefghijklmnopqrstuvwxyz";
export const TID_PATTERN = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/;

export function formatTid(value: bigint): string {
	if (value < 0n || value >= 1n << 63n) throw new RangeError("TID must be a positive 63-bit integer");
	let output = "";
	for (let i = 0; i < 13; i++) {
		output = ALPHABET[Number(value & 31n)] + output;
		value >>= 5n;
	}
	return output;
}

export function parseTid(tid: string): bigint {
	if (!TID_PATTERN.test(tid)) throw new TypeError("Invalid TID");
	let value = 0n;
	for (const character of tid) value = (value << 5n) | BigInt(ALPHABET.indexOf(character));
	return value;
}

export class TidClock {
	#last = -1n;
	constructor(private readonly clockId = crypto.getRandomValues(new Uint16Array(1))[0] & 1023) {}

	next(now = Date.now(), previous?: string): string {
		const wall = (BigInt(now) * 1000n << 10n) | BigInt(this.clockId);
		const persisted = previous === undefined ? -1n : parseTid(previous) + 1024n;
		this.#last = [wall, this.#last + 1024n, persisted].reduce((highest, value) => value > highest ? value : highest);
		return formatTid(this.#last);
	}
}
