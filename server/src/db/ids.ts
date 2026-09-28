import { randomBytes } from 'node:crypto';

let lastMs = -1;
let sequence = 0;

/**
 * RFC 9562 UUIDv7: a 48-bit Unix millisecond timestamp, then a 12-bit counter (rand_a) that
 * keeps ids created in the same millisecond strictly increasing, then 62 random bits. Ids sort
 * by creation order, which keyset pagination and the job queue's FIFO order rely on.
 */
export function uuidv7(now: number = Date.now()): string {
  let ms = now;
  if (ms <= lastMs) {
    ms = lastMs;
    sequence += 1;
    if (sequence > 0xfff) {
      ms += 1;
      sequence = 0;
    }
  } else {
    // Start in the lower half so a burst has room before the counter overflows.
    sequence = randomBytes(2).readUInt16BE(0) & 0x7ff;
  }
  lastMs = ms;
  const bytes = randomBytes(16);
  bytes.writeUIntBE(ms, 0, 6);
  bytes.writeUInt8(0x70 | (sequence >> 8), 6);
  bytes.writeUInt8(sequence & 0xff, 7);
  bytes.writeUInt8(0x80 | (bytes.readUInt8(8) & 0x3f), 8);
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function uuidv7Timestamp(id: string): number {
  return Number.parseInt(id.replaceAll('-', '').slice(0, 12), 16);
}
