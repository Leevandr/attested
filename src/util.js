// Small helpers shared by the CLI (Node) and the browser pages.
// No Node-only APIs here: only Uint8Array, TextEncoder and WebCrypto (globalThis.crypto.subtle).

const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8(s) {
  return enc.encode(s);
}
export function fromUtf8(b) {
  return dec.decode(b);
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex string expected');
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function base64ToBytes(b64) {
  const s = b64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function readU16LE(b, o) {
  return b[o] | (b[o + 1] << 8);
}
export function readU32LE(b, o) {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

async function digest(alg, data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await globalThis.crypto.subtle.digest(alg, bytes));
}
export const sha256 = (data) => digest('SHA-256', data);
export const sha384 = (data) => digest('SHA-384', data);
export async function sha256Hex(data) {
  return bytesToHex(await sha256(data));
}

// Canonical JSON: object keys sorted (by UTF-16 code unit), no whitespace, no undefined.
// Good enough for hashing our own receipts: every value we store is a string, boolean,
// null, integer or a plain nested array/object.
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalize(v === undefined ? null : v)).join(',') + ']';
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

export async function canonicalSha256(value) {
  return sha256Hex(canonicalize(value));
}

// Check labels used everywhere (CLI output, receipt.json, Proof Card, web page).
export const STATUS = Object.freeze({
  VERIFIED: 'VERIFIED',
  PRESENT: 'PRESENT-NOT-VERIFIED',
  FAILED: 'FAILED',
  NOT_RUN: 'NOT-RUN',
});

export function check(id, label, status, detail, extra = {}) {
  return { id, label, status, detail, ...extra };
}
