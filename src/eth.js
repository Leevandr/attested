// Ethereum-style "personal_sign" (EIP-191) signature recovery, used by NEAR AI Cloud for
// response signatures with signing_algo "ecdsa". Node only (uses @noble, pinned in package.json).

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8 } from './util.js';

export function personalMessageHash(text) {
  const msg = utf8(text);
  const prefix = utf8('\x19Ethereum Signed Message:\n' + msg.length);
  const all = new Uint8Array(prefix.length + msg.length);
  all.set(prefix, 0);
  all.set(msg, prefix.length);
  return keccak_256(all);
}

export function addressFromPublicKey(uncompressed65) {
  return '0x' + bytesToHex(keccak_256(uncompressed65.subarray(1)).subarray(12));
}

// Returns the lowercase 0x address that signed `text`, or throws on a malformed signature.
export function recoverPersonalSigner(text, signatureHex) {
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 65) throw new Error('signature must be 65 bytes (r || s || v)');
  let v = sig[64];
  if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) throw new Error('bad recovery id');
  const point = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(v).recoverPublicKey(personalMessageHash(text));
  return addressFromPublicKey(point.toBytes(false));
}

// Used by the local mock gateway in tests and by the synthetic test vectors.
export function signPersonal(text, secretKey) {
  const rec = secp256k1.sign(personalMessageHash(text), secretKey, { prehash: false, format: 'recovered' });
  // noble returns recovery || r || s; Ethereum wants r || s || (27 + recovery)
  const out = new Uint8Array(65);
  out.set(rec.subarray(1), 0);
  out[64] = 27 + rec[0];
  return '0x' + bytesToHex(out);
}

export function addressOfSecretKey(secretKey) {
  return addressFromPublicKey(secp256k1.getPublicKey(secretKey, false));
}
