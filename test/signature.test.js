import test from 'node:test';
import assert from 'node:assert/strict';
import { addressOfSecretKey, personalMessageHash, recoverPersonalSigner, signPersonal } from '../src/eth.js';
import { verifyResponseSignature, resolveSignatureKind } from '../src/signature.js';
import { STATUS, bytesToHex, sha256Hex } from '../src/util.js';
import { fixtureEvidence } from './helpers.js';

// Synthetic test key: NOT a TEE key. These tests prove the verifier logic only.
const sk = new Uint8Array(32).fill(7);
const keyOne = new Uint8Array(32);
keyOne[31] = 1;

test('secp256k1 + keccak: private key 1 has the well-known Ethereum address', () => {
  assert.equal(addressOfSecretKey(keyOne), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
});

test('EIP-191 personal_sign: sign then recover returns the signer; other text recovers someone else', () => {
  const addr = addressOfSecretKey(sk);
  const sig = signPersonal('hello', sk);
  assert.equal(recoverPersonalSigner('hello', sig), addr);
  assert.notEqual(recoverPersonalSigner('hellp', sig), addr);
  assert.equal(bytesToHex(personalMessageHash('hello')).length, 64);
  // v as 0/1 is accepted as well as 27/28
  const raw = sig.slice(2, 130) + (parseInt(sig.slice(130), 16) - 27).toString(16).padStart(2, '0');
  assert.equal(recoverPersonalSigner('hello', '0x' + raw), addr);
  assert.throws(() => recoverPersonalSigner('hello', '0x1234'));
});

async function setup(kind = 'provider_tee') {
  const { evidence } = fixtureEvidence();
  const addr = addressOfSecretKey(sk);
  if (kind === 'provider_tee') evidence.report.model.signing_address = addr;
  else evidence.report.gateway.signing_address = addr;
  const model = 'Qwen/Qwen3.8-27B';
  const requestSha256 = await sha256Hex('{"req":1}');
  const responseSha256 = await sha256Hex('{"res":2}');
  const text = kind === 'provider_tee' ? `${model}:${requestSha256}:${responseSha256}` : `${requestSha256}:${responseSha256}`;
  const sig = { text, signature: signPersonal(text, sk), signing_address: addr, signing_algo: 'ecdsa', signature_kind: kind };
  return { model, requestSha256, responseSha256, sig, evidence, keyBound: { gateway: true, model: true } };
}

test('response signature: model TEE signature verifies when the key is attested', async () => {
  const a = await setup();
  const r = verifyResponseSignature(a);
  assert.equal(r.status, STATUS.VERIFIED, r.detail);
  assert.equal(r.signature_kind, 'provider_tee');
});

test('response signature: gateway signature verifies but is labelled as gateway, not model TEE', async () => {
  const a = await setup('gateway');
  const r = verifyResponseSignature(a);
  assert.equal(r.status, STATUS.VERIFIED, r.detail);
  assert.match(r.detail, /gateway TEE, not the model TEE/);
});

test('response signature: every kind of mismatch FAILS', async () => {
  const cases = {
    'unbound key': (a) => ({ ...a, keyBound: { gateway: false, model: false } }),
    'request hash': (a) => ({ ...a, requestSha256: 'ab'.repeat(32) }),
    'response hash': (a) => ({ ...a, responseSha256: 'cd'.repeat(32) }),
    'model id': (a) => ({ ...a, model: 'other/model' }),
    'attested key differs': (a) => { a.evidence.report.model.signing_address = '0x' + '22'.repeat(20); return a; },
    'text altered after signing': (a) => ({ ...a, sig: { ...a.sig, text: a.sig.text.replace(/.$/, '0') } }),
    'kind says gateway but text has model': (a) => ({ ...a, sig: { ...a.sig, signature_kind: 'gateway' } }),
    'garbage signature': (a) => ({ ...a, sig: { ...a.sig, signature: '0xdeadbeef' } }),
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const a = mutate(await setup());
    assert.equal(verifyResponseSignature(a).status, STATUS.FAILED, name);
  }
});

test('signature kind inference for older responses without signature_kind', () => {
  assert.equal(resolveSignatureKind({ text: 'a:b:c' }), 'provider_tee');
  assert.equal(resolveSignatureKind({ text: 'a:b' }), 'gateway');
});
