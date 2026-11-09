import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { canonicalize, hexToBytes, bytesToHex, sha256Hex } from '../src/util.js';
import { parseCertificate, pemBlocks } from '../src/der.js';
import { INTEL_SGX_ROOT_CA_PEM, INTEL_SGX_ROOT_CA_SHA256 } from '../src/trust.js';
import { parseQuote, verifyQuoteSignatures } from '../src/tdx.js';
import { fixtureEvidence } from './helpers.js';

test('canonicalize sorts keys and drops whitespace', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, { z: 'x', y: 2 }] }), '{"a":[true,null,{"y":2,"z":"x"}],"b":1}');
  assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}');
});

test('hex helpers and sha256', async () => {
  assert.equal(bytesToHex(hexToBytes('00ff10')), '00ff10');
  assert.throws(() => hexToBytes('abc'));
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('pinned Intel root: constant equals the SHA-256 of the pinned certificate', async () => {
  const [der] = pemBlocks(INTEL_SGX_ROOT_CA_PEM);
  assert.equal(await sha256Hex(der), INTEL_SGX_ROOT_CA_SHA256);
});

test('mini DER parser agrees with node:crypto X509Certificate on the quote chain', () => {
  const { evidence } = fixtureEvidence();
  const q = parseQuote(evidence.report.model.intel_quote);
  const certs = pemBlocks(q.pckChainPem);
  assert.equal(certs.length, 3);
  for (const der of certs) {
    const mine = parseCertificate(der);
    const ref = new X509Certificate(Buffer.from(der));
    assert.equal(mine.subjectCN, /CN=([^\n]+)/.exec(ref.subject)[1]);
    assert.equal(mine.issuerCN, /CN=([^\n]+)/.exec(ref.issuer)[1]);
    assert.equal(mine.notBefore.getTime(), new Date(ref.validFrom).getTime());
    assert.equal(mine.notAfter.getTime(), new Date(ref.validTo).getTime());
  }
});

test('real TDX quotes verify (gateway, model, compose-manager)', async () => {
  const { evidence, ctx } = fixtureEvidence();
  for (const hex of [evidence.report.gateway.intel_quote, evidence.report.model.intel_quote, evidence.report.model.compose_manager.quote]) {
    const r = await verifyQuoteSignatures(hex, { validAt: ctx.validAt });
    assert.equal(r.ok, true, JSON.stringify(r.steps.filter((s) => !s.ok)));
    assert.equal(r.steps.length, 6);
  }
});

test('quote tamper test: flipping any single signed byte region makes verification fail', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const hex = evidence.report.model.intel_quote;
  const bytes = hexToBytes(hex);
  // regions: header, TD body (mr_td, report_data), signature, attestation key, QE report, QE signature, cert chain text
  const offsets = [10, 48 + 136, 48 + 520, 48 + 560, 636 + 5, 636 + 70, 636 + 128 + 6 + 10, 636 + 128 + 6 + 384 + 5, 636 + 128 + 6 + 450 + 8 + 100];
  for (const off of offsets) {
    const t = Uint8Array.from(bytes);
    t[off] ^= 0x01;
    const r = await verifyQuoteSignatures(t, { validAt: ctx.validAt });
    assert.equal(r.ok, false, `flip at byte ${off} was not detected`);
  }
});

test('quote verification respects certificate validity at the attestation time', async () => {
  const { evidence } = fixtureEvidence();
  const hex = evidence.report.gateway.intel_quote;
  assert.equal((await verifyQuoteSignatures(hex, { validAt: new Date('2026-11-09T05:00:00Z') })).ok, true);
  assert.equal((await verifyQuoteSignatures(hex, { validAt: new Date('2026-01-01T00:00:00Z') })).ok, false, 'PCK leaf was issued in Nov 2026');
  assert.equal((await verifyQuoteSignatures(hex, { validAt: new Date('2034-01-01T00:00:00Z') })).ok, false, 'chain expired in 2033');
});

test('a different root certificate is rejected', async () => {
  const { evidence, ctx } = fixtureEvidence();
  // Use the NVIDIA-unrelated RSA intermediate as a fake "root": signature chain cannot verify
  const fake = `-----BEGIN CERTIFICATE-----\n${evidence.nras.jwk.x5c[1]}\n-----END CERTIFICATE-----\n`;
  const r = await verifyQuoteSignatures(evidence.report.model.intel_quote, { validAt: ctx.validAt, rootPem: fake });
  assert.equal(r.ok, false);
});

test('rejects non-v4 or non-TDX quotes cleanly', async () => {
  const r = await verifyQuoteSignatures('0300' + '00'.repeat(700), { validAt: new Date() });
  assert.equal(r.ok, false);
  assert.match(r.steps[0].detail, /version/);
});
