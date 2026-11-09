import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runAsk } from '../src/ask.js';
import { verifyReceipt } from '../src/receipt.js';
import { verifyResponseSignature } from '../src/signature.js';
import { STATUS } from '../src/util.js';
import { tmp } from './helpers.js';

async function makeReceipt() {
  const out = tmp();
  const { receipt, paths } = await runAsk({ prompt: 'Review this fictional contract.', system: 'You are a reviewer.', model: 'Qwen/Qwen3.8-27B', apiKey: '', forceRecorded: true, scenario: 'test', out });
  return { receipt, paths, out };
}
const verify = (r) => verifyReceipt(r, { verifySig: verifyResponseSignature });

test('recorded ask: receipt has the required fields and honest labels', async () => {
  const { receipt } = await makeReceipt();
  assert.equal(receipt.schema, 'attested.receipt/v1');
  assert.equal(receipt.mode, 'recorded');
  assert.equal(receipt.model.id, 'Qwen/Qwen3.8-27B');
  assert.equal(receipt.model.tier, 'Confidential TEE');
  assert.match(receipt.nonce, /^[0-9a-f]{64}$/);
  for (const h of [receipt.request.sha256, receipt.response.sha256, receipt.attestation.digest, receipt.receipt_hash]) assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(receipt.response.source, 'recorded-fixture');
  assert.equal(receipt.response_signature, null);
  assert.ok(receipt.tool.version && receipt.created_at);
  const sig = receipt.checks.find((c) => c.id === 'response.signature');
  assert.equal(sig.status, STATUS.NOT_RUN, 'a canned answer must never be shown as signature-verified');
  assert.ok(receipt.checks.every((c) => Object.values(STATUS).includes(c.status)));
  assert.equal(receipt.totals.failed, 0);
});

test('verify-receipt accepts an untouched receipt', async () => {
  const { receipt } = await makeReceipt();
  const v = await verify(receipt);
  assert.equal(v.ok, true, JSON.stringify(v.results.filter((r) => r.status === 'FAILED')));
});

test('verify-receipt works after a JSON round trip through disk', async () => {
  const { paths } = await makeReceipt();
  const v = await verify(JSON.parse(readFileSync(paths.jsonPath, 'utf8')));
  assert.equal(v.ok, true);
});

test('the anchor field is not covered by the receipt hash, everything else is', async () => {
  const { receipt } = await makeReceipt();
  const withAnchor = { ...receipt, anchor: { network: 'sandbox', contract: 'x' } };
  assert.equal((await verify(withAnchor)).ok, true);
});

const mutations = {
  'model id changed': (r) => { r.model.id = 'Pwen/Qwen3.8-27B'; },
  'nonce changed': (r) => { r.nonce = r.nonce.replace(/^./, (c) => (c === 'a' ? 'b' : 'a')); },
  'request hash changed': (r) => { r.request.sha256 = '0'.repeat(64); },
  'response hash changed': (r) => { r.response.sha256 = '1'.repeat(64); },
  'receipt hash changed': (r) => { r.receipt_hash = '2'.repeat(64); },
  'attestation digest changed': (r) => { r.attestation.digest = '3'.repeat(64); },
  'a check flipped to VERIFIED': (r) => { r.checks.find((c) => c.id === 'tdx.collateral').status = 'VERIFIED'; },
  'a check removed': (r) => { r.checks.pop(); },
  'totals edited': (r) => { r.totals.verified += 1; },
  'quote byte flipped': (r) => { const q = r.attestation.evidence.report.model.intel_quote; r.attestation.evidence.report.model.intel_quote = q.slice(0, 700) + (q[700] === '0' ? '1' : '0') + q.slice(701); },
  'NVIDIA token altered': (r) => { const t = r.attestation.evidence.nras.response[0][1]; r.attestation.evidence.nras.response[0][1] = t.slice(0, 200) + (t[200] === 'A' ? 'B' : 'A') + t.slice(201); },
  'exchange: answer text edited': (r) => { r.exchange.response_body = r.exchange.response_body.replace('Liability', 'Liabilitx'); },
  'exchange: request text edited': (r) => { r.exchange.request_body += ' '; },
  'schema changed': (r) => { r.schema = 'attested.receipt/v2'; },
  'evidence removed': (r) => { delete r.attestation.evidence; },
  'a fake signature added': (r) => { r.response_signature = { text: 'a:b', signature: '0x00', signing_address: '0x00', signing_algo: 'ecdsa' }; },
};
for (const [name, mutate] of Object.entries(mutations)) {
  test(`tamper detected: ${name}`, async () => {
    const { receipt } = await makeReceipt();
    const t = structuredClone(receipt);
    mutate(t);
    const v = await verify(t);
    assert.equal(v.ok, false, name);
  });
}

test('byte-flip sweep over receipt.json: every flipped non-whitespace byte is rejected', async () => {
  const { paths } = await makeReceipt();
  const original = readFileSync(paths.jsonPath);
  const step = Math.floor(original.length / 140);
  let flips = 0;
  for (let i = 0; i < original.length; i += step) {
    const b = original[i];
    if ([0x20, 0x0a, 0x0d, 0x09].includes(b)) continue; // insignificant JSON whitespace
    const copy = Buffer.from(original);
    copy[i] = b ^ 0x01;
    let ok;
    try {
      const parsed = JSON.parse(copy.toString('utf8'));
      ok = (await verify(parsed)).ok;
    } catch {
      ok = false; // no longer JSON: rejected
    }
    assert.equal(ok, false, `flip at byte ${i} (${String.fromCharCode(b)}) was not detected`);
    flips++;
  }
  assert.ok(flips > 100);
});

test('verify-receipt without exchange text reports NOT-RUN for text hashes, still ok', async () => {
  const { receipt } = await makeReceipt();
  const t = structuredClone(receipt);
  delete t.exchange;
  const v = await verify(t);
  assert.equal(v.ok, true);
  assert.equal(v.results.find((r) => r.id === 'exchange.hashes').status, STATUS.NOT_RUN);
});

test('Proof Card html is self-contained and states recorded mode', async () => {
  const { paths } = await makeReceipt();
  const html = readFileSync(paths.htmlPath, 'utf8');
  assert.match(html, /canned fixture/);
  assert.match(html, /Recorded/);
  assert.ok(!/<link[^>]+href=["']https?:/.test(html) && !/<script[^>]+src=/.test(html), 'no external resources');
  assert.ok(!/src=["']https?:/.test(html));
  assert.match(html, /id="receipt-data"/);
  assert.match(html, /Re-check in this page/);
  assert.ok(join(paths.jsonPath).endsWith('receipt.json'));
});

test('a live-mode receipt: freshness of the nonce is only a creator claim for a third party', async () => {
  const { receipt } = await makeReceipt();
  const live = structuredClone(receipt);
  live.attestation.source = { kind: 'live', url: 'x' };
  live.mode = 'live';
  live.checks.find((c) => c.id === 'nonce.fresh').status = 'VERIFIED';
  live.totals = { verified: live.totals.verified + 1, present_not_verified: live.totals.present_not_verified, failed: 0, not_run: live.totals.not_run - 1 };
  const { computeReceiptHash } = await import('../src/receipt.js');
  live.receipt_hash = await computeReceiptHash(live);
  const v = await verify(live);
  assert.equal(v.ok, true, JSON.stringify(v.results.filter((r) => r.status === 'FAILED')));
  assert.equal(v.results.find((r) => r.id === 'nonce.freshness').status, STATUS.PRESENT);
});
