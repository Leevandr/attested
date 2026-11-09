import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { bundleCore, MODULES } from '../scripts/bundle.js';
import { buildIndexHtml } from '../scripts/build-web.js';
import { verifyReceipt } from '../src/receipt.js';
import { verifyResponseSignature } from '../src/signature.js';
import { renderCard } from '../src/cardview.js';
import { ROOT } from './helpers.js';

const sample = () => JSON.parse(readFileSync(join(ROOT, 'web/sample-receipt.json'), 'utf8'));

function loadBrowserCore() {
  // Evaluate the exact bundle that ships in the HTML, with only `window` and WebCrypto available.
  const sandbox = { window: {}, crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, Date, JSON, Uint8Array, Promise };
  vm.createContext(sandbox);
  vm.runInContext(bundleCore(), sandbox);
  return sandbox.window.AttestedCore;
}

test('the browser bundle declares no duplicate names and exposes the API', () => {
  const core = loadBrowserCore();
  for (const k of ['verifyReceipt', 'renderCard', 'verifyEvidence', 'STATUS']) assert.ok(core[k], k);
  assert.ok(MODULES.every((m) => existsSync(join(ROOT, 'src', m))));
});

test('browser bundle and Node give the same verdict on the sample receipt, and both reject a tampered one', async () => {
  const core = loadBrowserCore();
  const node = await verifyReceipt(sample(), { verifySig: verifyResponseSignature });
  const browser = await core.verifyReceipt(sample(), { verifySig: null });
  assert.equal(browser.ok, true);
  assert.equal(JSON.stringify(browser.results.map((r) => [r.id, r.status])), JSON.stringify(node.results.map((r) => [r.id, r.status])));
  const bad = sample();
  bad.model.id = 'Pwen/Qwen3.8-27B';
  assert.equal((await core.verifyReceipt(bad, { verifySig: null })).ok, false);
  const bad2 = sample();
  const q = bad2.attestation.evidence.report.model.intel_quote;
  bad2.attestation.evidence.report.model.intel_quote = q.slice(0, 800) + (q[800] === '0' ? '1' : '0') + q.slice(801);
  assert.equal((await core.verifyReceipt(bad2, { verifySig: null })).ok, false);
});

test('Proof Card markup escapes untrusted receipt content', () => {
  const r = sample();
  r.model.id = '<img src=x onerror=alert(1)>';
  r.summary.model_name = '"><script>alert(2)</script>';
  r.exchange.response_body = '<script>alert(3)</script>';
  const html = renderCard(r);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<script>alert'));
  assert.ok(html.includes('&lt;img src=x'));
});

test('web/index.html is up to date with its sources (run: npm run build:web)', () => {
  assert.equal(readFileSync(join(ROOT, 'web/index.html'), 'utf8'), buildIndexHtml());
});

test('the sample receipt verifies and is the recorded demo', () => {
  const s = sample();
  assert.equal(s.mode, 'recorded');
  assert.equal(s.scenario, 'confidential-contract-review');
});

test('committed contract wasm matches its recorded sha256', () => {
  const wasm = readFileSync(join(ROOT, 'contract/artifacts/receipt_registry.wasm'));
  const want = readFileSync(join(ROOT, 'contract/artifacts/receipt_registry.wasm.sha256'), 'utf8').trim().split(/\s+/)[0];
  assert.equal(createHash('sha256').update(wasm).digest('hex'), want);
});

test('package.json version equals the tool version in receipts', async () => {
  const { TOOL_VERSION } = await import('../src/version.js');
  assert.equal(JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version, TOOL_VERSION);
});
