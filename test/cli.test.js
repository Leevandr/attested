import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, tmp } from './helpers.js';

const BIN = join(ROOT, 'bin/attested.js');
// A clean environment: no key, no model override, no base URL, no colour.
const env = { PATH: process.env.PATH, HOME: process.env.HOME, NO_COLOR: '1', ...(process.env.NODE_OPTIONS ? { NODE_OPTIONS: process.env.NODE_OPTIONS } : {}) };
const run = (args, opts = {}) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...env, ...opts.env }, cwd: opts.cwd ?? ROOT, timeout: 120000 });

test('demo works from a clean environment (recorded, offline) and tells the truth', () => {
  const out = join(tmp(), 'demo');
  const r = run(['demo', '--out', out]);
  assert.equal(r.status, 0, r.stderr + r.stdout.slice(-800));
  for (const s of ['RECORDED', 'CANNED FIXTURE', 'verify-receipt: OK', 'Tamper test', 'INVALID', 'PRESENT-NOT-VERIFIED', 'NOT-RUN', 'VERIFIED']) assert.ok(r.stdout.includes(s), `missing "${s}"`);
  assert.ok(existsSync(join(out, 'receipt.json')) && existsSync(join(out, 'receipt.html')));
  assert.ok(!/LIVE: real/.test(r.stdout), 'recorded demo must not claim to be live');
});

test('verify-receipt exit codes: 0 intact, 1 tampered / not JSON, 2 usage', () => {
  const dir = tmp();
  const r = run(['ask', 'Review: fictional.', '--out', dir]);
  assert.equal(r.status, 0, r.stderr);
  const file = join(dir, 'receipt.json');
  assert.equal(run(['verify-receipt', file]).status, 0);
  const text = readFileSync(file, 'utf8');
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, text.replace('"Qwen/Qwen3.8-27B"', '"Pwen/Qwen3.8-27B"'));
  const t = run(['verify-receipt', bad]);
  assert.equal(t.status, 1);
  assert.match(t.stdout, /INVALID/);
  writeFileSync(bad, text.slice(0, 5000));
  assert.equal(run(['verify-receipt', bad]).status, 1);
  assert.equal(run(['verify-receipt']).status, 2);
  assert.equal(run(['verify-receipt', join(dir, 'missing.json')]).status, 1);
});

test('attest --recorded writes a receipt without request or response', () => {
  const dir = tmp();
  const r = run(['attest', '--recorded', '--out', dir]);
  assert.equal(r.status, 0, r.stderr);
  const receipt = JSON.parse(readFileSync(join(dir, 'receipt.json'), 'utf8'));
  assert.equal(receipt.request, null);
  assert.equal(receipt.response, null);
  assert.equal(receipt.mode, 'recorded');
  assert.equal(run(['verify-receipt', join(dir, 'receipt.json')]).status, 0);
});

test('recorded mode refuses to pretend it has an attestation for another model', () => {
  const r = run(['ask', 'hi', '--model', 'openai/gpt-5', '--out', tmp()]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /RECORDED mode only has a real attestation/);
});

test('mainnet is refused, unknown commands and no arguments behave', () => {
  const dir = tmp();
  run(['ask', 'x', '--out', dir]);
  const m = run(['anchor', join(dir, 'receipt.json'), '--network', 'mainnet']);
  assert.equal(m.status, 1);
  assert.match(m.stderr, /mainnet is not supported/);
  assert.equal(run(['frobnicate']).status, 2);
  assert.equal(run([]).status, 0);
});

test('a receipt that records FAILED checks is authentic but exits 3', () => {
  const dir = tmp();
  run(['ask', 'x', '--out', dir]);
  // Recorded evidence replayed with a wrong expected nonce cannot be produced through the CLI, so build one in-process.
  const r = spawnSync(process.execPath, ['-e', `
    import('${join(ROOT, 'src/ask.js').replace(/\\/g, '/')}').then(async (a) => {
      const f = await import('${join(ROOT, 'src/flows.js').replace(/\\/g, '/')}');
      const rc = await import('${join(ROOT, 'src/receipt.js').replace(/\\/g, '/')}');
      const g = await f.loadFixture();
      g.nonce = 'ab'.repeat(32);
      const r = await f.runChecks(g);
      const receipt = await rc.buildReceipt({ mode: 'recorded', model: g.model, tier: 'Confidential TEE', nonce: g.nonce, request: null, response: null, signature: null, gathered: g, attChecks: r.checks, summary: r.summary });
      await a.writeOutputs(receipt, '${dir.replace(/\\/g, '/')}/failed');
    });
  `], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const v = run(['verify-receipt', join(dir, 'failed/receipt.json')]);
  assert.equal(v.status, 3, v.stdout.slice(-600));
  assert.match(v.stdout, /AUTHENTIC, but it records/);
});
