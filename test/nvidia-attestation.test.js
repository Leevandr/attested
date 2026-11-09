import test from 'node:test';
import assert from 'node:assert/strict';
import { STATUS } from '../src/util.js';
import { verifyNras } from '../src/nvidia.js';
import { verifyEvidence, tallyChecks } from '../src/attestation.js';
import { byId, fixtureEvidence } from './helpers.js';

const status = (checks) => Object.fromEntries(checks.map((c) => [c.id, c.status]));

test('NRAS verdict on the recorded fixture verifies (signature, chain, claims, 8 GPUs)', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const r = await verifyNras({ nras: evidence.nras.response, jwk: evidence.nras.jwk, nonce: ctx.nonce, validAt: ctx.validAt });
  assert.deepEqual(status(r.checks), { 'nras.signature': 'VERIFIED', 'nras.chain': 'VERIFIED', 'nras.claims': 'VERIFIED', 'nras.gpus': 'VERIFIED' });
  assert.equal(r.info.gpuCount, 8);
  assert.equal(r.info.hwmodel, 'GH100');
});

test('NRAS: wrong nonce, late validity, and a tampered token are all caught', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const wrongNonce = await verifyNras({ nras: evidence.nras.response, jwk: evidence.nras.jwk, nonce: 'ab'.repeat(32), validAt: ctx.validAt });
  assert.equal(byId(wrongNonce.checks, 'nras.claims').status, STATUS.FAILED);
  const late = await verifyNras({ nras: evidence.nras.response, jwk: evidence.nras.jwk, nonce: ctx.nonce, validAt: new Date(ctx.validAt.getTime() + 3 * 86400e3) });
  assert.equal(byId(late.checks, 'nras.chain').status, STATUS.FAILED);
  // flip a character inside the payload of the overall token
  const resp = structuredClone(evidence.nras.response);
  const [h, p, s] = resp[0][1].split('.');
  const flipped = p.slice(0, 40) + (p[40] === 'A' ? 'B' : 'A') + p.slice(41);
  resp[0][1] = [h, flipped, s].join('.');
  const bad = await verifyNras({ nras: resp, jwk: evidence.nras.jwk, nonce: ctx.nonce, validAt: ctx.validAt });
  assert.equal(byId(bad.checks, 'nras.signature')?.status ?? STATUS.FAILED, STATUS.FAILED);
  assert.ok(bad.checks.some((c) => c.status === STATUS.FAILED));
  // a GPU token swapped for another one no longer matches the digest in the overall token
  const resp2 = structuredClone(evidence.nras.response);
  resp2[1]['GPU-0'] = resp2[1]['GPU-1'];
  const bad2 = await verifyNras({ nras: resp2, jwk: evidence.nras.jwk, nonce: ctx.nonce, validAt: ctx.validAt });
  assert.equal(byId(bad2.checks, 'nras.gpus').status, STATUS.FAILED);
});

test('NRAS: a wrong intermediate certificate never yields VERIFIED', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const jwk = structuredClone(evidence.nras.jwk);
  jwk.x5c[1] = jwk.x5c[0];
  const r = await verifyNras({ nras: evidence.nras.response, jwk, nonce: ctx.nonce, validAt: ctx.validAt });
  assert.notEqual(byId(r.checks, 'nras.chain').status, STATUS.VERIFIED);
});

test('recorded fixture: every attestation check has the expected status', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const r = await verifyEvidence(evidence, ctx);
  const s = status(r.checks);
  const expectVerified = ['nonce.echo', 'tdx.quote.gateway', 'tdx.report_data.gateway', 'tdx.debug.gateway', 'tdx.rtmr.gateway', 'tdx.compose.gateway', 'tdx.quote.model', 'tdx.report_data.model', 'tdx.debug.model', 'tdx.rtmr.model', 'tdx.compose.model', 'compose_manager', 'nvidia.nonce', 'nras.signature', 'nras.chain', 'nras.claims', 'nras.gpus'];
  for (const id of expectVerified) assert.equal(s[id], 'VERIFIED', id);
  assert.equal(s['nonce.fresh'], 'NOT-RUN');
  assert.equal(s['model.name'], 'PRESENT-NOT-VERIFIED');
  assert.equal(s['tdx.collateral'], 'PRESENT-NOT-VERIFIED');
  assert.deepEqual(tallyChecks(r.checks), { verified: 17, present_not_verified: 2, failed: 0, not_run: 1 });
  assert.equal(r.summary.compose_up.file, 'prod/small-models.yaml');
  assert.equal(r.summary.model_images.length, 4);
  assert.ok(r.summary.model_images.every((i) => /^[a-z0-9].*@sha256:[0-9a-f]{64}$/.test(i)));
});

test('live mode would mark the nonce as fresh', async () => {
  const { evidence, ctx } = fixtureEvidence();
  const r = await verifyEvidence(evidence, { ...ctx, mode: 'live', enforceNrasExpiry: false });
  assert.equal(byId(r.checks, 'nonce.fresh').status, STATUS.VERIFIED);
});

const tamperCases = [
  ['replayed report: a different nonce is expected', (e, c) => ({ evidence: e, ctx: { ...c, nonce: 'cd'.repeat(32) } }), ['nonce.echo', 'tdx.report_data.model', 'tdx.report_data.gateway', 'nvidia.nonce', 'compose_manager']],
  ['signing key swapped in the report', (e) => { e.report.model.signing_address = '0x' + '11'.repeat(20); return { evidence: e }; }, ['tdx.report_data.model']],
  ['boot event log altered', (e) => { e.report.model.tcb.event_log[12].digest = '00'.repeat(48); return { evidence: e }; }, ['tdx.rtmr.model']],
  ['compose manifest altered', (e) => { e.report.model.tcb.app_compose += ' '; return { evidence: e }; }, ['tdx.compose.model']],
  ['compose-manager action log altered', (e) => { e.report.model.compose_manager.actions[0].image = 'evil'; return { evidence: e }; }, ['compose_manager']],
  ['quote body altered', (e) => { const q = e.report.model.intel_quote; e.report.model.intel_quote = q.slice(0, 300) + (q[300] === '0' ? '1' : '0') + q.slice(301); return { evidence: e }; }, ['tdx.quote.model']],
  ['GPU payload nonce differs', (e) => { e.report.model.nvidia.nonce = 'ef'.repeat(32); return { evidence: e }; }, ['nvidia.nonce']],
  ['model name differs', (e, c) => ({ evidence: e, ctx: { ...c, model: 'other/model' } }), ['model.name']],
];
for (const [name, mutate, expectFailed] of tamperCases) {
  test(`tamper: ${name}`, async () => {
    const { evidence, ctx } = fixtureEvidence();
    const m = mutate(evidence, ctx);
    const r = await verifyEvidence(m.evidence, m.ctx ?? ctx);
    const failed = r.checks.filter((c) => c.status === STATUS.FAILED).map((c) => c.id);
    for (const id of expectFailed) assert.ok(failed.includes(id), `${id} should FAIL, failed: ${failed.join(',')}`);
  });
}
