// OPTIONAL network test: ATTESTED_LIVE=1 npm run test:live  (no API key needed)
import test from 'node:test';
import assert from 'node:assert/strict';
import { gatherLive, runChecks } from '../src/flows.js';
import { STATUS } from '../src/util.js';

const live = process.env.ATTESTED_LIVE === '1';

test('live: fresh attestation + NVIDIA verdict verify with no FAILED check', { skip: !live && 'set ATTESTED_LIVE=1 to run (needs network)' }, async () => {
  const g = await gatherLive({ log: () => {} });
  assert.equal(g.nrasError, null);
  const r = await runChecks(g);
  const failed = r.checks.filter((c) => c.status === STATUS.FAILED);
  assert.deepEqual(failed, []);
  assert.equal(r.checks.find((c) => c.id === 'nonce.fresh').status, STATUS.VERIFIED);
  assert.equal(r.checks.find((c) => c.id === 'tdx.report_data.model').status, STATUS.VERIFIED);
});
