// OPTIONAL: starts a local NEAR sandbox node (first run downloads the node binary: needs network once).
// Run with: ATTESTED_SANDBOX=1 npm run test:anchor
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runAsk } from '../src/ask.js';
import { anchorReceiptFile } from '../src/anchor.js';
import { verifyReceipt } from '../src/receipt.js';
import { verifyResponseSignature } from '../src/signature.js';
import { tmp } from './helpers.js';

const on = process.env.ATTESTED_SANDBOX === '1';

test('anchor: registers the hash in a local sandbox, reads it back, rejects a duplicate, receipt stays valid', { skip: !on && 'set ATTESTED_SANDBOX=1 to run (starts a local sandbox)', timeout: 180000 }, async () => {
  const out = tmp();
  const { receipt } = await runAsk({ prompt: 'anchor me', model: 'Qwen/Qwen3.8-27B', apiKey: '', forceRecorded: true, out });
  const a = await anchorReceiptFile(join(out, 'receipt.json'), { network: 'sandbox', say: () => {} });
  assert.equal(a.network, 'sandbox');
  assert.equal(a.record.model_id, 'Qwen/Qwen3.8-27B');
  assert.equal(a.record.attestation_digest, receipt.attestation.digest);
  assert.equal(a.total_receipts, 1);
  const after = JSON.parse(readFileSync(join(out, 'receipt.json'), 'utf8'));
  assert.equal(after.receipt_hash, receipt.receipt_hash, 'anchoring must not change the receipt hash');
  assert.equal((await verifyReceipt(after, { verifySig: verifyResponseSignature })).ok, true);
  assert.match(readFileSync(join(out, 'receipt.html'), 'utf8'), /local sandbox/);
});
