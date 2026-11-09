// `attested demo`: the "confidential contract review" story, end to end.
//   npm run demo        recorded mode: no network, no key, no env vars
//   npm run demo:live   live attestation fetch (no key); a real answer too if NEAR_AI_API_KEY is set
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DEFAULT_MODEL } from './gateway.js';
import { runAsk } from './ask.js';
import { verifyReceipt } from './receipt.js';
import { verifyResponseSignature } from './signature.js';
import { STATUS } from './util.js';
import { bold, dim, heading, kv, modeBanner, renderChecks, renderTotals, statusTag, wrap } from './format.js';


const DIR = (f) => fileURLToPath(new URL(`../demo/contract-review/${f}`, import.meta.url));

export async function demoCommand({ flags }, { say }) {
  const live = !!flags.live;
  const apiKey = live ? process.env.NEAR_AI_API_KEY || '' : '';
  const out = resolve(flags.out || (live ? 'out/demo-live' : 'out/demo'));
  const doc = await readFile(DIR('services-agreement.txt'), 'utf8');
  const question = await readFile(DIR('question.txt'), 'utf8');

  say(bold('attested demo: confidential contract review') + dim(live ? '   [live]' : '   [recorded, offline]'));
  say(`
Mira is a freelance designer. A client sent her a draft agreement that contains her bank
details and terms she cannot share. She wants an AI review, but only from a model running
inside a hardware-sealed enclave, and she wants a receipt her lawyer can check without
trusting her or the AI company. (Everything in the document is fictional.)
`);
  say(heading('Step 1. Send the document to a Confidential TEE model'));
  say(kv([['document', `demo/contract-review/services-agreement.txt (${doc.length} characters, fictional)`], ['model', process.env.NEAR_AI_MODEL || DEFAULT_MODEL]]));

  const { receipt, paths, live: realAnswer } = await runAsk({
    prompt: doc,
    system: question,
    model: process.env.NEAR_AI_MODEL || DEFAULT_MODEL,
    apiKey,
    forceRecorded: !apiKey,
    liveAttestation: live,
    scenario: 'confidential-contract-review',
    out,
  });
  say(dim(modeBanner(receipt.mode, receipt.response.source)));
  if (!realAnswer) say(dim(live ? 'No NEAR_AI_API_KEY: the attestation below is fetched live, but the answer text is the canned fixture.' : 'Offline: the attestation is a real report recorded on ' + receipt.attestation.source.recorded_at.slice(0, 10) + '; the answer text is a canned fixture.'));

  say(heading(realAnswer ? 'Step 2. The answer (from the model, signed)' : 'Step 2. The answer (CANNED FIXTURE, not model output)'));
  const answer = JSON.parse(receipt.exchange.response_body).choices[0].message.content;
  say(wrap(answer, 92, '  '));

  say(heading('Step 3. What the receipt proves (every check labelled)'));
  say(renderChecks(receipt.checks));
  say('\n  ' + bold('Totals') + '  ' + renderTotals(receipt.totals));

  say(heading('Step 4. Her lawyer re-checks the receipt offline'));
  const v = await verifyReceipt(receipt, { verifySig: verifyResponseSignature });
  say(renderChecks(v.results));
  say('\n  ' + bold(v.ok ? 'verify-receipt: OK' : 'verify-receipt: INVALID'));

  say(heading('Step 5. Tamper test: change one character in the receipt'));
  const tampered = structuredClone(receipt);
  tampered.model.id = 'Pwen' + tampered.model.id.slice(4);
  const tv = await verifyReceipt(tampered, { verifySig: verifyResponseSignature });
  const failedIds = tv.results.filter((r) => r.status === STATUS.FAILED).map((r) => r.id);
  say(`  ${statusTag(tv.ok ? STATUS.VERIFIED : STATUS.FAILED)} model id "Qwen..." changed to "Pwen...": verify-receipt says ${tv.ok ? 'OK (BUG)' : 'INVALID'} (${failedIds.join(', ')})`);

  let anchored = null;
  if (flags.anchor) {
    say(heading('Step 6. Anchor the receipt hash on NEAR (local sandbox)'));
    const { anchorReceiptFile } = await import('./anchor.js');
    anchored = await anchorReceiptFile(join(out, 'receipt.json'), { network: 'sandbox', say });
  }

  say(heading('Files'));
  say(kv([['receipt.json', paths.jsonPath], ['Proof Card', pathToFileURL(paths.htmlPath).href], ['receipt hash', receipt.receipt_hash]]));
  say(dim('\nOpen the Proof Card in a browser. It works offline and can re-check itself.'));
  return v.ok && !tv.ok && receipt.totals.failed === 0 ? 0 : 1;
}
