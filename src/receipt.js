// Receipt build + OFFLINE verification. Isomorphic (WebCrypto only), except that the
// optional response-signature re-check is injected by the caller (Node only).

import { verifyEvidence, tallyChecks } from './attestation.js';
import { RECEIPT_SCHEMA, TOOL_NAME, TOOL_VERSION } from './version.js';
import { STATUS, canonicalSha256, check, sha256Hex, utf8 } from './util.js';

const HEX64 = /^[0-9a-f]{64}$/;

export async function computeReceiptHash(receipt) {
  const { receipt_hash: _h, exchange: _e, anchor: _a, ...body } = receipt;
  return canonicalSha256(body);
}

export async function computeAttestationDigest(evidence) {
  return canonicalSha256(evidence);
}

// `request` / `response`: { body, source } or null (attestation-only receipts).
export async function buildReceipt({ createdAt = new Date(), mode, scenario = null, model, tier, nonce, request, response, signature, gathered, attChecks, signatureCheckResult, summary, notes = [] }) {
  const checks = [...attChecks];
  if (signatureCheckResult) checks.push(signatureCheckResult);
  const receipt = {
    schema: RECEIPT_SCHEMA,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    created_at: createdAt.toISOString(),
    mode,
    scenario,
    model: { id: model, tier },
    nonce,
    request: request ? { sha256: await sha256Hex(request.body), bytes: utf8(request.body).length } : null,
    response: response ? { sha256: await sha256Hex(response.body), bytes: utf8(response.body).length, source: response.source, chat_id: response.chat_id ?? null } : null,
    response_signature: signature ?? null,
    attestation: {
      source: gathered.source,
      fetched_at: gathered.fetchedAt.toISOString(),
      digest: await computeAttestationDigest(gathered.evidence),
      evidence: gathered.evidence,
    },
    checks,
    summary,
    totals: tallyChecks(checks),
    notes,
  };
  receipt.receipt_hash = await computeReceiptHash(receipt);
  if (request || response) receipt.exchange = { request_body: request?.body ?? null, response_body: response?.body ?? null };
  return receipt;
}

function isObj(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

// Fully offline re-check. `verifySig(...)` (optional) re-checks the response signature.
// Returns { ok, results: [...checks about the receipt itself], claimed: receipt.checks, rederived }.
export async function verifyReceipt(receipt, { exchange = null, verifySig = null } = {}) {
  const results = [];
  const add = (id, label, ok, detail) => results.push(check(id, label, ok ? STATUS.VERIFIED : STATUS.FAILED, detail));

  // 1. structure
  const problems = [];
  if (!isObj(receipt)) problems.push('receipt is not a JSON object');
  else {
    if (receipt.schema !== RECEIPT_SCHEMA) problems.push(`schema is "${receipt.schema}", expected "${RECEIPT_SCHEMA}"`);
    if (!isObj(receipt.tool) || typeof receipt.tool.version !== 'string') problems.push('tool.version missing');
    if (typeof receipt.created_at !== 'string' || Number.isNaN(Date.parse(receipt.created_at))) problems.push('created_at is not a date');
    if (!isObj(receipt.model) || typeof receipt.model.id !== 'string' || !receipt.model.id) problems.push('model.id missing');
    if (typeof receipt.nonce !== 'string' || !HEX64.test(receipt.nonce)) problems.push('nonce must be 64 lowercase hex characters');
    if (receipt.request !== null && !(isObj(receipt.request) && HEX64.test(receipt.request.sha256 ?? ''))) problems.push('request.sha256 invalid');
    if (receipt.response !== null && !(isObj(receipt.response) && HEX64.test(receipt.response.sha256 ?? ''))) problems.push('response.sha256 invalid');
    if (!isObj(receipt.attestation) || !HEX64.test(receipt.attestation.digest ?? '') || !isObj(receipt.attestation.evidence)) problems.push('attestation.digest or attestation.evidence missing');
    if (!isObj(receipt.attestation) || Number.isNaN(Date.parse(receipt.attestation?.fetched_at))) problems.push('attestation.fetched_at is not a date');
    if (!Array.isArray(receipt.checks) || receipt.checks.some((c) => !c || typeof c.id !== 'string' || !Object.values(STATUS).includes(c.status))) problems.push('checks list malformed');
    if (typeof receipt.receipt_hash !== 'string' || !HEX64.test(receipt.receipt_hash)) problems.push('receipt_hash invalid');
  }
  add('receipt.structure', 'receipt has the expected structure and fields', problems.length === 0, problems.length ? problems.join('; ') : `schema ${RECEIPT_SCHEMA}, tool version ${receipt.tool.version}`);
  if (problems.length) return finish(results, receipt, null);

  // 2. receipt hash
  const rh = await computeReceiptHash(receipt);
  add('receipt.hash', 'receipt_hash equals SHA-256 of the canonical receipt body', rh === receipt.receipt_hash, rh === receipt.receipt_hash ? `recomputed ${rh}` : `recomputed ${rh} but receipt says ${receipt.receipt_hash}`);

  // 3. attestation digest
  const ad = await computeAttestationDigest(receipt.attestation.evidence);
  add('attestation.digest', 'attestation.digest equals SHA-256 of the stored evidence', ad === receipt.attestation.digest, ad === receipt.attestation.digest ? `recomputed ${ad}` : `recomputed ${ad} but receipt says ${receipt.attestation.digest}`);

  // 4. exchange (request/response bytes)
  const ex = exchange ?? receipt.exchange ?? null;
  if (receipt.request || receipt.response) {
    if (!ex) {
      results.push(check('exchange.hashes', 'request/response text re-hashes to the receipt', STATUS.NOT_RUN, 'no exchange text supplied (receipt was shared without content); only the hashes can be compared to something you hold'));
    } else {
      const probs = [];
      if (receipt.request) {
        const h = typeof ex.request_body === 'string' ? await sha256Hex(ex.request_body) : null;
        if (h !== receipt.request.sha256) probs.push('request text does not hash to request.sha256');
      }
      if (receipt.response) {
        const h = typeof ex.response_body === 'string' ? await sha256Hex(ex.response_body) : null;
        if (h !== receipt.response.sha256) probs.push('response text does not hash to response.sha256');
      }
      add('exchange.hashes', 'request/response text re-hashes to the receipt', probs.length === 0, probs.length ? probs.join('; ') : 'both texts hash to the values stored in the receipt');
    }
  }

  // 5. re-derive attestation checks from the stored evidence
  const recorded = new Map(receipt.checks.map((c) => [c.id, c.status]));
  let rederived = null;
  try {
    rederived = await verifyEvidence(receipt.attestation.evidence, {
      nonce: receipt.nonce,
      model: receipt.model.id,
      validAt: new Date(receipt.attestation.fetched_at),
      mode: receipt.attestation.source?.kind === 'recorded' ? 'recorded' : 'live',
      enforceNrasExpiry: false,
    });
  } catch (e) {
    add('evidence.recheck', 'attestation checks re-derived offline from stored evidence', false, 'could not re-run: ' + e.message);
  }
  if (rederived) {
    const diffs = [];
    for (const c of rederived.checks) {
      if (c.id === 'nonce.fresh') {
        // Whether the creator picked the nonce freshly is the creator's claim: it cannot be re-derived from the file.
        if (!recorded.has(c.id)) diffs.push(`${c.id}: missing from receipt`);
        continue;
      }
      if (!recorded.has(c.id)) diffs.push(`${c.id}: missing from receipt`);
      else if (recorded.get(c.id) !== c.status) diffs.push(`${c.id}: receipt says ${recorded.get(c.id)}, offline re-check says ${c.status}`);
    }
    add('evidence.recheck', `${rederived.checks.length} attestation checks re-derived offline from the stored evidence match the receipt`, diffs.length === 0, diffs.length ? diffs.join('; ') : 'every recorded status was reproduced from the raw quotes, event logs and verdict tokens');
  }

  if (recorded.get('nonce.fresh') === STATUS.VERIFIED) {
    results.push(check('nonce.freshness', 'nonce was chosen fresh (when)', STATUS.PRESENT, 'the creator of this receipt says the nonce was generated just before the request. A third party cannot check that from the file. For freshness you can trust, run `attested attest --nonce <your own 64 hex chars>` yourself'));
  }

  // 6. response signature (if the receipt carries one)
  const sigClaim = receipt.checks.find((c) => c.id === 'response.signature');
  if (receipt.response_signature) {
    if (!verifySig) {
      results.push(check('signature.recheck', 'response signature re-checked offline', STATUS.NOT_RUN, 'this build cannot recover secp256k1 signatures (use the CLI)'));
    } else if (!receipt.request || !receipt.response) {
      add('signature.recheck', 'response signature re-checked offline', false, 'signature present but request/response hashes missing');
    } else {
      const bound = (id) => rederived?.checks.find((c) => c.id === id)?.status === STATUS.VERIFIED;
      const r = await verifySig({
        model: receipt.model.id,
        requestSha256: receipt.request.sha256,
        responseSha256: receipt.response.sha256,
        sig: receipt.response_signature,
        evidence: receipt.attestation.evidence,
        keyBound: { gateway: bound('tdx.quote.gateway') && bound('tdx.report_data.gateway'), model: bound('tdx.quote.model') && bound('tdx.report_data.model') },
      });
      const same = sigClaim && sigClaim.status === r.status;
      add('signature.recheck', 'response signature re-checked offline and matches the receipt', !!same, `offline re-check: ${r.status} (${r.detail}); receipt says ${sigClaim?.status ?? 'nothing'}`);
    }
  } else if (sigClaim && sigClaim.status === STATUS.VERIFIED) {
    add('signature.recheck', 'receipt claims a verified signature but carries none', false, 'response.signature is VERIFIED in checks, yet response_signature is null');
  }

  // 7. tally
  const t = tallyChecks(receipt.checks);
  const tallyOk = JSON.stringify(t) === JSON.stringify(receipt.totals);
  add('receipt.totals', 'totals match the recorded checks', tallyOk, tallyOk ? JSON.stringify(t) : `recorded ${JSON.stringify(receipt.totals)}, actual ${JSON.stringify(t)}`);

  return finish(results, receipt, rederived);
}

function finish(results, receipt, rederived) {
  const ok = results.every((r) => r.status !== STATUS.FAILED);
  return { ok, results, claimed: Array.isArray(receipt?.checks) ? receipt.checks : [], rederived };
}
