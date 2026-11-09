// Orchestration: gather attestation evidence (live or recorded), run `ask`, build receipts.

import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { compactReport, verifyEvidence } from './attestation.js';
import { DEFAULT_MODEL, chatCompletion, fetchAttestationReport, fetchSignature, sha256Utf8 } from './gateway.js';
import { decodeJwt, fetchNras, fetchNrasJwk, nvidiaPayloadSummary } from './nvidia.js';
import { verifyResponseSignature } from './signature.js';
import { STATUS, check } from './util.js';

export const FIXTURE_PATH = fileURLToPath(new URL('../fixtures/recorded-attestation.json', import.meta.url));
export const DEMO_RESPONSE_PATH = fileURLToPath(new URL('../fixtures/demo-response.json', import.meta.url));

export const newNonce = () => randomBytes(32).toString('hex');

async function nvidiaSummary(report) {
  const payload = report.model_attestations?.[0]?.nvidia_payload;
  if (!payload) return null;
  return { ...nvidiaPayloadSummary(payload), payloadSha256: sha256Utf8(payload) };
}

// Fetch a fresh report with a fresh nonce, and (unless disabled) NVIDIA's signed verdict.
export async function gatherLive({ model = DEFAULT_MODEL, nras = true, nonce: suppliedNonce = null, log = () => {} } = {}) {
  if (suppliedNonce !== null && !/^[0-9a-f]{64}$/.test(suppliedNonce)) throw new Error('nonce must be 64 lowercase hex characters');
  const nonce = suppliedNonce ?? newNonce();
  const fetchedAt = new Date();
  log(`GET attestation report (model ${model}, fresh nonce ${nonce.slice(0, 12)}...)`);
  const { url, report } = await fetchAttestationReport(model, nonce);
  const nv = await nvidiaSummary(report);
  const evidence = { report: compactReport(report, nv) };
  let nrasError = null;
  let nrasRaw = null;
  if (nras && nv) {
    try {
      log('POST GPU evidence to NVIDIA NRAS');
      const payload = report.model_attestations[0].nvidia_payload;
      nrasRaw = await fetchNras(payload);
      const kid = decodeJwt(nrasRaw[0][1]).header.kid;
      const jwk = await fetchNrasJwk(kid);
      evidence.nras = { response: nrasRaw, jwk };
    } catch (e) {
      nrasError = e.message;
    }
  }
  return { mode: 'live', nonce, nonceSource: suppliedNonce ? 'supplied' : 'generated', fetchedAt, model, source: { url: url.replace(nonce, '<nonce>'), kind: 'live' }, rawReport: report, nrasRaw, evidence, nrasError };
}

export async function loadFixture(path = FIXTURE_PATH) {
  const fx = JSON.parse(await readFile(path, 'utf8'));
  const nv = await nvidiaSummary(fx.report);
  const evidence = { report: compactReport(fx.report, nv) };
  if (fx.nras) evidence.nras = { response: fx.nras.response, jwk: fx.nras.jwk };
  return {
    mode: 'recorded',
    nonce: fx.nonce,
    fetchedAt: new Date(fx.recorded_at),
    model: fx.model,
    modelEntry: fx.model_entry,
    source: { url: fx.source_url, kind: 'recorded', recorded_at: fx.recorded_at },
    evidence,
    nrasError: null,
  };
}

// Run the attestation checks on gathered evidence.
export async function runChecks(g) {
  return verifyEvidence(g.evidence, { nonce: g.nonce, model: g.model, validAt: g.fetchedAt, mode: g.mode, nonceSource: g.nonceSource, enforceNrasExpiry: g.mode === 'live' });
}

// Build the standard chat request. One exact string: it is what gets hashed and signed.
export function buildChatRequest({ model, system, user }) {
  return JSON.stringify({ model, stream: false, messages: [...(system ? [{ role: 'system', content: system }] : []), { role: 'user', content: user }] });
}

// Live `ask`: needs an API key, a Confidential TEE model, and does one non-streaming completion.
export async function askLive({ apiKey, model, requestBody, gathered }) {
  const res = await chatCompletion(apiKey, requestBody);
  if (!res.id) throw new Error('response has no chat id, cannot fetch its signature');
  const sig = await fetchSignature(apiKey, res.id, model);
  return { responseBody: res.text, chatId: res.id, sig };
}

export function signatureCheck({ model, requestBody, responseBody, sig, evidence, attChecks }) {
  const ok = (id) => attChecks.find((c) => c.id === id)?.status === STATUS.VERIFIED;
  const keyBound = {
    gateway: ok('tdx.quote.gateway') && ok('tdx.report_data.gateway'),
    model: ok('tdx.quote.model') && ok('tdx.report_data.model'),
  };
  return verifyResponseSignature({ model, requestSha256: sha256Utf8(requestBody), responseSha256: sha256Utf8(responseBody), sig, evidence, keyBound });
}

export function notRunSignature(reason) {
  return check('response.signature', 'response signature by the TEE key', STATUS.NOT_RUN, reason);
}

