// `ask`: one chat completion (live, with a key) or the RECORDED fixture path, then checks and receipt.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DEMO_RESPONSE_PATH, askLive, buildChatRequest, gatherLive, loadFixture, notRunSignature, runChecks, signatureCheck } from './flows.js';
import { classifyModel, fetchModelList, isChatCapable } from './gateway.js';
import { buildReceipt } from './receipt.js';
import { renderProofCard } from './proofcard.js';

const log = (s) => process.stderr.write('  ' + s + '\n');

export async function writeOutputs(receipt, outDir) {
  await mkdir(outDir, { recursive: true });
  const jsonPath = join(outDir, 'receipt.json');
  const htmlPath = join(outDir, 'receipt.html');
  await writeFile(jsonPath, JSON.stringify(receipt, null, 2) + '\n');
  await writeFile(htmlPath, renderProofCard(receipt));
  return { jsonPath, htmlPath };
}

export class UsageError extends Error {}

// ---------------------------------------------------------------- ask
export async function runAsk({ prompt, system = null, model, apiKey, forceRecorded = false, noNras = false, scenario = null, liveAttestation = false, out }) {
  const live = !!apiKey && !forceRecorded;
  let g;
  let tier;
  let request;
  let response;
  let signature = null;
  let sigCheck;
  const requestBody = buildChatRequest({ model, system, user: prompt });
  if (live) {
    const entry = (await fetchModelList()).find((m) => m.modelId === model);
    if (!entry) throw new UsageError(`model "${model}" is not in the NEAR AI Cloud model list`);
    tier = classifyModel(entry);
    if (tier !== 'Confidential TEE' || !isChatCapable(entry)) throw new UsageError(`refusing to call "${model}": privacy tier is "${tier}". attested only calls Confidential TEE chat models (see: attested models).`);
    log(`POST chat completion (non-streaming) to ${model}`);
    const res = await askLive({ apiKey, model, requestBody });
    signature = res.sig;
    log('GET fresh attestation report for the same model');
    g = await gatherLive({ model, nras: !noNras, log });
    request = { body: requestBody };
    response = { body: res.responseBody, source: 'live-chat', chat_id: res.chatId };
  } else {
    const fx = await loadFixture();
    if (model !== fx.model) throw new UsageError(`RECORDED mode only has a real attestation for ${fx.model}, not "${model}". Set NEAR_AI_API_KEY to use another model.`);
    tier = fx.modelEntry.tier;
    if (liveAttestation) {
      g = await gatherLive({ model: fx.model, nras: !noNras, log });
    } else g = fx;
    model = g.model;
    const canned = await readFile(DEMO_RESPONSE_PATH, 'utf8');
    request = { body: buildChatRequest({ model, system, user: prompt }) };
    response = { body: canned, source: 'recorded-fixture', chat_id: null };
  }
  if (g.nrasError) log(`NVIDIA NRAS unavailable: ${g.nrasError}`);
  const r = await runChecks(g);
  if (live) sigCheck = signatureCheck({ model, requestBody: request.body, responseBody: response.body, sig: signature, evidence: g.evidence, attChecks: r.checks });
  else sigCheck = notRunSignature('no response signature exists: the answer is a canned fixture, no model ran. Run with NEAR_AI_API_KEY for a real signed answer');
  const mode = g.mode === 'live' ? 'live' : 'recorded';
  const notes = [];
  if (!live) notes.push('The answer text is a canned fixture written by the project authors. No model produced it and no response signature exists.');
  if (live) notes.push('Attestation was fetched right after the chat request, with a fresh nonce; the response signature key is matched to that attestation.');
  const receipt = await buildReceipt({ mode, scenario, model, tier, nonce: g.nonce, request, response, signature, gathered: g, attChecks: r.checks, signatureCheckResult: sigCheck, summary: r.summary, notes });
  const paths = await writeOutputs(receipt, out);
  return { receipt, paths, live };
}

