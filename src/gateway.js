// Plain-fetch client for the NEAR AI Cloud gateway (OpenAI-compatible). No SDK, no Node 24 needed.
// Only three kinds of calls: the public model list, the public attestation report, and (with an
// API key) one non-streaming chat completion plus its signature.

import { createHash } from 'node:crypto';

export const DEFAULT_BASE_URL = 'https://cloud-api.near.ai';
export const DEFAULT_MODEL = 'Qwen/Qwen3.8-27B';

export function baseUrl() {
  return (process.env.NEAR_AI_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
}

async function httpError(res, what) {
  let body = '';
  try {
    body = (await res.text()).slice(0, 200).replace(/\s+/g, ' ');
  } catch {
    /* ignore */
  }
  return new Error(`${what}: HTTP ${res.status}${body ? ' ' + body : ''}`);
}

export async function fetchModelList() {
  const res = await fetch(`${baseUrl()}/v1/model/list`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw await httpError(res, 'model list');
  return (await res.json()).models;
}

// Privacy tiers as documented by NEAR AI Cloud. Only "Confidential TEE" (NEAR's own GPU fleet,
// full attestation) is accepted by this tool. 3P TEE models and "Incognito" models (OpenAI,
// Anthropic, Gemini routed through the gateway) are NOT private in the sense this tool proves.
export function classifyModel(entry) {
  const md = entry?.metadata ?? {};
  if (md.verifiable === true && md.attestationSupported === true && md.providerType === 'vllm') return 'Confidential TEE';
  if (md.verifiable === true && md.attestationSupported === true) return `3P Confidential TEE (${md.providerType})`;
  return 'Incognito (not a TEE)';
}

export function isChatCapable(entry) {
  const out = entry?.metadata?.architecture?.outputModalities ?? [];
  return out.includes('text') && !/embedding|reranker|whisper|privacy-filter/i.test(entry.modelId);
}

export async function fetchAttestationReport(model, nonce, { signal } = {}) {
  const q = new URLSearchParams({ model, nonce, signing_algo: 'ecdsa' });
  const url = `${baseUrl()}/v1/attestation/report?${q}`;
  const res = await fetch(url, { headers: { accept: 'application/json' }, signal: signal ?? AbortSignal.timeout(60000) });
  if (!res.ok) throw await httpError(res, 'attestation report');
  return { url, report: await res.json() };
}

// One NON-STREAMING chat completion. The exact request string we send is what gets hashed.
export async function chatCompletion(apiKey, requestBody) {
  const res = await fetch(`${baseUrl()}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${apiKey}` },
    body: requestBody,
    signal: AbortSignal.timeout(180000),
  });
  if (!res.ok) throw await httpError(res, 'chat completion');
  const text = await res.text(); // exact bytes: this exact string is what gets hashed and signed
  let id = null;
  try {
    id = JSON.parse(text).id ?? null;
  } catch {
    /* handled by caller */
  }
  return { text, id };
}

// The signature is cached on the TEE node that served the request; a lookup may 404 until it
// lands on the right node, so retry briefly (same approach as the official example).
export async function fetchSignature(apiKey, chatId, model, { retries = 6, delayMs = 1000 } = {}) {
  const url = `${baseUrl()}/v1/signature/${encodeURIComponent(chatId)}?model=${encodeURIComponent(model)}&signing_algo=ecdsa`;
  let last;
  for (let i = 0; i < retries; i++) {
    const res = await fetch(url, { headers: { accept: 'application/json', authorization: `Bearer ${apiKey}` }, signal: AbortSignal.timeout(30000) });
    if (res.ok) return res.json();
    last = await httpError(res, 'signature lookup');
    if (res.status !== 404) break;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw last;
}

export const sha256Utf8 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
