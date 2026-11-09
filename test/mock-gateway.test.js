// Exercises the live `ask` choreography against a LOCAL mock gateway (no network, no key).
// The mock cannot forge Intel quotes, so it replays the recorded report: the tool must notice.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runAsk, UsageError } from '../src/ask.js';
import { verifyReceipt } from '../src/receipt.js';
import { verifyResponseSignature } from '../src/signature.js';
import { addressOfSecretKey, signPersonal } from '../src/eth.js';
import { sha256Utf8 } from '../src/gateway.js';
import { STATUS } from '../src/util.js';
import { byId, fixtureRaw, tmp } from './helpers.js';

const sk = new Uint8Array(32).fill(9);

function startMock({ requireKey = 'test-key', signKey = sk, kind = 'provider_tee' } = {}) {
  const fx = fixtureRaw();
  const state = { chatCalls: 0, sigCalls: 0, lastRequest: null, lastResponse: null, auth: null };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const json = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(typeof obj === 'string' ? obj : JSON.stringify(obj));
    };
    if (url.pathname === '/v1/model/list') {
      const tee = { modelId: 'Qwen/Qwen3.8-27B', metadata: { verifiable: true, attestationSupported: true, providerType: 'vllm', architecture: { outputModalities: ['text'] } } };
      const inc = { modelId: 'openai/gpt-5', metadata: { verifiable: false, attestationSupported: false, providerType: 'external', architecture: { outputModalities: ['text'] } } };
      return json(200, { models: [tee, inc] });
    }
    if (url.pathname === '/v1/attestation/report') {
      const nonce = url.searchParams.get('nonce');
      const r = structuredClone(fx.report);
      r.gateway_attestation.request_nonce = nonce;
      r.model_attestations[0].request_nonce = nonce;
      return json(200, r);
    }
    if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
      state.chatCalls++;
      state.auth = req.headers.authorization;
      if (req.headers.authorization !== `Bearer ${requireKey}`) return json(401, { error: 'no' });
      let body = '';
      req.on('data', (d) => (body += d));
      req.on('end', () => {
        state.lastRequest = body;
        state.lastResponse = JSON.stringify({ id: 'chatcmpl-mock-1', object: 'chat.completion', choices: [{ index: 0, message: { role: 'assistant', content: 'mock answer' } }] });
        json(200, state.lastResponse);
      });
      return;
    }
    if (url.pathname === '/v1/signature/chatcmpl-mock-1') {
      state.sigCalls++;
      if (state.sigCalls < 2) return json(404, { error: 'not on this node yet' });
      const req_h = sha256Utf8(state.lastRequest);
      const res_h = sha256Utf8(state.lastResponse);
      const text = kind === 'provider_tee' ? `${url.searchParams.get('model')}:${req_h}:${res_h}` : `${req_h}:${res_h}`;
      return json(200, { text, signature: signPersonal(text, signKey), signing_address: addressOfSecretKey(signKey), signing_algo: 'ecdsa', signature_kind: kind });
    }
    json(404, { error: 'unknown' });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, state, url: `http://127.0.0.1:${server.address().port}` })));
}

test('live ask refuses a model that is not a Confidential TEE model, before sending anything', async () => {
  const m = await startMock();
  process.env.NEAR_AI_BASE_URL = m.url;
  try {
    await assert.rejects(() => runAsk({ prompt: 'secret', model: 'openai/gpt-5', apiKey: 'test-key', noNras: true, out: tmp() }), (e) => e instanceof UsageError && /Incognito/.test(e.message));
    assert.equal(m.state.chatCalls, 0, 'no request may reach a non-TEE model');
  } finally {
    delete process.env.NEAR_AI_BASE_URL;
    m.server.close();
  }
});

test('live ask: full HTTP flow works, signature lookup is retried, and a replayed attestation is caught', async () => {
  const m = await startMock();
  process.env.NEAR_AI_BASE_URL = m.url;
  try {
    const { receipt } = await runAsk({ prompt: 'hello', system: 'sys', model: 'Qwen/Qwen3.8-27B', apiKey: 'test-key', noNras: true, out: tmp() });
    assert.equal(m.state.auth, 'Bearer test-key');
    assert.ok(m.state.sigCalls >= 2, 'retried after the first 404');
    assert.equal(JSON.parse(m.state.lastRequest).stream, false, 'never streams');
    assert.equal(receipt.mode, 'live');
    assert.equal(receipt.response.source, 'live-chat');
    assert.equal(receipt.response.sha256, sha256Utf8(m.state.lastResponse));
    assert.equal(receipt.request.sha256, sha256Utf8(m.state.lastRequest));
    assert.equal(receipt.response_signature.signature_kind, 'provider_tee');
    // the replayed report must NOT pass: its quotes commit to the old nonce
    assert.equal(byId(receipt.checks, 'nonce.echo').status, STATUS.VERIFIED, 'mock echoes the nonce in plain fields');
    assert.equal(byId(receipt.checks, 'tdx.report_data.model').status, STATUS.FAILED);
    assert.equal(byId(receipt.checks, 'response.signature').status, STATUS.FAILED, 'signing key of the mock is not the attested key');
    assert.ok(receipt.totals.failed >= 3);
    // The receipt itself is authentic, and honestly records the failures.
    const v = await verifyReceipt(receipt, { verifySig: verifyResponseSignature });
    assert.equal(v.ok, true, JSON.stringify(v.results.filter((r) => r.status === 'FAILED')));
    assert.ok(v.claimed.some((c) => c.status === STATUS.FAILED));
    // NVIDIA verdict was skipped on purpose here
    assert.equal(byId(receipt.checks, 'nvidia.nras').status, STATUS.PRESENT);
  } finally {
    delete process.env.NEAR_AI_BASE_URL;
    m.server.close();
  }
});

test('live ask: a wrong API key surfaces as an error, not as a receipt', async () => {
  const m = await startMock({ requireKey: 'other' });
  process.env.NEAR_AI_BASE_URL = m.url;
  try {
    await assert.rejects(() => runAsk({ prompt: 'x', model: 'Qwen/Qwen3.8-27B', apiKey: 'test-key', noNras: true, out: tmp() }), /HTTP 401/);
  } finally {
    delete process.env.NEAR_AI_BASE_URL;
    m.server.close();
  }
});
