import { readFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compactReport } from '../src/attestation.js';
import { nvidiaPayloadSummary } from '../src/nvidia.js';
import { sha256Utf8 } from '../src/gateway.js';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const fixtureRaw = () => JSON.parse(readFileSync(join(ROOT, 'fixtures/recorded-attestation.json'), 'utf8'));
export const tmp = () => mkdtempSync(join(tmpdir(), 'attested-test-'));

// Evidence + context exactly as the recorded demo mode builds them (fresh copy each call).
export function fixtureEvidence() {
  const fx = fixtureRaw();
  const p = fx.report.model_attestations[0].nvidia_payload;
  const nv = { ...nvidiaPayloadSummary(p), payloadSha256: sha256Utf8(p) };
  const evidence = { report: compactReport(fx.report, nv), nras: fx.nras };
  const ctx = { nonce: fx.nonce, model: fx.model, validAt: new Date(fx.recorded_at), mode: 'recorded' };
  return { fx, evidence, ctx };
}

export const byId = (checks, id) => checks.find((c) => c.id === id);
