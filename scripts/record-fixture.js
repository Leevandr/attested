#!/usr/bin/env node
// Developer script: record a REAL attestation report (fresh nonce) + NVIDIA's verdict into
// fixtures/recorded-attestation.json. This is how the shipped fixture was made.
// Needs network, no API key. Usage: node scripts/record-fixture.js [model]
import { writeFile } from 'node:fs/promises';
import { DEFAULT_MODEL, classifyModel, fetchModelList } from '../src/gateway.js';
import { FIXTURE_PATH, gatherLive } from '../src/flows.js';

const model = process.argv[2] || DEFAULT_MODEL;
const g = await gatherLive({ model, log: (m) => console.error('  ' + m) });
if (!g.evidence.nras) throw new Error('NVIDIA verdict missing: ' + g.nrasError);
const entry = (await fetchModelList()).find((m) => m.modelId === model);
if (!entry) throw new Error('model not in list');
const { modelDescription: _d, modelIcon: _i, ...metadata } = entry.metadata;
const fixture = {
  schema: 'attested.fixture/v1',
  note: 'REAL attestation report fetched from NEAR AI Cloud (no API key) plus the real NVIDIA NRAS verdict for its GPU payload. Reused offline by the RECORDED demo mode. The nonce is NOT fresh when replayed.',
  recorded_at: g.fetchedAt.toISOString(),
  source_url: g.source.url,
  model,
  nonce: g.nonce,
  model_entry: { modelId: entry.modelId, metadata, tier: classifyModel(entry) },
  report: g.rawReport,
  nras: g.evidence.nras,
};
await writeFile(FIXTURE_PATH, JSON.stringify(fixture) + '\n');
console.error(`wrote ${FIXTURE_PATH} (${JSON.stringify(fixture).length} bytes), recorded_at ${fixture.recorded_at}`);
