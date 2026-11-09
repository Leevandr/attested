#!/usr/bin/env node
// Regenerates web/sample-receipt.json from the RECORDED demo (and anchors it in a local sandbox with --anchor).
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAsk } from '../src/ask.js';
import { anchorReceiptFile } from '../src/anchor.js';
import { readFileSync } from 'node:fs';

const DIR = (f) => fileURLToPath(new URL(`../demo/contract-review/${f}`, import.meta.url));
const out = mkdtempSync(join(tmpdir(), 'attested-sample-'));
await runAsk({ prompt: readFileSync(DIR('services-agreement.txt'), 'utf8'), system: readFileSync(DIR('question.txt'), 'utf8'), model: 'Qwen/Qwen3.8-27B', apiKey: '', forceRecorded: true, scenario: 'confidential-contract-review', out });
if (process.argv.includes('--anchor')) await anchorReceiptFile(join(out, 'receipt.json'), { network: 'sandbox', say: console.log });
copyFileSync(join(out, 'receipt.json'), fileURLToPath(new URL('../web/sample-receipt.json', import.meta.url)));
console.log('wrote web/sample-receipt.json');
