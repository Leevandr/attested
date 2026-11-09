import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { TOOL_VERSION } from './version.js';
import { DEFAULT_MODEL, classifyModel, fetchModelList } from './gateway.js';
import { buildReceipt, verifyReceipt } from './receipt.js';
import { gatherLive, loadFixture, runChecks } from './flows.js';
import { UsageError, runAsk, writeOutputs } from './ask.js';
import { verifyResponseSignature } from './signature.js';
import { renderProofCard } from './proofcard.js';
import { STATUS, check } from './util.js';
import { bold, dim, heading, kv, modeBanner, renderChecks, renderTotals, statusTag } from './format.js';
import { tallyChecks } from './attestation.js';

const HELP = `attested ${TOOL_VERSION} - verifiable receipts for private AI on NEAR

Usage:
  attested attest [--model ID] [--recorded] [--no-nras] [--nonce HEX64] [--out DIR]
        Fetch an attestation report (no API key), run the checks, write a receipt.
        --nonce lets a verifier supply the challenge, so freshness is meaningful to them.
  attested ask [PROMPT | --file FILE] [--system TEXT] [--model ID] [--out DIR]
        With NEAR_AI_API_KEY: one real non-streaming chat on a Confidential TEE model.
        Without a key: RECORDED mode (real recorded attestation, canned answer, clearly labelled).
  attested verify-receipt FILE [--json]
        Fully offline re-check of a receipt. Exit 0 ok, 1 tampered/invalid, 3 authentic but records FAILED checks.
  attested proofcard FILE [--out FILE.html]
        Re-render the HTML Proof Card from a receipt.
  attested anchor FILE [--network sandbox|testnet]
        Register the receipt hash in the receipt-registry contract (local sandbox by default).
  attested demo [--live] [--anchor]
        The "confidential contract review" story end to end.
  attested models
        List NEAR AI Cloud models and their privacy tier (public endpoint, no key).

Environment: NEAR_AI_API_KEY (optional), NEAR_AI_MODEL, NEAR_AI_BASE_URL, NO_COLOR.
`;

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  const valued = new Set(['model', 'out', 'file', 'system', 'network', 'nonce']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (valued.has(k)) flags[k] = argv[++i];
      else flags[k] = true;
    } else positional.push(a);
  }
  return { flags, positional };
}

const say = (s = '') => process.stdout.write(s + '\n');
const log = (s) => process.stderr.write(dim('  ' + s) + '\n');

function printResult(receipt, paths) {
  say(heading('Checks'));
  say(renderChecks(receipt.checks));
  say('');
  say(`  ${bold('Totals')}  ${renderTotals(receipt.totals)}`);
  say(heading('Receipt'));
  say(
    kv([
      ['model', `${receipt.model.id} (${receipt.model.tier})`],
      ['nonce', receipt.nonce],
      ['request sha256', receipt.request ? receipt.request.sha256 : '(none, attestation only)'],
      ['response sha256', receipt.response ? receipt.response.sha256 : '(none, attestation only)'],
      ['attestation digest', receipt.attestation.digest],
      ['receipt hash', receipt.receipt_hash],
      ['receipt.json', paths.jsonPath],
      ['Proof Card', pathToFileURL(paths.htmlPath).href],
    ]),
  );
}

// ---------------------------------------------------------------- attest
async function cmdAttest({ flags }) {
  const recorded = !!flags.recorded;
  const model = flags.model || process.env.NEAR_AI_MODEL || DEFAULT_MODEL;
  say(bold(`attested attest`) + dim(`  v${TOOL_VERSION}`));
  let g;
  let tier;
  if (recorded) {
    g = await loadFixture();
    if (flags.model && flags.model !== g.model) throw new UsageError(`RECORDED mode only has a real attestation for ${g.model}, not "${flags.model}"`);
    tier = g.modelEntry.tier;
    say(dim(`RECORDED: using fixtures/recorded-attestation.json (${g.fetchedAt.toISOString()}), not a live fetch`));
  } else {
    const entry = (await fetchModelList()).find((m) => m.modelId === model);
    if (!entry) throw new UsageError(`model "${model}" is not in the NEAR AI Cloud model list`);
    tier = classifyModel(entry);
    if (flags.nonce && !/^[0-9a-f]{64}$/.test(flags.nonce)) throw new UsageError('--nonce must be 64 lowercase hex characters');
    g = await gatherLive({ model, nras: !flags['no-nras'], nonce: flags.nonce ?? null, log });
    if (g.nrasError) log(`NVIDIA NRAS unavailable: ${g.nrasError}`);
    say(dim(`LIVE: report fetched ${g.fetchedAt.toISOString()} with a fresh nonce`));
  }
  if (tier !== 'Confidential TEE') say(`\n${statusTag(STATUS.FAILED)} model tier is "${tier}": this tool only treats "Confidential TEE" models as private`);
  const r = await runChecks(g);
  const checks = tier === 'Confidential TEE' ? r.checks : [check('model.tier', `model privacy tier is Confidential TEE`, STATUS.FAILED, `"${tier}"`), ...r.checks];
  const receipt = await buildReceipt({ mode: g.mode, model: g.model, tier, nonce: g.nonce, request: null, response: null, signature: null, gathered: g, attChecks: checks, summary: r.summary });
  const paths = await writeOutputs(receipt, resolve(flags.out || 'attested-out'));
  printResult(receipt, paths);
  return receipt.totals.failed > 0 ? 1 : 0;
}

async function cmdAsk({ flags, positional }) {
  const apiKey = process.env.NEAR_AI_API_KEY || '';
  const model = flags.model || process.env.NEAR_AI_MODEL || DEFAULT_MODEL;
  let prompt = positional.join(' ');
  if (flags.file) prompt = (prompt ? prompt + '\n\n' : '') + (await readFile(flags.file, 'utf8'));
  if (!prompt.trim()) throw new UsageError('give a prompt or --file');
  say(bold('attested ask') + dim(`  v${TOOL_VERSION}`));
  const { receipt, paths, live } = await runAsk({ prompt, system: flags.system || null, model, apiKey, noNras: !!flags['no-nras'], out: resolve(flags.out || 'attested-out') });
  say(dim(modeBanner(receipt.mode, receipt.response.source)));
  if (!live) say(dim('No NEAR_AI_API_KEY set: your prompt was hashed but NOT sent anywhere.'));
  printResult(receipt, paths);
  return receipt.totals.failed > 0 ? 1 : 0;
}

// ---------------------------------------------------------------- verify-receipt
async function cmdVerify({ flags, positional }) {
  const file = positional[0];
  if (!file) throw new UsageError('usage: attested verify-receipt FILE');
  let receipt;
  try {
    receipt = JSON.parse(await readFile(file, 'utf8'));
  } catch (e) {
    say(`${statusTag(STATUS.FAILED)} cannot read ${file} as JSON: ${e.message}`);
    return 1;
  }
  const out = await verifyReceipt(receipt, { verifySig: verifyResponseSignature });
  if (flags.json) {
    say(JSON.stringify({ ok: out.ok, results: out.results }, null, 2));
  } else {
    say(bold(`attested verify-receipt`) + dim('  (offline: no network used)'));
    say(heading('Receipt integrity and offline re-check'));
    say(renderChecks(out.results, { verbose: true }));
    if (out.ok && out.claimed.length) {
      say(heading('What the receipt records (re-derived above)'));
      say(renderChecks(out.claimed));
    }
  }
  if (!out.ok) {
    say('\n' + bold('RESULT: INVALID. The receipt does not verify. Do not trust it.'));
    return 1;
  }
  const failed = out.claimed.filter((c) => c.status === STATUS.FAILED);
  if (failed.length) {
    say('\n' + bold(`RESULT: AUTHENTIC, but it records ${failed.length} FAILED check(s). It is an honest record of a failure, not proof of private execution.`));
    return 3;
  }
  const t = tallyChecks(out.claimed);
  say('\n' + bold(`RESULT: OK. Receipt is intact and its evidence re-verifies offline (${t.verified} verified, ${t.present_not_verified} present-not-verified, ${t.not_run} not-run).`));
  return 0;
}

// ---------------------------------------------------------------- proofcard
async function cmdProofcard({ flags, positional }) {
  const file = positional[0];
  if (!file) throw new UsageError('usage: attested proofcard FILE [--out FILE.html]');
  const receipt = JSON.parse(await readFile(file, 'utf8'));
  const outFile = resolve(flags.out || file.replace(/\.json$/, '') + '.html');
  await writeFile(outFile, renderProofCard(receipt));
  say(pathToFileURL(outFile).href);
  return 0;
}

// ---------------------------------------------------------------- models
async function cmdModels() {
  const list = await fetchModelList();
  say(bold('NEAR AI Cloud models by privacy tier') + dim('  (public list, no key)'));
  for (const tier of ['Confidential TEE', '3P', 'Incognito']) {
    const rows = list.filter((m) => classifyModel(m).startsWith(tier));
    say(heading(`${tier} (${rows.length})`));
    for (const m of rows) say(`  ${m.modelId}`);
  }
  say(dim('\nattested ask only accepts "Confidential TEE" models.'));
  return 0;
}

// ---------------------------------------------------------------- anchor + demo are in their own modules
async function cmdAnchor(args) {
  const { anchorCommand } = await import('./anchor.js');
  return anchorCommand(args, { say, bold, dim, kv, heading });
}

async function cmdDemo(args) {
  const { demoCommand } = await import('./demo.js');
  return demoCommand(args, { say });
}

export async function main(argv) {
  const [cmd, ...rest] = argv;
  const args = parseArgs(rest);
  try {
    switch (cmd) {
      case 'attest':
        return await cmdAttest(args);
      case 'ask':
        return await cmdAsk(args);
      case 'verify-receipt':
        return await cmdVerify(args);
      case 'proofcard':
        return await cmdProofcard(args);
      case 'anchor':
        return await cmdAnchor(args);
      case 'demo':
        return await cmdDemo(args);
      case 'models':
        return await cmdModels();
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        say(HELP);
        return 0;
      default:
        process.stderr.write(`unknown command "${cmd}"\n\n${HELP}`);
        return 2;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`error: ${e.message}\n`);
      return 2;
    }
    process.stderr.write(`error: ${e.message}\n`);
    if (/fetch failed|timeout|ENOTFOUND|ECONN|EAI_AGAIN|aborted/i.test(String(e.message) + String(e.cause?.code ?? ''))) {
      process.stderr.write('network problem: try the offline path (attested attest --recorded, npm run demo)\n');
    }
    return 2;
  }
}

