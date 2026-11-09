// `attested anchor`: register a receipt hash in the receipt-registry contract.
//   default      a fresh LOCAL sandbox node (near-kit): nothing is public, nothing persists
//   --network testnet   only with a throwaway testnet account whose key file lives OUTSIDE this repo
//   mainnet      refused, always
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, dirname, join, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReceipt } from './receipt.js';
import { verifyResponseSignature } from './signature.js';
import { renderProofCard } from './proofcard.js';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const WASM = join(REPO, 'contract/artifacts/receipt_registry.wasm');
const WASM_SHA = join(REPO, 'contract/artifacts/receipt_registry.wasm.sha256');
const DEPOSIT = '0.01 NEAR'; // measured need is about 0.0034 NEAR; the excess is refunded
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class AnchorError extends Error {}

async function loadAndVerify(file) {
  const receipt = JSON.parse(await readFile(file, 'utf8'));
  const v = await verifyReceipt(receipt, { verifySig: verifyResponseSignature });
  if (!v.ok) throw new AnchorError('refusing to anchor: the receipt does not verify offline (run verify-receipt)');
  return receipt;
}

// A record on chain must equal what the receipt says; anyone can register a hash first.
function recordMatches(rec, receipt) {
  return !!rec && rec.model_id === receipt.model.id && rec.attestation_digest === receipt.attestation.digest;
}

async function readWasm() {
  const wasm = await readFile(WASM);
  const want = (await readFile(WASM_SHA, 'utf8')).trim().split(/\s+/)[0];
  const got = createHash('sha256').update(wasm).digest('hex');
  if (got !== want) throw new AnchorError(`contract wasm sha256 ${got} does not match contract/artifacts/receipt_registry.wasm.sha256 (${want})`);
  return { wasm, sha256: got };
}

async function waitView(near, contract, hash, tries = 12) {
  // near-kit: a view right after a call can return stale data for a few seconds
  for (let i = 0; i < tries; i++) {
    const rec = await near.view(contract, 'get_receipt', { receipt_hash: hash });
    if (rec) return rec;
    await sleep(1000);
  }
  return null;
}

async function anchorSandbox(receipt, say) {
  const { Near, generateKey } = await import('near-kit');
  const { Sandbox } = await import('near-kit/sandbox');
  const { wasm, sha256 } = await readWasm();
  say(`  contract wasm ${wasm.length} bytes, sha256 ${sha256.slice(0, 16)}... (matches contract/artifacts)`);
  say('  starting a local NEAR sandbox node (first run downloads the node binary, needs network once)...');
  const sandbox = await Sandbox.start({ detached: false });
  try {
    const root = new Near({ network: sandbox });
    const contract = 'registry.test.near';
    const submitter = 'submitter.test.near';
    const ck = generateKey();
    const sk = generateKey();
    await root.transaction(sandbox.rootAccount.id).createAccount(contract).transfer(contract, '5 NEAR').addKey(ck.publicKey.toString(), { type: 'fullAccess' }).deployContract(contract, wasm).send();
    await root.transaction(sandbox.rootAccount.id).createAccount(submitter).transfer(submitter, '10 NEAR').addKey(sk.publicKey.toString(), { type: 'fullAccess' }).send();
    const near = new Near({ network: sandbox, privateKey: sk.secretKey, defaultSignerId: submitter });
    const args = { receipt_hash: receipt.receipt_hash, model_id: receipt.model.id, attestation_digest: receipt.attestation.digest };
    say(`  register_receipt(${receipt.receipt_hash.slice(0, 16)}...) with ${DEPOSIT} attached for storage`);
    const outcome = await near.call(contract, 'register_receipt', args, { attachedDeposit: DEPOSIT, gas: '30 Tgas' });
    const txHash = outcome.transaction?.hash ?? outcome.transaction_outcome?.id ?? null;
    const rec = await waitView(near, contract, receipt.receipt_hash);
    if (!recordMatches(rec, receipt)) throw new AnchorError('on-chain record does not match the receipt');
    say(`  on-chain record: submitter ${rec.submitter}, model ${rec.model_id}, timestamp_ms ${rec.timestamp_ms}`);
    // No overwrite, ever: a second registration of the same hash must fail.
    let dupRejected = false;
    try {
      await near.call(contract, 'register_receipt', args, { attachedDeposit: DEPOSIT, gas: '30 Tgas' });
    } catch (e) {
      dupRejected = /already registered/.test(String(e.message) + JSON.stringify(e.data ?? ''));
    }
    say(`  second registration of the same hash: ${dupRejected ? 'rejected ("already registered"), as designed' : 'NOT rejected (unexpected)'}`);
    if (!dupRejected) throw new AnchorError('duplicate registration was not rejected');
    const total = await near.view(contract, 'total_receipts', {});
    return {
      network: 'sandbox',
      note: 'local sandbox node, discarded after this command; nothing public',
      contract,
      contract_wasm_sha256: sha256,
      submitter: rec.submitter,
      tx_hash: txHash,
      registered_at: new Date(rec.timestamp_ms).toISOString(),
      record: rec,
      total_receipts: total,
    };
  } finally {
    await sandbox.stop();
  }
}

function insideRepo(p) {
  const rel = relative(REPO, resolve(p));
  return !rel.startsWith('..') && !isAbsolute(rel);
}

async function testnetNear() {
  const contract = process.env.ATTESTED_REGISTRY_CONTRACT;
  const account = process.env.ATTESTED_ACCOUNT;
  const keyFile = process.env.ATTESTED_KEY_FILE;
  if (!contract) throw new AnchorError('set ATTESTED_REGISTRY_CONTRACT to the testnet contract account (see README, "Testnet")');
  const { Near } = await import('near-kit');
  const net = { networkId: 'testnet', rpcUrl: process.env.ATTESTED_RPC_URL || 'https://test.rpc.fastnear.com' };
  if (!account || !keyFile) return { near: new Near({ network: net }), contract, readOnly: true };
  if (insideRepo(keyFile)) throw new AnchorError('refusing to read a key file inside the repository; keep testnet keys outside it');
  const key = JSON.parse(await readFile(keyFile, 'utf8')).private_key;
  if (!account.endsWith('.testnet')) throw new AnchorError('ATTESTED_ACCOUNT must be a .testnet account');
  return { near: new Near({ network: net, privateKey: key, defaultSignerId: account }), contract, readOnly: false, account };
}

async function anchorTestnet(receipt, say, { verifyOnly }) {
  const t = await testnetNear();
  const existing = await t.near.view(t.contract, 'get_receipt', { receipt_hash: receipt.receipt_hash });
  if (verifyOnly || existing) {
    if (!existing) throw new AnchorError('this receipt hash is not registered on testnet');
    if (!recordMatches(existing, receipt)) throw new AnchorError('a record exists for this hash but it does not match the receipt (someone else registered the hash first?)');
    say(`  already registered on testnet by ${existing.submitter} at ${new Date(existing.timestamp_ms).toISOString()}; record matches the receipt`);
    return { network: 'testnet', contract: t.contract, submitter: existing.submitter, tx_hash: null, registered_at: new Date(existing.timestamp_ms).toISOString(), record: existing };
  }
  if (t.readOnly) throw new AnchorError('to register on testnet set ATTESTED_ACCOUNT (a throwaway *.testnet account) and ATTESTED_KEY_FILE (JSON with "private_key", outside the repo)');
  const args = { receipt_hash: receipt.receipt_hash, model_id: receipt.model.id, attestation_digest: receipt.attestation.digest };
  say(`  register_receipt on testnet contract ${t.contract} as ${t.account}`);
  const outcome = await t.near.call(t.contract, 'register_receipt', args, { attachedDeposit: DEPOSIT, gas: '30 Tgas' });
  const rec = await waitView(t.near, t.contract, receipt.receipt_hash);
  if (!recordMatches(rec, receipt)) throw new AnchorError('on-chain record does not match the receipt');
  return { network: 'testnet', contract: t.contract, submitter: rec.submitter, tx_hash: outcome.transaction?.hash ?? null, registered_at: new Date(rec.timestamp_ms).toISOString(), record: rec };
}

export async function anchorReceiptFile(file, { network = 'sandbox', say, verifyOnly = false }) {
  if (network === 'mainnet') throw new AnchorError('mainnet is not supported, by design');
  if (network !== 'sandbox' && network !== 'testnet') throw new AnchorError(`unknown network "${network}" (use sandbox or testnet)`);
  const receipt = await loadAndVerify(file);
  say(`  receipt ${receipt.receipt_hash.slice(0, 16)}... verifies offline`);
  const anchor = network === 'sandbox' ? await anchorSandbox(receipt, say) : await anchorTestnet(receipt, say, { verifyOnly });
  receipt.anchor = anchor;
  await writeFile(file, JSON.stringify(receipt, null, 2) + '\n');
  const html = join(dirname(resolve(file)), 'receipt.html');
  await writeFile(html, renderProofCard(receipt));
  return anchor;
}

export async function anchorCommand({ flags, positional }, { say, bold, dim, kv, heading }) {
  const file = positional[0];
  if (!file) {
    process.stderr.write('usage: attested anchor FILE [--network sandbox|testnet] [--verify-only]\n');
    return 2;
  }
  say(bold('attested anchor') + dim(`  (${flags.network || 'sandbox'})`));
  try {
    const a = await anchorReceiptFile(file, { network: flags.network || 'sandbox', say, verifyOnly: !!flags['verify-only'] });
    say(heading('Anchored'));
    say(kv([['network', a.network === 'sandbox' ? 'local sandbox (ephemeral, not public)' : a.network], ['contract', a.contract], ['submitter', a.submitter], ['transaction', a.tx_hash ?? '(existing record)'], ['block time', a.registered_at]]));
    say(dim('\nreceipt.json and receipt.html were updated with the anchor record (the anchor is not part of the receipt hash).'));
    return 0;
  } catch (e) {
    if (e instanceof AnchorError) {
      process.stderr.write(`error: ${e.message}\n`);
      return 1;
    }
    throw e;
  }
}
