#!/usr/bin/env node
// Builds web/index.html: the static, self-contained verifier page (no server, no network, no framework).
// Inputs: web/style.css, web/page.js, web/fonts/*, src/*.js (bundled), web/sample-receipt.json.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { pageShell } from '../src/proofcard.js';

const WEB = (f) => fileURLToPath(new URL(`../web/${f}`, import.meta.url));

export function buildIndexHtml() {
  const sample = JSON.parse(readFileSync(WEB('sample-receipt.json'), 'utf8'));
  const body = `
<section class="page-hero">
  <p class="eyebrow">Private AI &middot; hardware attestation &middot; NEAR</p>
  <h1>Check that an AI answer really came from a sealed model.</h1>
  <p>Confidential AI runs inside a hardware enclave that signs what it is. Attested turns that evidence into a receipt anyone can re-check offline, and anchors the receipt's hash on NEAR.</p>
  <div class="flow">
    <div class="f"><b>1. Ask</b>Send a sensitive document to a model on NEAR AI Cloud's confidential tier.</div>
    <div class="f"><b>2. Receipt</b>Get the answer plus a receipt: hashes, the enclave's Intel and NVIDIA evidence, every check labelled.</div>
    <div class="f"><b>3. Verify</b>A third party re-derives it all from the file, offline. One changed byte fails it.</div>
  </div>
</section>

<section class="card" id="verify-box">
  <h2>Verify it yourself</h2>
  <p class="lede">Paste or drop a <code>receipt.json</code>. Everything runs in this page, in your browser, with no network. Nothing is uploaded.</p>
  <div class="drop" id="drop">
    <b>Drop receipt.json here</b>
    <label class="btn secondary filebtn" for="file">Choose a file</label>
    <input id="file" class="sr-only" type="file" accept=".json,application/json">
    <p class="or">or paste the JSON</p>
    <textarea id="paste" placeholder='{"schema": "attested.receipt/v1", ...}' spellcheck="false" aria-label="Receipt JSON"></textarea>
    <div class="row-actions">
      <button class="btn" id="go" type="button">Check receipt</button>
      <button class="btn secondary" id="load-sample" type="button">Load the sample receipt</button>
      <button class="btn secondary" id="tamper" type="button">Tamper with the sample</button>
    </div>
  </div>
</section>

<div id="view"></div>

<section class="card">
  <h2>What a receipt does and does not prove</h2>
  <div class="cols">
    <div>
      <p class="lede" style="margin-bottom:8px"><strong style="color:var(--ink)">Verified here, with real cryptography</strong></p>
      <ul class="limit-list">
        <li>Intel TDX quote signature chains up to Intel's pinned root</li>
        <li>The enclave's signing key and our nonce sit inside the signed quote</li>
        <li>The boot log replays to the measured registers</li>
        <li>NVIDIA's signed verdict for 8 GPUs, bound to the same nonce</li>
        <li>The receipt's own hashes: change one byte and it fails</li>
      </ul>
    </div>
    <div>
      <p class="lede" style="margin-bottom:8px"><strong style="color:var(--ink)">Not proven (and labelled that way)</strong></p>
      <ul class="limit-list">
        <li>Intel TCB status and revocation (needs Intel collateral)</li>
        <li>That the published software is the audited build</li>
        <li>Streaming answers (signed by the gateway, not the model)</li>
        <li>That the answer is correct</li>
        <li>The browser cannot re-check the secp256k1 response signature; the CLI does</li>
      </ul>
    </div>
  </div>
</section>
<div class="foot"><span>Attested: verifiable receipts for private AI on NEAR. MIT licensed. Code written with AI assistance.</span><span class="hash-inline">sample = recorded demo receipt</span></div>`;
  return pageShell({
    title: 'Attested: verifiable receipts for private AI',
    description: 'Check that an AI answer came from a hardware-sealed model. Offline receipt verifier and Proof Card, anchored on NEAR.',
    body,
    receiptForScript: sample,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(WEB('index.html'), buildIndexHtml());
  console.log('wrote web/index.html');
}
