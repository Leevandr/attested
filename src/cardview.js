// Proof Card markup. Isomorphic: a pure function from a receipt object to an HTML string,
// used by the CLI (receipt.html) and by the browser verifier page.

import { STATUS } from './util.js';

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

const PILL = { [STATUS.VERIFIED]: 'ok', [STATUS.PRESENT]: 'warn', [STATUS.FAILED]: 'bad', [STATUS.NOT_RUN]: 'idle' };
export const pill = (status) => `<span class="pill ${PILL[status] || 'idle'}">${esc(status)}</span>`;

function midTruncate(s, head = 14, tail = 10) {
  return s && s.length > head + tail + 3 ? `${s.slice(0, head)}...${s.slice(-tail)}` : s;
}

function hashRow(label, value, { truncate = false, plain = false } = {}) {
  if (!value) return `<div><dt>${esc(label)}</dt><dd><span class="v plain">none</span></dd></div>`;
  const shown = truncate ? midTruncate(value, 18, 12) : value;
  return `<div><dt>${esc(label)}</dt><dd><span class="v${plain ? ' plain' : ''}" title="${esc(value)}">${esc(shown)}</span><button class="copy" type="button" data-copy="${esc(value)}">Copy</button></dd></div>`;
}

const GROUPS = [
  ['Freshness and identity', 'Is the evidence fresh, and for the model we asked about?', (id) => id.startsWith('nonce.') || id.startsWith('model.')],
  ['Intel TDX: gateway enclave', 'The gateway that routes requests', (id) => /^tdx\.(quote|report_data|debug|rtmr|compose)\.gateway$/.test(id)],
  ['Intel TDX: model enclave', 'The confidential VM that runs the model', (id) => /^tdx\.(quote|report_data|debug|rtmr|compose)\.model$/.test(id) || id === 'compose_manager'],
  ['NVIDIA GPUs', 'Confidential-computing GPUs, judged by NVIDIA\'s attestation service', (id) => id.startsWith('nvidia.') || id.startsWith('nras.')],
  ['Response', 'Does the answer come from the attested key?', (id) => id.startsWith('response.')],
  ['Known gaps', 'Things this tool does not evaluate', (id) => id === 'tdx.collateral'],
];

export function groupChecks(checks) {
  const used = new Set();
  const out = [];
  for (const [title, hint, test] of GROUPS) {
    const items = checks.filter((c) => !used.has(c) && test(c.id));
    items.forEach((c) => used.add(c));
    if (items.length) out.push({ title, hint, items });
  }
  const rest = checks.filter((c) => !used.has(c));
  if (rest.length) out.push({ title: 'Other', hint: '', items: rest });
  return out;
}

function stat(n, label, cls) {
  return `<div class="stat ${n === 0 ? 'zero' : cls}"><b>${n}</b><span>${esc(label)}</span></div>`;
}

function verdictText(receipt) {
  const t = receipt.totals;
  const sig = receipt.checks.find((c) => c.id === 'response.signature');
  const hw = receipt.checks.filter((c) => /^(tdx\.quote\.|nras\.signature)/.test(c.id));
  const hwOk = hw.length > 0 && hw.every((c) => c.status === STATUS.VERIFIED);
  if (t.failed > 0) return '<strong>At least one check FAILED.</strong> <em>Treat this as evidence that something did not hold up; the failed rows below say what.</em>';
  let s = hwOk ? '<strong>The enclave\'s hardware evidence verifies.</strong> ' : '<strong>Evidence is incomplete.</strong> ';
  if (!receipt.response) s += '<em>This receipt covers the attestation only; no request or answer is attached.</em>';
  else if (sig?.status === STATUS.VERIFIED) s += `<em>The answer is signed by a key that a hardware quote commits to${sig.signature_kind === 'gateway' ? ' (the gateway TEE key, not the model TEE key)' : ''}.</em>`;
  else s += '<em>No response signature is verified, so this receipt does not tie the answer to the enclave.</em>';
  return s;
}

function exchangeBlock(receipt) {
  const ex = receipt.exchange;
  if (!ex) return '';
  const part = (title, body) => {
    if (typeof body !== 'string') return '';
    let shown = body;
    try {
      const j = JSON.parse(body);
      const msgs = j.messages ?? null;
      const answer = j.choices?.[0]?.message?.content;
      if (msgs) shown = msgs.map((m) => `[${m.role}]\n${m.content}`).join('\n\n');
      else if (typeof answer === 'string') shown = answer;
    } catch {
      /* show raw */
    }
    return `<details class="text"><summary>${esc(title)}</summary><pre>${esc(shown)}</pre></details>`;
  };
  return part('Show the request text (hashed above)', ex.request_body) + part('Show the answer text (hashed above)', ex.response_body);
}

function runsBlock(receipt) {
  const s = receipt.summary || {};
  const rows = [];
  if (s.model_name) rows.push(['Model', s.model_name, false, true]);
  if (s.compose_up) rows.push(['Deployed from', `${s.compose_up.file} at ${s.compose_up.tag}, commit ${String(s.compose_up.commit).slice(0, 10)}`, false, true]);
  if (s.model_compose_hash) rows.push(['Compose manifest', s.model_compose_hash, true]);
  if (s.os_image_hash) rows.push(['OS image hash', s.os_image_hash, true]);
  if (s.model_mr_td) rows.push(['TD measurement', s.model_mr_td, true]);
  if (s.gpu) rows.push(['GPUs', `${s.gpu.gpuCount} x ${s.gpu.hwmodel}, driver ${s.gpu.driverVersion}, secure boot on, debug off`, false, true]);
  if (s.model_images?.length) rows.push(['Container images', `${s.model_images.length} images pinned by digest in the attested manifest`, false, true]);
  if (!rows.length) return '';
  return `<section class="card"><h2>What the enclave says it runs</h2><p class="lede">Values below are committed to by the verified quotes. They identify the software; comparing them to an audited build is up to you.</p><dl class="kv">${rows.map(([k, v, h, plain]) => hashRow(k, v, { truncate: h, plain: plain })).join('')}</dl></section>`;
}

function anchorBlock(receipt) {
  const a = receipt.anchor;
  if (!a) {
    return `<section class="card"><h2>Anchor on NEAR</h2><p class="lede">Not anchored yet. Anchoring stores this receipt's hash in a public contract so anyone can later prove it existed, unchanged, at that time.</p><code class="cmd">node bin/attested.js anchor receipt.json</code></section>`;
  }
  const net = a.network === 'sandbox' ? 'local sandbox (not a public network)' : a.network;
  return `<section class="card"><h2>Anchor on NEAR</h2><p class="lede">The receipt hash was registered in the receipt-registry contract. This record is not checked offline; re-query the chain to confirm it.</p><dl class="kv">${hashRow('Network', net, { plain: true })}${hashRow('Contract', a.contract, { plain: true })}${hashRow('Submitter', a.submitter, { plain: true })}${hashRow('Transaction', a.tx_hash)}${hashRow('Block time', a.registered_at, { plain: true })}</dl></section>`;
}

const SEAL_OK = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.2 4.2L19 7"/></svg>';
const SEAL_BAD = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 6v7M12 17.5v.5"/></svg>';

export function renderCard(receipt, { verifyUi = true } = {}) {
  const live = receipt.mode === 'live';
  const answerFixture = receipt.response?.source === 'recorded-fixture';
  const tierOk = receipt.model.tier === 'Confidential TEE';
  const t = receipt.totals;
  const recordedNotice = receipt.mode === 'recorded' || answerFixture;
  const modeText = live ? (answerFixture ? 'Live attestation' : 'Live') : 'Recorded';
  const groups = groupChecks(receipt.checks)
    .map(
      (g) =>
        `<div class="group"><h3>${esc(g.title)} <small>${esc(g.hint)}</small></h3>${g.items
          .map((c) => `<div class="row"><div class="pillcell">${pill(c.status)}</div><div><div class="t">${esc(c.label)}</div><div class="d">${esc(c.detail)}</div></div></div>`)
          .join('')}</div>`,
    )
    .join('');
  return `
<section class="card hero">
  <div class="seal ${t.failed > 0 ? 'bad' : 'ok'}" title="${t.failed > 0 ? 'At least one check failed' : 'No check failed'}">${t.failed > 0 ? SEAL_BAD : SEAL_OK}</div>
  <p class="eyebrow">Proof Card &middot; attested v${esc(receipt.tool.version)}</p>
  <h1>${esc(receipt.model.id)}</h1>
  <p class="sub"><span class="tier ${tierOk ? '' : 'bad'}">${esc(receipt.model.tier)}</span><span class="pill ${live ? 'mode-live' : 'mode-rec'}">${esc(modeText)}</span><span class="mono" style="color:var(--ink-3)">${esc(receipt.created_at.replace('T', ' ').replace(/\.\d+Z$/, ' UTC'))}</span></p>
  <div class="stats">${stat(t.verified, 'checks verified', 'ok')}${stat(t.present_not_verified, 'present, not verified', 'warn')}${stat(t.failed, 'failed', 'bad')}${stat(t.not_run, 'not run in this mode', 'idle')}</div>
  <p class="verdict">${verdictText(receipt)}</p>
  ${
    recordedNotice
      ? `<div class="notice warn"><strong>${answerFixture ? 'The answer text is a canned fixture' : 'Recorded evidence'}.</strong> ${
          receipt.mode === 'recorded' ? `The attestation was recorded on ${esc((receipt.attestation.source.recorded_at || receipt.attestation.fetched_at).slice(0, 10))} and replayed; its nonce is not fresh.` : 'The attestation was fetched live for this run.'
        } ${answerFixture ? 'No model produced the answer and no response signature exists. Run with a NEAR AI key for a real signed answer.' : ''}</div>`
      : ''
  }
</section>

<section class="card">
  <h2>The exchange</h2>
  <p class="lede">Only hashes are needed to verify a receipt. The text stays private unless you share it.</p>
  <dl class="kv">
    ${hashRow('Request SHA-256', receipt.request?.sha256, { truncate: true })}
    ${hashRow('Response SHA-256', receipt.response?.sha256, { truncate: true })}
    ${hashRow('Nonce', receipt.nonce, { truncate: true })}
    ${hashRow('Attestation digest', receipt.attestation.digest, { truncate: true })}
    ${hashRow('Receipt hash', receipt.receipt_hash, { truncate: true })}
  </dl>
  ${exchangeBlock(receipt)}
</section>

<section class="card">
  <h2>What was checked</h2>
  <p class="lede">Every row is one of four labels. VERIFIED means we ran the cryptographic check ourselves. PRESENT-NOT-VERIFIED means the data is there but this tool did not prove it. NOT-RUN means the check does not apply in this mode.</p>
  ${groups}
</section>

${runsBlock(receipt)}
${anchorBlock(receipt)}

${
  verifyUi
    ? `<section class="card" id="verify">
  <h2>Verify it yourself</h2>
  <p class="lede">Do not trust this page. Re-derive everything from the raw evidence stored in the receipt.</p>
  <ol class="steps">
    <li>Click the button: this page re-hashes the receipt, re-computes the attestation digest, and re-verifies the Intel quote signatures and the NVIDIA verdict token in your browser, with no network.<div class="row-actions" style="justify-content:flex-start"><button class="btn" id="recheck" type="button">Re-check in this page</button></div><div class="out" id="recheck-out"></div></li>
    <li>Or run the same re-check on the command line, offline:<code class="cmd">node bin/attested.js verify-receipt receipt.json</code></li>
  </ol>
</section>`
    : ''
}

<section class="card">
  <h2>What this does not prove</h2>
  <ul class="limit-list">
    <li>Intel TCB status, revocation lists and QE identity are not evaluated (needs Intel PCS collateral). The quote signatures verify; that the platform firmware is current is not checked.</li>
    <li>The NVIDIA verdict is checked against NVIDIA's signed token. The raw GPU evidence is judged by NVIDIA's service, not re-implemented here, and the NVIDIA root CA itself is not pinned (two intermediates are).</li>
    <li>The software identity (compose hash, images) is shown, not compared to an audited build.</li>
    <li>Streaming answers are signed by the gateway, not the model TEE; this tool only handles non-streaming requests.</li>
    <li>A receipt proves what ran and what was signed. It does not prove the answer is correct.</li>
  </ul>
</section>
<div class="foot"><span>attested v${esc(receipt.tool.version)} &middot; schema ${esc(receipt.schema)}</span><span class="hash-inline">receipt ${esc(midTruncate(receipt.receipt_hash, 16, 8))}</span></div>`;
}
