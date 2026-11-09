// HTML page shell + the self-contained Proof Card (receipt.html). Node only: reads the CSS, fonts and
// page script from web/ and inlines everything, so the file works offline from file://.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bundleCore } from '../scripts/bundle.js';
import { esc, renderCard } from './cardview.js';

const WEB = (f) => fileURLToPath(new URL(`../web/${f}`, import.meta.url));
const b64 = (f) => readFileSync(WEB(f)).toString('base64');

export const LOGO = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5.5c0 4.2-2.9 7.9-7 9.5-4.1-1.6-7-5.3-7-9.5V6l7-3z"/><path d="M8.7 12.2l2.3 2.3 4.4-4.6"/></svg>`;

export function inlineCss() {
  const fonts = `@font-face{font-family:"Inter";src:url(data:font/woff2;base64,${b64('fonts/inter-latin-wght-normal.woff2')}) format("woff2");font-weight:100 900;font-style:normal;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url(data:font/woff2;base64,${b64('fonts/jetbrains-mono-latin-wght-normal.woff2')}) format("woff2");font-weight:100 800;font-style:normal;font-display:swap}`;
  return fonts + '\n' + readFileSync(WEB('style.css'), 'utf8');
}

export function jsonForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export function pageShell({ title, description, body, receiptForScript = null }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<style>${inlineCss()}</style>
</head>
<body>
<div class="wrap">
<header class="bar">
  <a class="brand" href="#">${LOGO}<span>Attested</span></a>
  <div class="bar-right"><button class="icon-btn" id="theme" type="button" aria-label="Toggle light or dark theme"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg></button></div>
</header>
<main>
${body}
</main>
</div>
${receiptForScript ? `<script type="application/json" id="receipt-data">${jsonForScript(receiptForScript)}</script>` : ''}
<script>${bundleCore()}</script>
<script>${readFileSync(WEB('page.js'), 'utf8')}</script>
</body>
</html>
`;
}

export function renderProofCard(receipt) {
  return pageShell({
    title: `Proof Card: ${receipt.model.id}`,
    description: 'Verifiable receipt for a private AI answer: hardware attestation checks, hashes and offline re-verification.',
    body: renderCard(receipt),
    receiptForScript: receipt,
  });
}
