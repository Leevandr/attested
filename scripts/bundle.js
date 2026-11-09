// Dependency-free bundler for the isomorphic modules. Concatenates them into one IIFE that
// exposes `window.AttestedCore`, so the Proof Card and the verifier page work from file:// with
// no network and no build tool. Fails loudly if two modules declare the same top-level name.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SRC = (f) => fileURLToPath(new URL(`../src/${f}`, import.meta.url));
export const MODULES = ['util.js', 'der.js', 'trust.js', 'tdx.js', 'nvidia.js', 'attestation.js', 'version.js', 'receipt.js', 'cardview.js'];
const API = ['verifyReceipt', 'verifyEvidence', 'renderCard', 'esc', 'pill', 'STATUS', 'canonicalize', 'sha256Hex', 'groupChecks', 'RECEIPT_SCHEMA', 'TOOL_VERSION'];

export function bundleCore() {
  const seen = new Map();
  const parts = [];
  for (const f of MODULES) {
    let code = readFileSync(SRC(f), 'utf8');
    if (/^import[^;]*$/m.test(code.replace(/^import .*;$/gm, ''))) throw new Error(`${f}: multi-line import not supported`);
    if (/^export \{/m.test(code)) throw new Error(`${f}: "export {" lists not supported`);
    code = code.replace(/^import .*;$/gm, '');
    code = code.replace(/^export (async function|function|const|let|class) /gm, '$1 ');
    for (const m of code.matchAll(/^(?:async function|function|const|let|class) ([A-Za-z0-9_$]+)/gm)) {
      if (seen.has(m[1])) throw new Error(`bundle: "${m[1]}" declared in both ${seen.get(m[1])} and ${f}`);
      seen.set(m[1], f);
    }
    parts.push(`// ---- ${f}\n${code.trim()}\n`);
  }
  for (const n of API) if (!seen.has(n)) throw new Error(`bundle: API name "${n}" not found`);
  return `(function(){\n"use strict";\n${parts.join('\n')}\nwindow.AttestedCore = { ${API.join(', ')} };\n})();\n`;
}
