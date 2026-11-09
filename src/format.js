// Plain-text rendering for the terminal (no dependencies). Colour only on a TTY and without NO_COLOR.
import { STATUS } from './util.js';

const useColor = () => process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : s);
export const bold = (s) => paint('1', s);
export const dim = (s) => paint('2', s);

const COLORS = { [STATUS.VERIFIED]: '32', [STATUS.PRESENT]: '33', [STATUS.FAILED]: '31;1', [STATUS.NOT_RUN]: '36' };
export const statusTag = (status) => paint(COLORS[status] ?? '0', status.padEnd(20));

export function renderChecks(checks, { verbose = false } = {}) {
  const lines = [];
  for (const c of checks) {
    lines.push(`  ${statusTag(c.status)} ${c.label}`);
    if (verbose || c.status !== STATUS.VERIFIED) lines.push(dim(`  ${' '.repeat(20)} ${c.detail}`));
  }
  return lines.join('\n');
}

export function renderTotals(t) {
  return `${t.verified} VERIFIED, ${t.present_not_verified} PRESENT-NOT-VERIFIED, ${t.failed} FAILED, ${t.not_run} NOT-RUN`;
}

export function heading(text) {
  return '\n' + bold(text) + '\n' + dim('-'.repeat(Math.min(text.length, 72)));
}

export function kv(pairs) {
  const w = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `  ${dim(k.padEnd(w))}  ${v}`).join('\n');
}

export function short(hex, n = 16) {
  return hex && hex.length > n + 3 ? hex.slice(0, n) + '...' : hex;
}

export function modeBanner(mode, responseSource) {
  if (mode === 'live' && responseSource === 'live-chat') return 'LIVE: real attestation fetched now, real model answer, real signature';
  if (mode === 'live') return 'LIVE ATTESTATION + RECORDED ANSWER: attestation fetched now; the answer text is a canned fixture';
  return 'RECORDED: real attestation report recorded earlier; the answer text is a canned fixture, not model output';
}


export function wrap(text, width, indent = '') {
  return text
    .split('\n')
    .map((para) => {
      if (!para.trim()) return indent;
      const words = para.split(/\s+/);
      const lines = [];
      let cur = '';
      for (const w of words) {
        if ((cur + ' ' + w).trim().length > width) {
          lines.push(cur);
          cur = w;
        } else cur = (cur + ' ' + w).trim();
      }
      if (cur) lines.push(cur);
      return lines.map((l) => indent + l).join('\n');
    })
    .join('\n');
}
