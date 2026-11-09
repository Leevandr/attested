#!/usr/bin/env node
// Flip ONE byte of a receipt, to show that verify-receipt notices.
//   node scripts/tamper.js IN.json OUT.json            flips the first character of the model id
//   node scripts/tamper.js IN.json OUT.json --offset N flips the lowest bit of byte N
import { readFileSync, writeFileSync } from 'node:fs';

const [inFile, outFile, flag, value] = process.argv.slice(2);
if (!inFile || !outFile) {
  console.error('usage: node scripts/tamper.js IN.json OUT.json [--offset N]');
  process.exit(2);
}
const buf = Buffer.from(readFileSync(inFile));
let pos;
if (flag === '--offset') pos = Number(value);
else {
  const text = buf.toString('utf8');
  const m = text.indexOf('"model"');
  const id = m < 0 ? -1 : text.indexOf('"id": "', m);
  if (id < 0) {
    console.error('could not find the model id; use --offset N');
    process.exit(2);
  }
  pos = Buffer.byteLength(text.slice(0, id + '"id": "'.length));
}
if (!(pos >= 0 && pos < buf.length)) {
  console.error('offset out of range');
  process.exit(2);
}
const before = buf[pos];
buf[pos] = before ^ 0x01;
writeFileSync(outFile, buf);
console.log(`flipped byte ${pos}: ${JSON.stringify(String.fromCharCode(before))} -> ${JSON.stringify(String.fromCharCode(buf[pos]))}; wrote ${outFile}`);
