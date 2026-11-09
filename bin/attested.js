#!/usr/bin/env node
import { main } from '../src/cli.js';

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
    process.exitCode = 2;
  },
);
