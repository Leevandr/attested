# Pre-screen self-test (fresh clone, README steps run literally)

Purpose: imitate what the organisers' automated pre-screen does (clone, run the README steps, check that the
project runs and does what the README says), and record what happened, including what could NOT be tested here.

## Method

- `cp -r` of the repository into a new empty directory, then `rm -rf node_modules out attested-out contract/target`
  (a clean copy; no git was used, nothing was cloned from a network). files copied: 68.
- Every command ran under `env -i PATH=... HOME=... NO_COLOR=1`: **no environment variables** (no `NEAR_AI_API_KEY`, no overrides).
- Steps that the README says need no network (2 to 6) ran with a preload (`NODE_OPTIONS=--require no-net.cjs`, a harness
  kept outside the repository) that makes any non-loopback socket or `fetch` inside Node throw. They passed, so those steps really
  use no network. (This blocks Node only; it is not an OS-level firewall, which was not available here.)
- date: 2026-11-09T05:37:53Z  node: v22.23.1  npm: 10.9.8. OS: Linux 6.8. Browser checks: headless Chromium 1248 from the local Playwright cache.
- The test driver script is a harness and is not part of the repository.

## Results

| README step | Command | Network | Result |
|---|---|---|---|
| 1 install | `npm ci` | yes (registry) | exit 0, `added 21 packages`, `found 0 vulnerabilities` |
| 2 tests | `npm test` | blocked | exit 0: 70 tests, 68 pass, 0 fail, 2 skipped (optional network tests) |
| 3 demo | `npm run demo` | blocked | exit 0, recorded mode, answer labelled as canned fixture |
| 4 Proof Card | headless Chromium, click "Re-check in this page" | none needed | rendered result `Result: OK.` |
| 5 verify | `node bin/attested.js verify-receipt out/demo/receipt.json` | blocked | exit 0, `RESULT: OK` |
| 6 tamper | `node scripts/tamper.js ...` then `verify-receipt` | blocked | tamper script exit 0; verify exit **1**, `RESULT: INVALID` |
| 7 live | `npm run demo:live` | yes | exit 0, live attestation (about 2 s), canned answer, labelled |
| 9 anchor | `node bin/attested.js anchor out/demo/receipt.json` | sandbox binary cached | exit 0, duplicate rejected |
| 10 contract | `cd contract && cargo test --locked` | crates cached | exit 0: 19 unit + 10 sandbox integration tests pass |
| 11 web page | headless Chromium on `web/index.html` | none needed | sample shows `Result: OK.`; after "Tamper with the sample": `Result: INVALID.` |

### 1. `npm ci`
```
added 21 packages, and audited 22 packages in 411ms
found 0 vulnerabilities
exit=0
```

### 2. `npm test` (network blocked)
```
ℹ tests 70
ℹ pass 68
ℹ fail 0
ℹ cancelled 0
ℹ skipped 2
exit=0
```

### 3. `npm run demo` (network blocked), abridged
```
attested demo: confidential contract review   [recorded, offline]
Step 1. Send the document to a Confidential TEE model
RECORDED: real attestation report recorded earlier; the answer text is a canned fixture, not model output
Offline: the attestation is a real report recorded on 2026-11-09; the answer text is a canned fixture.
Step 2. The answer (CANNED FIXTURE, not model output)
Step 3. What the receipt proves (every check labelled)
  VERIFIED             report echoes the request nonce (gateway and model)
  NOT-RUN              nonce chosen fresh for this run
  PRESENT-NOT-VERIFIED report names the requested model
  VERIFIED             gateway: Intel TDX quote signature chain
  VERIFIED             gateway: quote commits to the signing key and to our nonce
  VERIFIED             gateway: TD is not in debug mode
  VERIFIED             gateway: boot event log replays to the quote's RTMR0-3
  VERIFIED             gateway: docker-compose manifest hash is in the quote (RTMR3 event and mr_config_id)
  VERIFIED             model: Intel TDX quote signature chain
  VERIFIED             model: quote commits to the signing key and to our nonce
  VERIFIED             model: TD is not in debug mode
  VERIFIED             model: boot event log replays to the quote's RTMR0-3
  VERIFIED             model: docker-compose manifest hash is in the quote (RTMR3 event and mr_config_id)
  VERIFIED             model: deployment action log is bound to a hardware quote (and our nonce)
  VERIFIED             GPU evidence payload carries our nonce
  VERIFIED             NRAS verdict token signature (ES384)
  VERIFIED             NRAS signing certificate chain
  VERIFIED             NVIDIA verdict: overall result true, nonce equals ours
  VERIFIED             8 GPU token(s): signed, digest-bound, nonce match, secure boot on, debug off, measurements ok
  PRESENT-NOT-VERIFIED Intel TCB status, revocation and QE identity
  NOT-RUN              response signature by the TEE key
  Totals  17 VERIFIED, 2 PRESENT-NOT-VERIFIED, 0 FAILED, 2 NOT-RUN
Step 4. Her lawyer re-checks the receipt offline
  VERIFIED             receipt has the expected structure and fields
  VERIFIED             receipt_hash equals SHA-256 of the canonical receipt body
  VERIFIED             attestation.digest equals SHA-256 of the stored evidence
  VERIFIED             request/response text re-hashes to the receipt
  VERIFIED             20 attestation checks re-derived offline from the stored evidence match the receipt
  VERIFIED             totals match the recorded checks
  verify-receipt: OK
Step 5. Tamper test: change one character in the receipt
  FAILED               model id "Qwen..." changed to "Pwen...": verify-receipt says INVALID (receipt.hash, evidence.recheck)
exit=0
```

### 5. `verify-receipt` (network blocked)
```
attested verify-receipt  (offline: no network used)
RESULT: OK. Receipt is intact and its evidence re-verifies offline (17 verified, 2 present-not-verified, 2 not-run).
exit=0
```

### 6. one flipped byte (network blocked)
```
flipped byte 237: "Q" -> "P"; wrote out/demo/tampered.json
exit=0
  FAILED               receipt_hash equals SHA-256 of the canonical receipt body
  FAILED               20 attestation checks re-derived offline from the stored evidence match the receipt
                       model.name: receipt says PRESENT-NOT-VERIFIED, offline re-check says FAILED
RESULT: INVALID. The receipt does not verify. Do not trust it.
exit=1
```

### 7. `npm run demo:live`
```
LIVE ATTESTATION + RECORDED ANSWER: attestation fetched now; the answer text is a canned fixture
No NEAR_AI_API_KEY: the attestation below is fetched live, but the answer text is the canned fixture.
  VERIFIED             nonce chosen fresh for this run
  VERIFIED             NVIDIA verdict: overall result true, nonce equals ours
  VERIFIED             8 GPU token(s): signed, digest-bound, nonce match, secure boot on, debug off, measurements ok
  Totals  18 VERIFIED, 2 PRESENT-NOT-VERIFIED, 0 FAILED, 1 NOT-RUN
exit=0
```

### 9. anchor in the local sandbox
```
  receipt 0dd5fb1586fdd251... verifies offline
  contract wasm 134127 bytes, sha256 4bbafb23d846d36a... (matches contract/artifacts)
  starting a local NEAR sandbox node (first run downloads the node binary, needs network once)...
  register_receipt(0dd5fb1586fdd251...) with 0.01 NEAR attached for storage
  on-chain record: submitter submitter.test.near, model Qwen/Qwen3.8-27B, timestamp_ms 1794202687140
  second registration of the same hash: rejected ("already registered"), as designed
Anchored
  network      local sandbox (ephemeral, not public)
  contract     registry.test.near
  submitter    submitter.test.near
  transaction  5h3MUpmGdebKx1Q3LZnt5Ki1RcKnqon2jqh4dpGo21xA
  block time   2026-11-09T05:38:07.140Z
exit=0
```

### 10. contract tests
```
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.76s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit=0
```

### 4 and 11. browser checks (rendered result block only)
```
Proof Card, after clicking "Re-check in this page":      Result: OK.
Verifier page, sample receipt shown on load:             Result: OK.
Verifier page, after clicking "Tamper with the sample":  Result: INVALID.
```

## What this self-test did NOT cover (be aware)

- **Step 8 (a real NEAR AI answer with an API key) was never run**, here or anywhere: no key was available. The code path is covered by
  unit tests and a local mock gateway only; a real-gateway run may reveal differences.
- The first-run download of the `near-sandbox` node binary (step 9) was not exercised in this session: the binary was already in
  `~/.near-kit`, cached by earlier work on this machine. On a machine without it, step 9 needs internet once.
- The Rust step used a warm crates cache; a cold build takes about 45 s plus the sandbox binary download (the contract agent measured 42 s cold).
- Only Linux, Node 22.23.1 and headless Chromium were used. No macOS, Windows, Firefox or Safari.
- Testnet was not touched (only a read-only smoke test of the RPC path); mainnet was never touched.
- Network blocking was inside Node, not at OS level.
- This file itself was added to the repository after the copy was made; everything else in the tested copy is identical to the
  delivered repository, except that the delivered repository also contains this file.
