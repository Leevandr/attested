# Submission (ready to paste)

Do not submit anything from this file automatically. The owner submits the form by hand after
creating the public repository and the X demo post. Nothing here contains personal data.

## Project name

Attested

## One line

Anyone can check that an AI answer really came from a hardware-sealed (TEE) model, and the proof lives on NEAR.

## Tracks (tick these two in the form)

- Privacy & Private AI (`privacy`) - primary
- AI Security & Defense (`security`)

## Description (paste into the form; 1508 characters, limit 20 to 2000)

```
Attested makes private AI auditable. Confidential AI on NEAR AI Cloud runs inside hardware enclaves that can prove what they are, but that proof is a 270 KB blob of quotes and certificates nobody reads. Attested fetches the live attestation (no API key, fresh random nonce), runs the cryptographic checks itself, and produces a portable receipt plus a self-contained Proof Card.

Verified on real NEAR AI Cloud data: the Intel TDX quote signature chain up to a pinned Intel root; the quote commits to the enclave's signing key and our nonce, so replayed reports fail; the boot log replays to the measured registers; the Docker manifest hash is hardware-measured; NVIDIA's signed verdict for the GPUs. Every check is labelled VERIFIED, PRESENT-NOT-VERIFIED, FAILED or NOT-RUN, and the README lists what is not checked (Intel TCB collateral, audited-build comparison).

verify-receipt re-checks a receipt fully offline, re-running the cryptography on the evidence inside it; flip one byte and it fails. A static page does the same in the browser. The receipt hash is anchored in a Rust NEAR contract (near-sdk-rs 5.30.1, write-once, caller pays storage, 29 tests).

Demo: a fictional confidential contract review. npm ci && npm run demo works offline in labelled recorded mode (real recorded attestation, canned answer). npm run demo:live fetches a fresh attestation. Honest limits: the real-key chat path was not run against the live gateway; the contract ran only on a local sandbox; nothing touched mainnet.
```

## Fields the owner must fill in himself

| Field | Status |
|---|---|
| Project lead name, email, team size | owner |
| NEAR mainnet account for the payout (named or 64-character implicit account) | owner |
| Public repository URL | owner creates the public GitHub repository (nothing was pushed or published by the author) |
| Public X demo post URL (with video; see `docs/DEMO_SCRIPT.md`) | owner records and posts |
| Consent checkboxes | owner |
| Optional: a NEAR AI Cloud API key, to record a real signed answer for the video | owner (never commit it) |

## Facts to keep consistent with the README

- Contract: Rust, `near-sdk-rs` 5.30.1, 19 unit tests + 10 sandbox integration tests, run only on a local sandbox. Not deployed to testnet or mainnet.
- Tests: `npm test` runs 70 tests offline (68 pass, 2 optional network tests skipped).
- Recorded mode uses a real attestation report recorded on 2026-11-09 and a canned answer; every output says so.
- AI-written code is disclosed in the README together with the list of third-party code and templates.
