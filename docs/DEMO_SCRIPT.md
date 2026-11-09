# Demo video script (60 to 90 seconds)

Goal: one complete moment, led by the user problem. Record the terminal at a readable font size
(about 18 pt) and a browser window. No narration of install steps. Total target: 80 seconds.
Say "recorded" out loud when it is recorded; the on-screen labels already say it.

| Time | Screen | Say (voice-over or caption) |
|---|---|---|
| 0:00 to 0:08 | Title card: "Attested: proof that a private AI really ran in a sealed enclave". Under it, the fictional contract (`demo/contract-review/services-agreement.txt`) with the bank line highlighted. | "A freelancer must send a contract with her bank details to an AI. Privacy promises are just promises. How does anyone check?" |
| 0:08 to 0:18 | Terminal: `npm run demo`. The story and the answer scroll by; stop on "Step 3". | "Attested sends it only to a confidential model on NEAR AI Cloud and keeps a receipt. This run is recorded mode, so the tool labels the answer as a canned fixture." |
| 0:18 to 0:35 | Slow scroll through the check list: VERIFIED rows, then the amber PRESENT-NOT-VERIFIED and NOT-RUN rows. Pause on the totals line. | "Every check has one of four labels. Intel's hardware signatures, the enclave key, the boot log, the container manifest, NVIDIA's verdict for eight GPUs: verified here, with real cryptography. What we could not verify is labelled, not hidden." |
| 0:35 to 0:50 | Terminal: `node bin/attested.js verify-receipt out/demo/receipt.json` (green, exit 0). Then `node scripts/tamper.js out/demo/receipt.json out/demo/tampered.json` and verify again: red `INVALID`, `exit code: 1`. | "Her lawyer re-checks the receipt offline. One flipped byte, and it fails." |
| 0:50 to 1:05 | Browser: open `out/demo/receipt.html` (the Proof Card), light then dark theme; click "Re-check in this page" and show `Result: OK`. Show the mobile width briefly. | "The Proof Card works from a file. The browser re-runs the cryptography, no server, nothing uploaded." |
| 1:05 to 1:15 | Terminal: `node bin/attested.js anchor out/demo/receipt.json`; stop on "second registration of the same hash: rejected". | "The receipt's hash is anchored in a small Rust contract on NEAR: write once, the caller pays storage. This is a local sandbox; nothing is public." |
| 1:15 to 1:20 | End card: "Live mode: npm run demo:live fetches a fresh attestation. Not proven: Intel TCB status, audited-build match. MIT." plus the repo link. | "Live mode fetches a fresh attestation in two seconds. The README lists exactly what is and is not proven." |

Recording notes:

- Run `npm run demo` once beforehand so `out/demo/receipt.html` exists; the anchor step needs the sandbox binary to be downloaded already (run `node bin/attested.js anchor out/demo/receipt.json` once before recording).
- If you have a NEAR AI key, an optional extra shot (not required, not part of the 80 s): `node bin/attested.js ask --file demo/contract-review/services-agreement.txt "Review this contract."` and show `response signature by the model TEE key: VERIFIED`. The author never ran this against the real gateway, so rehearse it first and do not put it in the video if anything is `FAILED`.
- Post text suggestion (the owner posts it): lead with the problem ("You can't punish an AI, but you can check what ran."), show one complete moment (the tamper test), link the repo, tag the tracks. No claims beyond the README.
