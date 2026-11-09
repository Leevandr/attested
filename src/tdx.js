// Intel TDX quote (v4, ECDSA-P256) parser and signature-chain verifier.
// Pure WebCrypto: runs in Node 22 and in browsers.
//
// WHAT THIS VERIFIES (cryptographically):
//   1. the attestation-key signature over the quote header + TD report body;
//   2. the Quoting Enclave (QE) report binds that attestation key (SHA-256 check);
//   3. the QE report signature, made by the PCK leaf certificate key;
//   4. the PCK certificate chain leaf -> platform CA -> pinned Intel SGX Root CA,
//      each certificate valid at the time of attestation.
// WHAT IT DOES NOT VERIFY (Intel PCS collateral needed, not fetched):
//   - certificate revocation lists, QE identity, TCB info / TCB status (UpToDate, OutOfDate, Revoked).
// Layout reference: Intel TDX DCAP Quote Generation Library, quote format v4.

import { certSignedBy, importEcPublicKey, parseCertificate, pemBlocks } from './der.js';
import { bytesEqual, bytesToHex, concatBytes, fromUtf8, hexToBytes, readU16LE, readU32LE, sha256 } from './util.js';
import { INTEL_SGX_ROOT_CA_PEM } from './trust.js';

const HEADER_LEN = 48;
const BODY_LEN = 584;

export function parseQuote(quoteHex) {
  const q = typeof quoteHex === 'string' ? hexToBytes(quoteHex) : quoteHex;
  if (q.length < HEADER_LEN + BODY_LEN + 4) throw new Error('quote too short');
  const version = readU16LE(q, 0);
  const attKeyType = readU16LE(q, 2);
  const teeType = readU32LE(q, 4);
  if (version !== 4) throw new Error(`unsupported quote version ${version} (only v4 is supported)`);
  if (teeType !== 0x81) throw new Error(`not a TDX quote (tee type 0x${teeType.toString(16)})`);
  if (attKeyType !== 2) throw new Error(`unsupported attestation key type ${attKeyType}`);

  const b = q.subarray(HEADER_LEN, HEADER_LEN + BODY_LEN);
  let o = 0;
  const take = (n) => {
    const v = b.subarray(o, o + n);
    o += n;
    return v;
  };
  const body = {
    teeTcbSvn: take(16),
    mrSeam: take(48),
    mrSignerSeam: take(48),
    seamAttributes: take(8),
    tdAttributes: take(8),
    xfam: take(8),
    mrTd: take(48),
    mrConfigId: take(48),
    mrOwner: take(48),
    mrOwnerConfig: take(48),
    rtmr: [take(48), take(48), take(48), take(48)],
    reportData: take(64),
  };

  const sigLen = readU32LE(q, HEADER_LEN + BODY_LEN);
  const sd = q.subarray(HEADER_LEN + BODY_LEN + 4);
  if (sd.length < sigLen || sigLen < 128 + 6) throw new Error('signature data truncated');
  const ecdsaSignature = sd.subarray(0, 64);
  const attestationKey = sd.subarray(64, 128);
  let p = 128;
  const certType = readU16LE(sd, p);
  const certSize = readU32LE(sd, p + 2);
  p += 6;
  if (certType !== 6) throw new Error(`unsupported certification data type ${certType} (expected 6, QE report)`);
  const cd = sd.subarray(p, p + certSize);
  if (cd.length < 450) throw new Error('certification data truncated');
  const qeReport = cd.subarray(0, 384);
  const qeReportSignature = cd.subarray(384, 448);
  const authSize = readU16LE(cd, 448);
  const qeAuthData = cd.subarray(450, 450 + authSize);
  let c = 450 + authSize;
  const innerType = readU16LE(cd, c);
  const innerSize = readU32LE(cd, c + 2);
  c += 6;
  if (innerType !== 5) throw new Error(`unsupported inner certification data type ${innerType} (expected 5, PCK chain)`);
  const pem = fromUtf8(cd.subarray(c, c + innerSize)).replace(/\0+$/, '');

  return {
    bytes: q,
    version,
    teeType,
    signedBytes: q.subarray(0, HEADER_LEN + BODY_LEN),
    body,
    ecdsaSignature,
    attestationKey,
    qeReport,
    qeReportSignature,
    qeAuthData,
    pckChainPem: pem,
  };
}

// Verify the signature chain of a quote. `validAt` is the time at which certificate validity
// is evaluated (the attestation time; NOT "now", so old recorded receipts stay checkable).
export async function verifyQuoteSignatures(quoteHex, { validAt = new Date(), rootPem = INTEL_SGX_ROOT_CA_PEM } = {}) {
  const steps = [];
  const step = (name, ok, detail = '') => steps.push({ name, ok, detail });
  let parsed;
  try {
    parsed = parseQuote(quoteHex);
  } catch (e) {
    return { ok: false, parsed: null, steps: [{ name: 'parse quote', ok: false, detail: e.message }] };
  }
  step('parse quote (v4, TDX, ECDSA-P256)', true);
  const subtle = globalThis.crypto.subtle;
  const p256 = { name: 'ECDSA', namedCurve: 'P-256' };

  try {
    // 1. attestation key signs header||body
    const akKey = await subtle.importKey('raw', concatBytes(new Uint8Array([4]), parsed.attestationKey), p256, false, ['verify']);
    const sigOk = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, akKey, parsed.ecdsaSignature, parsed.signedBytes);
    step('attestation key signature over header + TD report', sigOk);

    // 2. QE report data = SHA-256(attestation key || QE auth data) (first 32 bytes)
    const qeReportData = parsed.qeReport.subarray(320, 384);
    const expected = await sha256(concatBytes(parsed.attestationKey, parsed.qeAuthData));
    step('QE report binds the attestation key', bytesEqual(qeReportData.subarray(0, 32), expected));

    // 3. PCK chain
    const der = pemBlocks(parsed.pckChainPem);
    if (der.length < 2) throw new Error(`PCK chain has ${der.length} certificate(s), expected 2 or 3`);
    const certs = der.map(parseCertificate);
    const root = parseCertificate(pemBlocks(rootPem)[0]);
    const leaf = certs[0];

    // 3a. QE report signature by PCK leaf key
    const leafKey = await importEcPublicKey(leaf.publicKey, leaf.curveOid);
    const qeSigOk = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, leafKey, parsed.qeReportSignature, parsed.qeReport);
    step('QE report signature by PCK leaf certificate', qeSigOk);

    // 3b. chain leaf -> ... -> pinned root
    let chainOk = true;
    let detail = '';
    for (let i = 0; i < certs.length; i++) {
      const issuer = i + 1 < certs.length ? certs[i + 1] : root;
      if (!(await certSignedBy(certs[i], issuer))) {
        chainOk = false;
        detail = `certificate ${i} (${certs[i].subjectCN}) is not signed by ${issuer.subjectCN}`;
        break;
      }
    }
    // The chain may or may not include the root itself; if it does it must equal the pinned root.
    if (chainOk && certs.length >= 3) {
      const last = certs[certs.length - 1];
      if (!bytesEqual(last.der, root.der)) {
        chainOk = false;
        detail = 'the root certificate inside the quote is not the pinned Intel SGX Root CA';
      }
    }
    if (chainOk && !(await certSignedBy(root, root))) {
      chainOk = false;
      detail = 'pinned root certificate failed its self-signature check';
    }
    step('PCK chain leaf -> platform CA -> pinned Intel SGX Root CA', chainOk, detail);

    // 3c. validity windows
    const t = validAt.getTime();
    const chainForTime = certs.length >= 3 ? certs : [...certs, root];
    const expired = chainForTime.filter((c) => t < c.notBefore.getTime() || t > c.notAfter.getTime());
    step('certificates valid at attestation time', expired.length === 0, expired.map((c) => c.subjectCN + ' ' + c.notBefore.toISOString() + ' to ' + c.notAfter.toISOString()).join('; '));
  } catch (e) {
    step('signature chain', false, e.message);
  }
  return { ok: steps.every((s) => s.ok), parsed, steps };
}

export function describeQuote(parsed) {
  const b = parsed.body;
  return {
    mrTd: bytesToHex(b.mrTd),
    mrConfigId: bytesToHex(b.mrConfigId),
    rtmr: b.rtmr.map(bytesToHex),
    reportData: bytesToHex(b.reportData),
    tdAttributes: bytesToHex(b.tdAttributes),
    debug: (b.tdAttributes[0] & 1) === 1,
  };
}
