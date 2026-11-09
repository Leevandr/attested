// NVIDIA GPU attestation: send the evidence in `nvidia_payload` to NVIDIA's Remote Attestation
// Service (NRAS), then verify the signed answer ourselves.
//
// Logic follows the official NEAR AI verifiers (near-examples/nearai-cloud-verification-example,
// MIT, and nearai/nearai-cloud-verifier): POST the payload to NRAS, read the overall JWT, check
// `x-nvidia-overall-att-result` and that `eat_nonce` equals our nonce. On top of that this module
// verifies the ES384 token signature against the NRAS signing certificate (x5c) and that
// certificate's issuer against pinned NVIDIA intermediates, and re-computes the per-GPU token digests.
//
// The GPU evidence itself (SPDM reports, certificate chains, RIM measurements) is judged by
// NVIDIA's service, not re-implemented here: we verify NVIDIA's signed verdict, not the raw evidence.

import { certSignedBy, importEcPublicKey, parseCertificate } from './der.js';
import { STATUS, base64ToBytes, check, fromUtf8, sha256Hex, utf8 } from './util.js';
import { NVIDIA_NRAS_INTERMEDIATES } from './trust.js';

export const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
export const NRAS_JWKS_URL = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';
const NRAS_ISSUER = 'https://nras.attestation.nvidia.com';

export function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  return {
    header: JSON.parse(fromUtf8(base64ToBytes(parts[0]))),
    payload: JSON.parse(fromUtf8(base64ToBytes(parts[1]))),
    signingInput: utf8(parts[0] + '.' + parts[1]),
    signature: base64ToBytes(parts[2]),
  };
}

// NRAS response shape: [["JWT", overallToken], {"GPU-0": token, ...}]
export function splitNrasResponse(resp) {
  if (!Array.isArray(resp) || !Array.isArray(resp[0]) || typeof resp[0][1] !== 'string') throw new Error('unexpected NRAS response shape');
  return { overall: resp[0][1], gpus: resp[1] && typeof resp[1] === 'object' ? resp[1] : {} };
}

async function verifyEs384(token, leaf) {
  const jwt = decodeJwt(token);
  const key = await importEcPublicKey(leaf.publicKey, leaf.curveOid);
  const ok = jwt.signature.length === 96 && (await globalThis.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, jwt.signature, jwt.signingInput));
  return { jwt, ok };
}

export async function fetchNras(nvidiaPayload, fetchImpl = fetch) {
  const body = typeof nvidiaPayload === 'string' ? nvidiaPayload : JSON.stringify(nvidiaPayload);
  const res = await fetchImpl(NRAS_URL, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body });
  if (!res.ok) throw new Error(`NRAS HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

export async function fetchNrasJwk(kid, fetchImpl = fetch) {
  const res = await fetchImpl(NRAS_JWKS_URL, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`NRAS JWKS HTTP ${res.status}`);
  const jwks = await res.json();
  const jwk = (jwks.keys || []).find((k) => k.kid === kid);
  if (!jwk) throw new Error(`NRAS JWKS has no key ${kid}`);
  return jwk;
}

// Verify an NRAS answer. Returns a list of checks plus a summary of what NVIDIA reported.
//   nras:  the raw NRAS response; jwk: the JWKS entry (with x5c) for the token's kid.
//   nonce: the request nonce the evidence must be bound to.
//   validAt: time at which token + certificate validity are evaluated.
//   enforceExpiry: true for a fresh live run (token must not be expired right now).
export async function verifyNras({ nras, jwk, nonce, validAt, enforceExpiry = false }) {
  const checks = [];
  const info = { gpuCount: 0 };
  try {
    const { overall, gpus } = splitNrasResponse(nras);
    const jwt = decodeJwt(overall);
    if (jwt.header.alg !== 'ES384') throw new Error('unexpected token algorithm ' + jwt.header.alg);
    if (!jwk || jwk.kid !== jwt.header.kid) throw new Error('token key id does not match the supplied NRAS signing key');
    if (!Array.isArray(jwk.x5c) || jwk.x5c.length < 2) throw new Error('signing key has no certificate chain');
    const leaf = parseCertificate(base64ToBytes(jwk.x5c[0]));
    const inter = parseCertificate(base64ToBytes(jwk.x5c[1]));

    // 1. signature of the overall token
    const sig = await verifyEs384(overall, leaf);
    checks.push(check('nras.signature', 'NRAS verdict token signature (ES384)', sig.ok ? STATUS.VERIFIED : STATUS.FAILED, sig.ok ? 'signature valid under the NRAS signing certificate' : 'signature does NOT verify'));

    // 2. certificate chain, anchored on pinned intermediates
    const leafOk = await certSignedBy(leaf, inter);
    const interFp = await sha256Hex(inter.der);
    const pinned = Object.prototype.hasOwnProperty.call(NVIDIA_NRAS_INTERMEDIATES, interFp);
    const t = validAt.getTime();
    const leafTimeOk = t >= leaf.notBefore.getTime() && t <= leaf.notAfter.getTime();
    let chainStatus = STATUS.VERIFIED;
    let chainDetail = `leaf signed by ${inter.subjectCN}, which is pinned in this repo`;
    if (!leafOk) {
      chainStatus = STATUS.FAILED;
      chainDetail = 'signing certificate is not signed by the listed intermediate';
    } else if (!leafTimeOk) {
      chainStatus = STATUS.FAILED;
      chainDetail = `signing certificate not valid at ${validAt.toISOString()}`;
    } else if (!pinned) {
      chainStatus = STATUS.PRESENT;
      chainDetail = `signing certificate chains to "${inter.subjectCN}" (sha256 ${interFp.slice(0, 16)}...), which is not one of the pinned NVIDIA intermediates`;
    }
    checks.push(check('nras.chain', 'NRAS signing certificate chain', chainStatus, chainDetail));

    // 3. claims
    const c = jwt.payload;
    const claimProblems = [];
    if (c.iss !== NRAS_ISSUER) claimProblems.push('issuer is ' + c.iss);
    if (c['x-nvidia-overall-att-result'] !== true) claimProblems.push('overall attestation result is not true');
    if (typeof c.eat_nonce !== 'string' || c.eat_nonce.toLowerCase() !== nonce.toLowerCase()) claimProblems.push('eat_nonce does not equal the request nonce');
    const iat = (c.iat ?? c.nbf) * 1000;
    const exp = c.exp * 1000;
    if (enforceExpiry && !(t >= iat - 60000 && t <= exp)) claimProblems.push('token is not valid right now');
    if (!enforceExpiry && !(t >= iat - 60000 && t <= exp)) claimProblems.push('token validity window does not include the attestation time ' + validAt.toISOString());
    checks.push(check('nras.claims', 'NVIDIA verdict: overall result true, nonce equals ours', claimProblems.length ? STATUS.FAILED : STATUS.VERIFIED, claimProblems.length ? claimProblems.join('; ') : `x-nvidia-overall-att-result=true, eat_nonce=${nonce.slice(0, 12)}...`));
    info.issuedAt = new Date(iat).toISOString();
    info.expiresAt = new Date(exp).toISOString();

    // 4. per-GPU tokens
    const names = Object.keys(c.submods || {});
    const gpuProblems = [];
    for (const name of names) {
      const tok = gpus[name];
      if (typeof tok !== 'string') {
        gpuProblems.push(name + ': token missing');
        continue;
      }
      const digest = c.submods[name]?.[1]?.[1];
      if ((await sha256Hex(tok)) !== digest) gpuProblems.push(name + ': digest does not match overall token');
      const g = decodeJwt(tok);
      const gs = await verifyEs384(tok, leaf);
      if (g.header.kid !== jwk.kid || !gs.ok) gpuProblems.push(name + ': token signature not verified');
      const p = g.payload;
      if (p['x-nvidia-gpu-attestation-report-nonce-match'] !== true) gpuProblems.push(name + ': GPU report nonce mismatch');
      if (p.measres !== 'success') gpuProblems.push(name + ': measurements ' + p.measres);
      if (p.secboot !== true) gpuProblems.push(name + ': secure boot off');
      if (p.dbgstat !== 'disabled') gpuProblems.push(name + ': debug ' + p.dbgstat);
      info.hwmodel = p.hwmodel;
      info.driverVersion = p['x-nvidia-gpu-driver-version'];
      info.vbios = p['x-nvidia-gpu-vbios-version'];
    }
    info.gpuCount = names.length;
    const gpuOk = names.length > 0 && gpuProblems.length === 0;
    checks.push(check('nras.gpus', `${names.length} GPU token(s): signed, digest-bound, nonce match, secure boot on, debug off, measurements ok`, gpuOk ? STATUS.VERIFIED : STATUS.FAILED, gpuOk ? `${info.hwmodel}, driver ${info.driverVersion}` : gpuProblems.slice(0, 4).join('; ') || 'no GPU tokens'));
  } catch (e) {
    checks.push(check('nras.error', 'NVIDIA NRAS verdict', STATUS.FAILED, e.message));
  }
  return { checks, info };
}

export function nvidiaPayloadSummary(payloadString) {
  const p = JSON.parse(payloadString);
  return { nonce: p.nonce, arch: p.arch, gpuCount: Array.isArray(p.evidence_list) ? p.evidence_list.length : 0 };
}
