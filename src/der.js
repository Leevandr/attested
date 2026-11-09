// Minimal DER / X.509 reader. Just enough to verify the Intel PCK and NVIDIA token
// certificate chains with WebCrypto (which cannot parse certificates itself).
// It extracts: the to-be-signed bytes, the signature, validity, names and the public key.
// It does NOT interpret extensions (no basicConstraints / keyUsage / CRL checks).

import { base64ToBytes, bytesEqual, fromUtf8 } from './util.js';

export function readTlv(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr = 2 + n;
  }
  const start = off + hdr;
  const end = start + len;
  if (end > buf.length) throw new Error('DER element overruns buffer');
  return { tag, start, end, hdr, raw: buf.subarray(off, end), value: buf.subarray(start, end) };
}

export function children(tlv) {
  const out = [];
  let o = 0;
  const v = tlv.value;
  while (o < v.length) {
    const t = readTlv(v, o);
    out.push(t);
    o = t.end;
  }
  return out;
}

const OID_CN = '2.5.4.3';

function oidToString(b) {
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

function parseTime(tlv) {
  const s = fromUtf8(tlv.value);
  let m;
  if (tlv.tag === 0x17) m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
  else if (tlv.tag === 0x18) m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
  if (!m) throw new Error('unsupported time format');
  let y = +m[1];
  if (tlv.tag === 0x17) y += y >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

function commonName(nameTlv) {
  for (const rdn of children(nameTlv)) {
    for (const atv of children(rdn)) {
      const [oid, val] = children(atv);
      if (oidToString(oid.value) === OID_CN) return fromUtf8(val.value);
    }
  }
  return null;
}

// Parse one DER certificate.
export function parseCertificate(der) {
  const cert = readTlv(der, 0);
  const [tbs, sigAlg, sigBits] = children(cert);
  const f = children(tbs);
  let i = 0;
  if (f[i].tag === 0xa0) i++; // explicit version
  i++; // serial
  const tbsSigAlg = f[i++];
  const issuer = f[i++];
  const validity = children(f[i++]);
  const subject = f[i++];
  const spki = f[i++];
  const [algId, keyBits] = children(spki);
  const [keyOid, curveOid] = children(algId);
  return {
    der,
    tbs: tbs.raw,
    sigAlgOid: oidToString(children(sigAlg)[0].value),
    tbsSigAlgOid: oidToString(children(tbsSigAlg)[0].value),
    signatureDer: sigBits.value.subarray(1), // drop the "unused bits" byte
    notBefore: parseTime(validity[0]),
    notAfter: parseTime(validity[1]),
    issuerDer: issuer.raw,
    subjectDer: subject.raw,
    issuerCN: commonName(issuer),
    subjectCN: commonName(subject),
    keyOid: oidToString(keyOid.value),
    curveOid: curveOid ? oidToString(curveOid.value) : null,
    publicKey: keyBits.value.subarray(1), // uncompressed EC point 04||X||Y
    spkiDer: spki.raw,
  };
}

// ECDSA signature DER (SEQUENCE { INTEGER r, INTEGER s }) -> fixed-size r||s for WebCrypto.
export function derEcdsaToRaw(der, size) {
  const [r, s] = children(readTlv(der, 0));
  const fix = (x) => {
    let v = x.value;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error('ECDSA integer too large');
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const out = new Uint8Array(size * 2);
  out.set(fix(r), 0);
  out.set(fix(s), size);
  return out;
}

export function pemBlocks(text, label = 'CERTIFICATE') {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`, 'g');
  const out = [];
  let m;
  while ((m = re.exec(text))) out.push(base64ToBytes(m[1].replace(/\s+/g, '')));
  return out;
}

export const OID = Object.freeze({
  EC_PUBLIC_KEY: '1.2.840.10045.2.1',
  RSA_ENCRYPTION: '1.2.840.113549.1.1.1',
  P256: '1.2.840.10045.3.1.7',
  P384: '1.3.132.0.34',
  ECDSA_SHA256: '1.2.840.10045.4.3.2',
  ECDSA_SHA384: '1.2.840.10045.4.3.3',
  RSA_SHA256: '1.2.840.113549.1.1.11',
  RSA_SHA384: '1.2.840.113549.1.1.12',
});

const CURVES = {
  [OID.P256]: { name: 'P-256', size: 32 },
  [OID.P384]: { name: 'P-384', size: 48 },
};

export async function importEcPublicKey(point, curveOid) {
  const c = CURVES[curveOid];
  if (!c) throw new Error('unsupported curve ' + curveOid);
  return globalThis.crypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: c.name }, false, ['verify']);
}

// Verify that `cert` was signed by `issuer`. Supports ECDSA (P-256/P-384) and RSA PKCS#1 v1.5
// with SHA-256/384, which is all the Intel and NVIDIA chains use.
export async function certSignedBy(cert, issuer) {
  if (!bytesEqual(cert.issuerDer, issuer.subjectDer)) return false;
  const subtle = globalThis.crypto.subtle;
  const alg = cert.sigAlgOid;
  if (alg === OID.ECDSA_SHA256 || alg === OID.ECDSA_SHA384) {
    const curve = CURVES[issuer.curveOid];
    if (issuer.keyOid !== OID.EC_PUBLIC_KEY || !curve) throw new Error('issuer key is not a supported EC key');
    const key = await importEcPublicKey(issuer.publicKey, issuer.curveOid);
    const raw = derEcdsaToRaw(cert.signatureDer, curve.size);
    return subtle.verify({ name: 'ECDSA', hash: alg === OID.ECDSA_SHA256 ? 'SHA-256' : 'SHA-384' }, key, raw, cert.tbs);
  }
  if (alg === OID.RSA_SHA256 || alg === OID.RSA_SHA384) {
    if (issuer.keyOid !== OID.RSA_ENCRYPTION) throw new Error('issuer key is not an RSA key');
    const hash = alg === OID.RSA_SHA256 ? 'SHA-256' : 'SHA-384';
    const key = await subtle.importKey('spki', issuer.spkiDer, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    return subtle.verify('RSASSA-PKCS1-v1_5', key, cert.signatureDer, cert.tbs);
  }
  throw new Error('unsupported certificate signature algorithm ' + alg);
}
