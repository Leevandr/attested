// Response-signature check for one NON-STREAMING chat completion.
//
// NEAR AI Cloud signs "text" with the TEE key (EIP-191 personal_sign, ecdsa):
//   provider_tee: "{model_id}:{request_sha256}:{response_sha256}"   signed inside the model TEE
//   gateway:      "{request_sha256}:{response_sha256}"              signed inside the gateway TEE
// Streaming responses are signed by the gateway, never by the model TEE; this tool does not do streaming.
// Layout and rules follow the official example (near-examples/nearai-cloud-verification-example, MIT).

import { STATUS, check } from './util.js';
import { recoverPersonalSigner } from './eth.js';

export function resolveSignatureKind(sig) {
  if (sig.signature_kind === 'provider_tee' || sig.signature_kind === 'gateway') return sig.signature_kind;
  return String(sig.text).split(':').length === 3 ? 'provider_tee' : 'gateway';
}

// `keyBound`: { gateway: boolean, model: boolean }, true when the quote of that TEE is
// verified AND commits to that signing key (checks tdx.quote.* and tdx.report_data.*).
export function verifyResponseSignature({ model, requestSha256, responseSha256, sig, evidence, keyBound }) {
  try {
    const kind = resolveSignatureKind(sig);
    const parts = String(sig.text).split(':');
    const wantParts = kind === 'provider_tee' ? 3 : 2;
    if (parts.length !== wantParts) throw new Error(`signed text has ${parts.length} parts, ${kind} needs ${wantParts}`);
    const [signedModel, reqHash, resHash] = kind === 'provider_tee' ? parts : [null, parts[0], parts[1]];
    const problems = [];
    if (kind === 'provider_tee' && signedModel !== model) problems.push('signed model id differs from the requested model');
    if (reqHash !== requestSha256) problems.push('signed request hash differs from our request hash');
    if (resHash !== responseSha256) problems.push('signed response hash differs from our response hash');
    if ((sig.signing_algo || 'ecdsa') !== 'ecdsa') problems.push('only ecdsa signatures are supported');
    const recovered = recoverPersonalSigner(sig.text, sig.signature).toLowerCase();
    const att = kind === 'provider_tee' ? evidence.report.model : evidence.report.gateway;
    const expected = att.signing_address.toLowerCase().replace(/^(0x)?/, '0x');
    if (recovered !== expected) problems.push(`recovered signer ${recovered} is not the attested ${kind === 'provider_tee' ? 'model' : 'gateway'} TEE key ${expected}`);
    if (sig.signing_address && sig.signing_address.toLowerCase().replace(/^(0x)?/, '0x') !== recovered) problems.push('signature response names a different signer than the one recovered');
    const bound = kind === 'provider_tee' ? keyBound.model : keyBound.gateway;
    const who = kind === 'provider_tee' ? 'model TEE' : 'gateway TEE';
    if (problems.length) return check('response.signature', 'response signature', STATUS.FAILED, problems.join('; '), { signature_kind: kind });
    if (!bound) return check('response.signature', 'response signature', STATUS.FAILED, `signature is valid for the ${who} key, but that key is not bound to a verified quote`, { signature_kind: kind });
    return check(
      'response.signature',
      `response signature by the ${who} key`,
      STATUS.VERIFIED,
      `signer ${recovered} recovered from the signature equals the key committed to by the ${who} quote; signed hashes equal ours${kind === 'gateway' ? ' (signed by the gateway TEE, not the model TEE)' : ''}`,
      { signature_kind: kind },
    );
  } catch (e) {
    return check('response.signature', 'response signature', STATUS.FAILED, e.message);
  }
}
