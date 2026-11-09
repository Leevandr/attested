// Turn a raw NEAR AI Cloud attestation report into (a) a compact evidence object that is stored
// in the receipt and (b) a list of honestly labelled checks. The same function re-runs on the
// stored evidence inside `verify-receipt`, completely offline.

import { verifyQuoteSignatures, describeQuote } from './tdx.js';
import { verifyNras } from './nvidia.js';
import { STATUS, bytesEqual, bytesToHex, canonicalize, check, concatBytes, hexToBytes, sha256Hex, sha384, utf8 } from './util.js';

const ZERO48 = new Uint8Array(48);

// ---- compacting -----------------------------------------------------------------------

function compactAttestation(a, extra = {}) {
  const t = a.info?.tcb_info ?? {};
  return {
    model_name: a.model_name,
    signing_address: a.signing_address,
    signing_algo: a.signing_algo,
    signing_public_key: a.signing_public_key,
    request_nonce: a.request_nonce,
    report_data: a.report_data,
    intel_quote: a.intel_quote,
    app_name: a.info?.app_name,
    app_id: a.info?.app_id,
    os_image_hash: a.info?.os_image_hash,
    compose_hash: a.info?.compose_hash,
    tcb: { app_compose: t.app_compose, event_log: t.event_log },
    ...extra,
  };
}

// `nvidia`: { nonce, arch, gpuCount, payloadSha256 } computed by the caller from the big payload.
export function compactReport(report, nvidia) {
  const m = report.model_attestations?.[0];
  if (!report.gateway_attestation || !m) throw new Error('report lacks gateway_attestation or model_attestations');
  const cm = m.compose_manager_attestation;
  return {
    gateway: compactAttestation(report.gateway_attestation),
    model: compactAttestation(m, {
      nvidia: nvidia ? { nonce: nvidia.nonce, arch: nvidia.arch, gpu_count: nvidia.gpuCount, payload_sha256: nvidia.payloadSha256 } : null,
      compose_manager: cm ? { actions: cm.actions, actions_hash: cm.actions_hash, nonce: cm.nonce, nonce_source: cm.nonce_source, quote: cm.quote, report_data: cm.report_data } : null,
    }),
  };
}

// ---- helpers --------------------------------------------------------------------------

function canonicalizeJsonOfficial(value) {
  // Same canonical form as the official verifier (sorted keys, no whitespace).
  return canonicalize(value);
}

function expectedKeyBinding(att) {
  const algo = (att.signing_algo || 'ecdsa').toLowerCase();
  const raw = hexToBytes(att.signing_address);
  if (algo === 'ecdsa' && raw.length !== 20) throw new Error('ecdsa signing address must be 20 bytes');
  if (algo === 'ed25519' && raw.length !== 32) throw new Error('ed25519 signing key must be 32 bytes');
  if (raw.length > 32) throw new Error('signing address longer than 32 bytes');
  const out = new Uint8Array(32);
  out.set(raw, 0);
  return out;
}

async function replayRtmrs(eventLog) {
  const acc = [0, 1, 2, 3].map(() => new Uint8Array(ZERO48));
  let runtimeEvents = 0;
  let runtimeOk = 0;
  for (const e of eventLog) {
    if (!(e.imr >= 0 && e.imr <= 3)) throw new Error('event with unexpected imr ' + e.imr);
    const digest = hexToBytes(e.digest);
    if (digest.length !== 48) throw new Error('event digest must be 48 bytes');
    acc[e.imr] = await sha384(concatBytes(acc[e.imr], digest));
    if (e.imr === 3 && e.event_type === 0x08000001) {
      runtimeEvents++;
      const et = new Uint8Array(4);
      et[0] = e.event_type & 0xff;
      et[1] = (e.event_type >>> 8) & 0xff;
      et[2] = (e.event_type >>> 16) & 0xff;
      et[3] = (e.event_type >>> 24) & 0xff;
      const d = await sha384(concatBytes(et, utf8(':'), utf8(e.event), utf8(':'), hexToBytes(e.event_payload || '')));
      if (bytesEqual(d, digest)) runtimeOk++;
    }
  }
  return { acc, runtimeEvents, runtimeOk };
}

function dockerImages(appCompose) {
  try {
    const compose = JSON.parse(appCompose).docker_compose_file || '';
    return [...new Set([...compose.matchAll(/([A-Za-z0-9][A-Za-z0-9._\/-]*)@sha256:([0-9a-f]{64})/g)].map((m) => `${m[1]}@sha256:${m[2]}`))];
  } catch {
    return [];
  }
}

// ---- per-attestation checks -----------------------------------------------------------

async function checkOne(who, att, { nonce, validAt, quoteHex, quoteLabel = 'TDX quote' }) {
  const out = [];
  const quote = await verifyQuoteSignatures(quoteHex, { validAt });
  const qOk = quote.ok;
  const failedStep = quote.steps.find((s) => !s.ok);
  out.push(
    check(
      `tdx.quote.${who}`,
      `${who}: Intel TDX quote signature chain`,
      qOk ? STATUS.VERIFIED : STATUS.FAILED,
      qOk ? 'attestation key, QE report and PCK chain verify up to the pinned Intel SGX Root CA' : `${failedStep.name}${failedStep.detail ? ': ' + failedStep.detail : ''}`,
    ),
  );
  if (!quote.parsed) return { checks: out, quote };
  const q = describeQuote(quote.parsed);
  const dependent = (id, label, ok, detailOk, detailBad) => {
    let status = ok ? STATUS.VERIFIED : STATUS.FAILED;
    let detail = ok ? detailOk : detailBad;
    if (ok && !qOk) {
      status = STATUS.FAILED;
      detail = 'values match, but the quote signature chain failed, so they are not hardware-attested';
    }
    out.push(check(id, label, status, detail));
  };

  // report_data = signing key (padded to 32 bytes) || nonce
  try {
    const key = expectedKeyBinding(att);
    const rd = quote.parsed.body.reportData;
    const keyOk = bytesEqual(rd.subarray(0, 32), key);
    const nonceOk = bytesEqual(rd.subarray(32, 64), hexToBytes(nonce));
    dependent(
      `tdx.report_data.${who}`,
      `${who}: quote commits to the signing key and to our nonce`,
      keyOk && nonceOk,
      `report_data = ${att.signing_algo} signing key ${att.signing_address.slice(0, 14)}... || nonce`,
      `${keyOk ? '' : 'signing key not in report_data. '}${nonceOk ? '' : 'nonce not in report_data.'}`.trim(),
    );
  } catch (e) {
    out.push(check(`tdx.report_data.${who}`, `${who}: quote commits to the signing key and to our nonce`, STATUS.FAILED, e.message));
  }

  dependent(`tdx.debug.${who}`, `${who}: TD is not in debug mode`, !q.debug, `td_attributes=${q.tdAttributes}, DEBUG bit clear`, 'DEBUG bit is set: a debug TD is not confidential');

  // RTMR replay (only for the main attestation: it carries the event log)
  if (att.tcb?.event_log) {
    try {
      const { acc, runtimeEvents, runtimeOk } = await replayRtmrs(att.tcb.event_log);
      const match = acc.every((a, i) => bytesToHex(a) === q.rtmr[i]);
      dependent(
        `tdx.rtmr.${who}`,
        `${who}: boot event log replays to the quote's RTMR0-3`,
        match && runtimeOk === runtimeEvents,
        `${att.tcb.event_log.length} events replay to RTMR0-3; ${runtimeOk}/${runtimeEvents} runtime event digests recomputed`,
        match ? `runtime event digests: ${runtimeOk}/${runtimeEvents} recomputed` : 'replayed RTMR values differ from the quote',
      );
    } catch (e) {
      out.push(check(`tdx.rtmr.${who}`, `${who}: boot event log replays to the quote's RTMR0-3`, STATUS.FAILED, e.message));
    }
    // compose hash
    try {
      const composeHash = await sha256Hex(att.tcb.app_compose);
      const ev = att.tcb.event_log.find((e) => e.event === 'compose-hash');
      const evOk = ev && ev.event_payload === composeHash;
      const cfg = q.mrConfigId;
      const cfgOk = cfg.startsWith('01' + composeHash) && /^0*$/.test(cfg.slice(66));
      dependent(
        `tdx.compose.${who}`,
        `${who}: docker-compose manifest hash is in the quote (RTMR3 event and mr_config_id)`,
        !!evOk && cfgOk,
        `sha256(app_compose)=${composeHash.slice(0, 16)}... equals the measured compose-hash event and mr_config_id`,
        `${evOk ? '' : 'compose-hash event does not equal sha256(app_compose). '}${cfgOk ? '' : 'mr_config_id does not equal 01||sha256(app_compose).'}`.trim(),
      );
    } catch (e) {
      out.push(check(`tdx.compose.${who}`, `${who}: docker-compose manifest hash is in the quote`, STATUS.FAILED, e.message));
    }
  }
  return { checks: out, quote, q };
}

async function checkComposeManager(cm, { nonce, validAt }) {
  const out = [];
  const q = await verifyQuoteSignatures(cm.quote, { validAt });
  const actionsHash = await sha256Hex(canonicalizeJsonOfficial(cm.actions));
  const hashOk = actionsHash === cm.actions_hash;
  let bindOk = false;
  if (q.parsed) {
    const rd = q.parsed.body.reportData;
    bindOk = bytesToHex(rd.subarray(0, 32)) === cm.actions_hash && bytesToHex(rd.subarray(32, 64)) === nonce.toLowerCase();
  }
  const ok = hashOk && bindOk && q.ok;
  const probs = [];
  if (!q.ok) probs.push('compose-manager quote signature chain failed');
  if (!hashOk) probs.push('actions_hash is not sha256 of the canonical action log');
  if (!bindOk) probs.push('quote report_data is not actions_hash || nonce');
  out.push(
    check(
      'compose_manager',
      'model: deployment action log is bound to a hardware quote (and our nonce)',
      ok ? STATUS.VERIFIED : STATUS.FAILED,
      ok ? `${cm.actions.length} logged actions hash to ${cm.actions_hash.slice(0, 16)}..., which the compose-manager quote commits to` : probs.join('; '),
    ),
  );
  return out;
}

// ---- main entry -----------------------------------------------------------------------
//   evidence: output of compactReport() plus optional { nras: {response, jwk} }
//   ctx: { nonce, model, validAt: Date, mode: 'live'|'recorded', enforceNrasExpiry }
export async function verifyEvidence(evidence, ctx) {
  const { nonce, model, validAt, mode } = ctx;
  const checks = [];
  const g = evidence.report.gateway;
  const m = evidence.report.model;

  // nonce echo
  const echoOk = g.request_nonce === nonce && m.request_nonce === nonce;
  checks.push(
    check(
      'nonce.echo',
      'report echoes the request nonce (gateway and model)',
      echoOk ? STATUS.VERIFIED : STATUS.FAILED,
      echoOk ? `nonce ${nonce.slice(0, 12)}... returned by both attestations` : 'nonce missing or different',
    ),
  );
  if (mode === 'recorded') {
    checks.push(check('nonce.fresh', 'nonce chosen fresh for this run', STATUS.NOT_RUN, 'recorded evidence: the nonce was chosen when the fixture was recorded, so this run proves nothing about freshness'));
  } else {
    checks.push(check('nonce.fresh', 'nonce chosen fresh for this run', STATUS.VERIFIED, ctx.nonceSource === 'supplied' ? 'nonce supplied by the verifier (challenge-response); the quotes commit to it (see report_data checks)' : 'random 32-byte nonce generated locally just before the request; the quotes commit to it (see report_data checks). Only the party that ran this can know it was fresh'));
  }
  checks.push(
    check(
      'model.name',
      'report names the requested model',
      m.model_name === model ? STATUS.PRESENT : STATUS.FAILED,
      m.model_name === model ? `model_name="${m.model_name}"; this field is not itself signed by the quote (the compose-manager log shows what was deployed)` : `report says "${m.model_name}", we asked for "${model}"`,
    ),
  );

  const gw = await checkOne('gateway', g, { nonce, validAt, quoteHex: g.intel_quote });
  const md = await checkOne('model', m, { nonce, validAt, quoteHex: m.intel_quote });
  checks.push(...gw.checks, ...md.checks);

  if (m.compose_manager) checks.push(...(await checkComposeManager(m.compose_manager, { nonce, validAt })));
  else checks.push(check('compose_manager', 'model: deployment action log is bound to a hardware quote', STATUS.PRESENT, 'report has no compose_manager_attestation'));

  // NVIDIA
  let nrasResult = null;
  if (!m.nvidia) {
    checks.push(check('nvidia.payload', 'NVIDIA GPU evidence present', STATUS.FAILED, 'model attestation has no nvidia_payload'));
  } else {
    const nOk = m.nvidia.nonce?.toLowerCase() === nonce.toLowerCase();
    checks.push(check('nvidia.nonce', 'GPU evidence payload carries our nonce', nOk ? STATUS.VERIFIED : STATUS.FAILED, nOk ? `${m.nvidia.gpu_count} GPU evidence blobs, arch ${m.nvidia.arch}, payload sha256 ${m.nvidia.payload_sha256.slice(0, 16)}...` : 'payload nonce differs from the request nonce'));
    if (evidence.nras) {
      nrasResult = await verifyNras({ nras: evidence.nras.response, jwk: evidence.nras.jwk, nonce, validAt, enforceExpiry: !!ctx.enforceNrasExpiry });
      checks.push(...nrasResult.checks);
    } else {
      checks.push(check('nvidia.nras', 'NVIDIA NRAS verdict', STATUS.PRESENT, 'GPU evidence is present but no NRAS verdict was obtained (offline or --no-nras); the GPU evidence itself is NOT checked here'));
    }
  }

  // Intel collateral: honest gap
  checks.push(check('tdx.collateral', 'Intel TCB status, revocation and QE identity', STATUS.PRESENT, 'not evaluated: needs Intel PCS collateral (TCB info, CRLs). The quote signatures verify, but whether the platform firmware is up to date is not checked'));

  // what the enclave says it runs
  const lastUp = [...(m.compose_manager?.actions || [])].reverse().find((a) => a.action === 'compose_up');
  const summary = {
    model_name: m.model_name,
    gateway_signing_address: g.signing_address,
    model_signing_address: m.signing_address,
    model_compose_hash: md.q ? md.q.mrConfigId.slice(2, 66) : null,
    gateway_compose_hash: gw.q ? gw.q.mrConfigId.slice(2, 66) : null,
    model_mr_td: md.q?.mrTd ?? null,
    os_image_hash: m.os_image_hash,
    model_images: dockerImages(m.tcb?.app_compose),
    compose_up: lastUp ? { tag: lastUp.tag, commit: lastUp.commit, file: lastUp.file, timestamp: lastUp.timestamp } : null,
    gpu: nrasResult ? nrasResult.info : null,
  };
  return { checks, summary };
}

export function tallyChecks(checks) {
  const t = { verified: 0, present_not_verified: 0, failed: 0, not_run: 0 };
  for (const c of checks) {
    if (c.status === STATUS.VERIFIED) t.verified++;
    else if (c.status === STATUS.PRESENT) t.present_not_verified++;
    else if (c.status === STATUS.FAILED) t.failed++;
    else t.not_run++;
  }
  return t;
}
