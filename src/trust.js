// Trust anchors pinned in this repository. Everything here is public data.
//
// 1) Intel SGX/TDX Provisioning Certification Root CA.
//    Downloaded on 2026-11-09 from
//    https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
//    and found byte-identical to the root certificate embedded in the live NEAR AI TDX quotes.
//    SHA-256 of the DER: 44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3
export const INTEL_SGX_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
`;
export const INTEL_SGX_ROOT_CA_SHA256 = '44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3';

// 2) NVIDIA Remote Attestation Service (NRAS) intermediate CAs that sign the short-lived
//    (about 12 h) token-signing certificates listed in
//    https://nras.attestation.nvidia.com/.well-known/jwks.json (x5c[1] of every key).
//    Pinned by SHA-256 of the DER certificate, read from that JWKS on 2026-11-09.
//    CAVEAT: the NVIDIA root ("NVIDIA Attestation Service CA 001") that signs these
//    intermediates is NOT pinned here, because we have no independent copy of it.
//    So the NRAS check anchors on these two intermediates (trust-on-first-fetch over TLS).
export const NVIDIA_NRAS_INTERMEDIATES = {
  '2df8907cf4d6c277b855d407ec178a649930a8e73f7294e8fce66e6ee27c5175': 'NVIDIA Attestation Service GPU Intermediate 004',
  '38e3daf3cdbd5243bb15dd7993edcdd83a7238cb6745b980f8f3bf0a31a0d343': 'NVIDIA Attestation Service GPU Intermediate 005',
};
