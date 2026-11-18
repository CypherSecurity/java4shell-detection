# Build information

- Package: `java4shell-detection-package-2026-11-17` (name is the disclosure date; content continues
  to change after it, deliberately, so the release URL stays stable).
- Built: 2026-11-18, by the Java4Shell watch programme.
- Dossier version: 0.1 (18 Nov 2026).

## What was verified on this build

- NVD record: `Received`, published 2026-11-17T22:18:23Z, CVSS 3.1 8.1, CWE-122, refs 9.
- OpenJDK advisory 2026-11-17 (read directly): CVE listed, hotspot/compiler, affected versions as
  quoted in the dossier, inconsistency between text and risk matrix recorded.
- Oracle CPU November 2026: CVE present, CVSS 8.1, affected Oracle Java SE and GraalVM versions.
- Corretto fixed builds read from each branch's CHANGELOG: 8.514.01.1, 11.0.33.1.1,
  17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4, all released 17 Nov 2026.
- CISA KEV: **not listed** (catalog 2026.11.17).
- Cisco advisory `cisco-sa-nov2026-java-rce-eCa6ss9z` read directly (18 Nov): Version 1.0 Interim, no
  affected products or fixed releases yet, no workarounds; PSIRT aware of PoC, not of malicious use.
- Startup-flag mitigation verified in OpenJDK source: `UseBASE64Intrinsics` gates generation of
  `_base64_decodeBlock` (`stubGenerator_x86_64.cpp`), defaulted on for AVX2+ CPUs in
  `vm_version_x86.cpp`; VBMI tables installed only when `supports_avx512_vbmi()`. Vendor-reported by
  Check Point and the Xint runtime-patch README.
- CISA alert and NCSC-NZ alert: read.

## Validation performed on this build

- Suricata 8.0.8: both rules load, both fire on a synthetic malformed-Base64 request, neither fires
  on a benign Basic-auth control; a malformed negative-control rule is correctly rejected.
- Sigma: sigma-cli 4.0.1 reports 0 errors and 0 validation issues; rules convert to Splunk queries.
  The restart-burst rule was rewritten as a correlation rule after validation rejected its original
  aggregation syntax.
- Exposure checker: eleven stub JDK versions produce the expected verdicts in text and JSON modes.
- Published artifacts: repo tree 15 blobs, release ZIP 26,230 bytes, cache-busted download SHA256
  matches. Full record in `05-validation/VALIDATION-REPORT.md`.

## What is not verified

- No reproduction of the bug, crash or RCE by us. No exploit code was run.
- Calif's product-specific RCE demonstrations are vendor-reported only.
- Immersive's working-exploit claim is unverified.
- No confirmed in-the-wild exploitation as of 18 Nov 2026.
- Fixed builds beyond Corretto/Oracle (Temurin, Zulu, Microsoft, Liberica, SapMachine, Red Hat) are
  pending and will be added when published.
- The Suricata rules are validated for syntax and match logic but **untested on production traffic**;
  false positives are expected. Sigma rules are validated and converted, not deployed on a SIEM.

## Ground rules

No exploit code ships in any version of this package. Detection content describes shapes and
artefacts; it does not include a working trigger or chain.
