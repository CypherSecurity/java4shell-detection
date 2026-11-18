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
- CISA alert and NCSC-NZ alert: read.

## What is not verified

- No reproduction of the bug, crash or RCE by us. No exploit code was run.
- Calif's product-specific RCE demonstrations are vendor-reported only.
- Immersive's working-exploit claim is unverified.
- No confirmed in-the-wild exploitation as of 18 Nov 2026.
- Fixed builds beyond Corretto/Oracle (Temurin, Zulu, Microsoft, Liberica, SapMachine, Red Hat) are
  pending and will be added when published.
- The Suricata rules are experimental and untested on production traffic; false positives are
  expected. Sigma rules are behavioural and should be tuned to your environment.

## Ground rules

No exploit code ships in any version of this package. Detection content describes shapes and
artefacts; it does not include a working trigger or chain.
