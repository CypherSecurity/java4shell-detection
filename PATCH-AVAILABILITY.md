# Patch availability — Java4Shell (CVE-2026-114938)

Status as of 2026-11-18. Vendors continue to publish; this file is updated as fixed builds are
verified. **The complete fix is a fixed JDK build.** There is no JVM configuration flag that removes
the vulnerable decoder path, and disabling Base64 decoding is not generally possible.

## Fixed builds verified by us

| Vendor | Fixed build | Released | Evidence |
|---|---|---|---|
| Amazon Corretto 8 | **8.514.01.1** | 2026-11-17 | Corretto changelog; older format without CVE table |
| Amazon Corretto 11 | **11.0.33.1.1** | 2026-11-17 | Corretto changelog; older format without CVE table |
| Amazon Corretto 17 | **17.0.21.1.2** | 2026-11-17 | Corretto changelog lists CVE-2026-114938 |
| Amazon Corretto 21 | **21.0.13.1.2** | 2026-11-17 | Corretto changelog lists CVE-2026-114938 |
| Amazon Corretto 25 | **25.0.5.1.2** | 2026-11-17 | Corretto changelog lists CVE-2026-114938 |
| Amazon Corretto 27 | **27.0.1.1.4** | 2026-11-17 | Corretto changelog lists CVE-2026-114938; imports jdk-27.0.1.1+4 |

The Corretto 8 and 11 changelogs do not carry a CVE table; their fixed status rests on the release
date and the imported OpenJDK baseline, not on an explicit CVE line.

## Upstream and Oracle

- **OpenJDK / Oracle JDK**: fixed in the updates announced by the OpenJDK advisory of
  2026-11-17 (affected 27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3, 17.0.21.0.3, 11.0.33, 8u512 and
  earlier). Oracle ships the fix through the November 2026 Critical Security Patch Update:
  https://www.oracle.com/security-alerts/cspunov2026.html
- **Oracle GraalVM for JDK / Enterprise Edition**: fixed through the same Oracle CPU for the affected
  versions listed in the Oracle risk matrix.
- The same patch set contains nine further Java SE CVEs (CVE-2026-114939 to CVE-2026-114947) and
  OpenJFX CVE-2026-86144. Treat the update as a security patch set, not a single-CVE fix.

## Pending verification

| Vendor | Expected | Status |
|---|---|---|
| Eclipse Temurin / Adoptium | 17.0.21+, 21.0.13+, 25.0.5+ security builds | awaiting advisory/release notes |
| Azul Zulu | platform builds | awaiting |
| Microsoft Build of OpenJDK | builds | awaiting |
| BellSoft Liberica | builds | awaiting |
| SAP SapMachine | builds | awaiting |
| Red Hat OpenJDK | errata | Red Hat CVE page not yet published |
| Alibaba Dragonwell, Tencent Kona, others | builds | not yet checked |

Do not assume a vendor is unpatched because this table says "awaiting": check the vendor's own
release notes. Update this table when you verify a build.

## Compensating controls when patching is delayed

CISA recommends restricting and validating Base64 input at the application boundary, enforcing
input-size limits, and limiting unauthenticated access. These reduce exposure of specific endpoints;
they are **not** a fix. A JVM startup flag, `-XX:-UseBASE64Intrinsics`, also suppresses the vulnerable
intrinsic (mechanism verified in OpenJDK source; see `03-guidance/MITIGATION.md`), at a Base64
performance cost and with the same "not a fix" caveat. Useful prioritisation:

1. **Identity and access services first** — Keycloak, PingFederate, and anything that decodes Base64
   in authentication headers before credentials are checked.
2. **Internet-facing CI and artefact services** — Jenkins, Atlassian, JFrog.
3. **Data services with authenticated access** — Kafka, Solr, Elasticsearch, Gerrit, Spinnaker.
4. **Everything else that embeds a JVM** — appliances, build agents, container images.

## Verify the gate, not just the version

An affected JDK on a CPU without AVX-512 VBMI does not execute the vulnerable path, and a
VBMI-capable CPU with a patched JDK is not affected. Use
`02-detections/common/check-java4shell-exposure.sh` to report both facts per host.
