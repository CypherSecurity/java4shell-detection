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

**Fixed builds named by the Canadian Centre for Cyber Security (AL26-029, page read 18 Nov 2026):**

| Product | Affected | Fixed |
|---|---|---|
| Oracle Java SE 8 | 8u511b33-perf | **8u513-perf** |
| Oracle Java SE 17 | 17.0.6 to 17.0.21.0.3 | **17.0.21.1** |
| Oracle Java SE 21 | 21.0.13.0.3 and prior | **21.0.13.1** |
| Oracle Java SE 25 | 25.0.5.0.3 and prior | **25.0.5.1** |
| Oracle Java SE 27 | 27.0.1.0.3 and prior | **27.0.1.1** |
| Oracle GraalVM for JDK | 17.0.6–17.0.21.0.3 and 21.0.0–21.0.13.0.3 | **17.0.21.1, 21.0.13.1** |
| Oracle GraalVM EE | 21.3.20.0.3 and prior | **21.3.20.1** |
| Oracle OpenJDK | 17.0.6–27.0.1.0.3 | **27.0.1.1** |

The Oracle CPU page we captured does not display the `8u513` build string, so that specific line rests
on the Canadian Centre's reading of Oracle's advisory; the 17/21/25/27 lines match the OpenJDK patch
releases that Corretto imports. **Numbering differs by vendor:** Oracle Java 8 fixed is `8u513-perf`,
Amazon Corretto 8 is `8.514.01.1`, OpenJDK 8u is `8u514-b01`. Do not compare strings across vendors.

- **OpenJDK advisory** (2026-11-17): affected 27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3, 17.0.21.0.3,
  11.0.33, 8u512 and earlier; fixed patch releases as above.
- **Oracle CPU November 2026**: https://www.oracle.com/security-alerts/cspunov2026.html
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

## Product-vendor advisories (products that embed a JVM)

| Vendor | Advisory | State (as of 18 Nov 2026) |
|---|---|---|
| Cisco | `cisco-sa-nov2026-java-rce-eCa6ss9z`, "Vulnerability in Oracle OpenJDK (Java4Shell) Affecting Cisco Products" | **Version 1.0, Interim, first published 18 Nov 16:00 GMT**: Cisco is investigating its product line; **no affected products or fixed releases listed yet**, **no workarounds**. Scope statement matches the disclosure: x86-64 with AVX-512 VBMI affected; x86-64 without AVX-512, ARM and Cisco Silicon One not affected. Re-read before quoting Cisco exposure |
| Siemens | `SSA-272816`, "Java4Shell Vulnerability in Industrial Edge" | **V1.0, 18 Nov 2026**: **affected, no fix available** for Industrial Edge Management Pro V1, Pro V2 and Virtual (all versions). Not affected: Industrial Edge Device Kit (no Java) and IEM Cloud. Mitigation: block direct internet access or shut the instances down until a fix exists |
| Keycloak / Red Hat | Keycloak guidance post, 18 Nov (updated 09:29 UTC) | Images **26.8.2-1 and 26.8.2-2 bundle affected OpenJDK 21.0.13**; **no fixed Keycloak image recommended yet**. Preferred interim mitigation `-XX:-UseBASE64Intrinsics` via `JAVA_OPTS_APPEND` (Operator: `JDK_JAVA_OPTIONS`), verified with `jcmd ... VM.flags -all`. Keycloak decodes Base64 before authentication |

If you run a product that embeds a JVM (Atlassian, Jenkins, JFrog, Ping, Cisco and others), check the
vendor's own advisory rather than assuming either state. This table is updated only when a vendor
advisory is read and verified by this programme.

## Verify the gate, not just the version

An affected JDK on a CPU without AVX-512 VBMI does not execute the vulnerable path, and a
VBMI-capable CPU with a patched JDK is not affected. Use
`02-detections/common/check-java4shell-exposure.sh` to report both facts per host.
