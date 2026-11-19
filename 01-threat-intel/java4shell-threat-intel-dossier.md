# Java4Shell (CVE-2026-114938) — Threat Intelligence Dossier

**Status:** living document, version 0.1 (18 November 2026, 10:45 UTC).
**Disclosure:** 17 November 2026, by Calif.io, as "Java4Shell".
**Programme:** watch running hourly during the discovery phase; public page https://f4n6.co.uk/java4shell/; package and release https://github.com/CypherSecurity/java4shell-detection (package `java4shell-detection-package-2026-11-17`; its current size and sha256 are shown on the public page and in Build info; rules and checker validated in its `05-validation/VALIDATION-REPORT.md`).
**One-line:** a memory-corruption bug in OpenJDK's AVX-512 Base64 decoder that yields heap
overwrite, memory disclosure and, with an application-specific chain, remote code execution on
Java servers whose CPU exposes AVX-512 VBMI.

Calibration labels used throughout: **verified** (read directly from the primary source),
**vendor-reported** (a vendor or researcher states it; we have not reproduced it), **unverified**
(secondary claim, not confirmed by the party it describes), **contested** (credible sources
disagree). Deliverables contain no exploit code.

---

## 1. Identity and status

| Item | Value | Provenance |
|---|---|---|
| CVE | **CVE-2026-114938** | NVD record |
| Name | **Java4Shell** | Calif.io disclosure |
| Published (NVD) | 2026-11-17T22:18:23Z | verified, NVD |
| NVD status | **Modified** since 19 Nov 21:17Z, **refs 14** (14th is Siemens **SSA-810379**, published 19 Nov); earlier `Analyzed` on 19 Nov 11:47Z; scores (8.1 Oracle secondary) and CWE-122 unchanged | verified, NVD |
| NVD status | **`Undergoing Analysis`** (Received → Awaiting Analysis → Undergoing Analysis, 18 Nov; not yet analyzed) | verified, NVD |
| Oracle CVSS 3.1 | **8.1** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | verified, NVD + Oracle CPU |
| Calif CVSS 4.0 | **9.2 CRITICAL** | vendor-reported, Calif |
| CWE | **CWE-122** (heap-based buffer overflow) | verified, NVD |
| Component | hotspot/compiler | verified, OpenJDK advisory |
| In CISA KEV | **No** (catalog `2026.11.17`, 1,782 entries) | verified, 18 Nov |
| CISA alert | Yes, 17 Nov, "Critical Java Vulnerability Requires Immediate Patching" | verified, CISA |
| Exploited in the wild | **Exploitation attempts observed**, no confirmed successful exploitation or victim as of 18 Nov 2026 20:00 UTC | GreyNoise live dashboard (read directly): **4 source IPs sending trigger-shaped Base64, 69 shaped requests, 0 successful intrusions**. Tenable's 18 Nov update reports the same attempts. Not in KEV |

**Severity is contested.** Oracle, and NVD reflecting Oracle, call it 8.1 with
`AC:H`. Calif markets it as 9.2 critical. Both are defensible readings of the same facts: the
corruption is trivial to trigger, but a working chain is application-specific. Do not quote one
score as if both sources agree.

---

## 2. Technical root cause (verified from the Calif disclosure and Oracle/OpenJDK records)

OpenJDK accelerates Base64 decoding with hand-written x86-64 assembly using AVX-512 VBMI when the
CPU supports it. In that path the routine mishandles the padded tail of a short malformed input:

- Decoding 64 `A` characters followed by a single `=` (128 plus `=` on older JDK 17 builds) produces a
  **negative computed output length**.
- That length is treated as a full **64-byte write** into a 50-byte result buffer, writing roughly
  **62 bytes past the end**.
- Java rejects the malformed input **after** the write has happened, so neighbouring heap memory is
  corrupted before any exception is raised.

The corrupted bytes are fixed (`A`-derived), so a bare trigger usually crashes the JVM. Exploitation
requires shaping the heap so the overwrite enlarges or redirects a neighbouring array, which then
gives relative read/write and, from there, memory disclosure or control of execution. Calif splits
this into two outcomes:

- **"JavaBleed"**: heap disclosure, potentially exposing private keys, session tokens and credentials
  without code execution.
- **RCE**: application-specific chains, pre-auth where Base64 is decoded before authentication.

Two further properties matter for defenders:

- **CPU gate.** Only x86-64 CPUs exposing AVX-512 **VBMI** execute the vulnerable path. Calif lists
  Intel Ice Lake, Sapphire Rapids, Emerald Rapids and Granite Rapids, and AMD Zen 4 or newer. On
  Linux, all four of `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` must be present in
  `/proc/cpuinfo` flags. A vulnerable JDK on a CPU without VBMI does not reach the bug.
- **No universal exploit.** Each product needs its own chain and heap layout; failed attempts often
  crash the process, and an attacker can usually retry. That slows mass exploitation but does not
  protect a specific high-value target such as an identity provider.

---

## 3. Affected software

### 3.1 OpenJDK and Oracle builds

OpenJDK advisory of 17 November lists: **27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3, 17.0.21.0.3,
11.0.33, 8u512 and earlier**. Oracle CPU adds Oracle Java SE
`8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3`, Oracle GraalVM for JDK
`17.0.21.0.3` and `21.0.13.0.3`, and GraalVM Enterprise Edition `21.3.20.0.3`.

**Open question:** the OpenJDK advisory's affected-version sentence names 11.0.33 and 8u512, but its
own risk matrix marks only 17, 21, 25 and 27. The two statements are inconsistent; the dossier keeps
both and prefers the conservative reading (treat 8 and 11 as affected) until a source resolves it.

### 3.2 Distributions named as affected by the disclosure

Amazon Corretto, Eclipse Temurin, Microsoft Build of OpenJDK, Azul Zulu, BellSoft Liberica, SAP
SapMachine, Red Hat OpenJDK, Oracle OpenJDK, Oracle Java SE, Oracle GraalVM. The list is
**vendor-reported** by Calif and should be re-verified per vendor as advisories appear.

### 3.3 Fixed builds (17 November 2026), verified where stated

| Distribution | Fixed version | Provenance |
|---|---|---|
| OpenJDK | 27.0.1.1+4 (and matching patch builds for older branches) | verified from Corretto baselines; OpenJDK advisory is source of version shape |
| Amazon Corretto 8 | **8.514.01.1** | verified, Corretto changelog (17 Nov 2026) |
| Amazon Corretto 11 | **11.0.33.1.1** | verified, Corretto changelog |
| Amazon Corretto 17 | **17.0.21.1.2** | verified, Corretto changelog (lists CVE-2026-114938) |
| Amazon Corretto 21 | **21.0.13.1.2** | verified, Corretto changelog |
| Amazon Corretto 25 | **25.0.5.1.2** | verified, Corretto changelog |
| Amazon Corretto 27 | **27.0.1.1.4** | verified, Corretto changelog |
| Oracle Java SE 8 | **8u513-perf** | CCCS AL26-029 (page read 18 Nov); the Oracle CPU page we captured does not display this build string |
| Oracle Java SE 17 / 21 / 25 / 27 | **17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1** | CCCS AL26-029; consistent with the OpenJDK patch releases Corretto imports |
| Oracle GraalVM for JDK | **17.0.21.1 and 21.0.13.1** | CCCS AL26-029 |
| Oracle GraalVM Enterprise Edition | **21.3.20.1** | CCCS AL26-029 |
| Oracle OpenJDK | **27.0.1.1** (covers 17.0.6–27.0.1.0.3) | CCCS AL26-029 |
| Other vendors | pending | to be recorded as released |

**Version-numbering caveat:** Oracle's Java 8 fixed build is named `8u513-perf` by the Canadian Centre,
while Amazon Corretto's 8-line fix is **8.514.01.1** and imports OpenJDK **8u514-b01**. Those are
different numbering schemes for the same upstream fix, not conflicting reports. Compare like with like
per vendor; do not treat "8u513" and "8.514" as the same string.

Corretto changelogs for 17/21/25/27 explicitly list CVE-2026-114938 in their CVE tables; the 8 and
11 changelogs use an older format without a CVE table, so their fixed status rests on the release
date and the imported OpenJDK baseline rather than an explicit line.

The same patch set contains nine further Java SE CVEs (CVE-2026-114939 to CVE-2026-114947) and
OpenJFX **CVE-2026-86144** (javafx/web, 7.5). This dossier tracks 114938 only, but patch messaging
must not imply a single-CVE update.

---

## 4. Applications demonstrated vulnerable (vendor-reported by Calif; not reproduced by us)

Calif says it achieved RCE in default configurations on the following, on an affected JDK on a
VBMI-capable CPU. Treat as researcher evidence, not as our test result.

**Pre-authentication RCE:** Keycloak, Atlassian Jira, Atlassian Confluence, JFrog Artifactory,
Jenkins, PingFederate.

**Post-authentication RCE:** Apache Kafka Broker, Apache Solr, Elasticsearch, Gerrit, Spinnaker.

**Frameworks:** sample applications on Apache Struts and Spring Boot.

**Client side:** a Java program that opens a TLS connection to an attacker-controlled server can be
compromised even with no listening service; Calif credits samczsun for a client-side exploit.

Why pre-auth is common: Base64 is decoded in HTTP Basic authentication headers, SAML artifacts,
CSRF tokens and file uploads, often before any credential check.

---

## 5. Exploitation status

| Claim | Status |
|---|---|
| In-the-wild exploitation | **none reported** by Tenable, Check Point or Qualys as of 17–18 Nov; not in KEV | 
| Calif trigger PoC | **published**: shows whether a JDK+CPU reproduces the bug; does not give control | 
| Product-specific exploits | **withheld** by Calif, which says it will publish them later |
| Immersive (Kevin Breen) working exploit | **claimed on X**, app-specific, unreleased; unverified |
| Independent RCE reproduction | **not shown** publicly; Check Point says labs reproduced crashes and memory disclosure only |
| Root cause public | yes, since disclosure; Check Point claims a triggering input was visible since 9 September 2026 (unverified) |
| National CERT position | Canadian Centre for Cyber Security (AL26-029, 17 Nov): "not aware of active exploitation at this time, but that can change quickly"; CIRCL (TR-104, 18 Nov): not independently confirmed; Cisco Talos (17 Nov): not observed, anticipates probing soon. **Verified quotes, all as of 17–18 Nov** |
| Commercial exploit availability | **VulnCheck states a full RCE exploit is available to its Initial Access Intelligence customers as of 6 PM EST, 17 November**, with a version scanner, PCAP and detection rules. Not public, not verified by us. This is capability distribution, not evidence of use |

Assessment: the barrier to a first working exploit is **not** the trigger, it is the per-product
heap shaping. Expect product-specific exploits to appear in the coming days to weeks. A KEV addition
would change the calculus; there is no sign of one yet.

**Disclosure timeline and pre-disclosure history (added by Calif on 19 November; verified against the
primary repositories it names).** Calif published a timeline that materially changes the "who knew what
when" picture:

| Date (2026, Pacific) | Event |
|---|---|
| 9 June | **sundarms hit the bug in the wild** and opened an Adoptium support issue — a crash, months before disclosure |
| 8 September | sundarms posted a public PoC that reproduced the crash; **albertnetymk identified the root cause the same day** |
| 9 September | albertnetymk opened **openjdk/jdk#32781**, "8392044: AVX-512 Base64 decoder overwrites output buffer on short padded tail" |
| 4 November | **PR #32781 was closed without merging** (verified via GitHub API; created 9 Sep, closed 4 Nov) |
| 24 October | Quang Luong (Calif) independently found the bug with Codex; reported to Oracle with a **post-auth RCE PoC against Elasticsearch** |
| 29–31 October | Oracle asked for more information; Calif supplied **pre-auth PoCs against Jenkins and Keycloak** |
| 9 November | Calif told Oracle the bug was already public (in report form) and asked to start disclosure coordination |
| 13 November | Oracle said it had fixed the bug and would ship on 17 November, 13:00 Pacific |
| 14–17 November | Calif notified government agencies and industry partners |
| 17 November | Oracle released fixes and credited albertnetymk and Quang Luong; Calif published the write-up |
| 19 November | Calif added this timeline to its write-up |

Calif's framing is that the bug "had already been reported, but it was patched only after we showed it
could be exploited." The repository metadata supports the sequence: a public PoC from 8 September and a
fix PR opened 9 September, closed unmerged on 4 November, with the Oracle fix arriving 17 November.
**Calibrated labels:** the June "hit in the wild" is a *crash/reliability* report, not a demonstrated
compromise; no RCE is claimed for it. The Jenkins/Keycloak/Elasticsearch PoCs are Calif's own product-
specific work, released as claims with PoCs withheld. What this adds for defenders is motive to hunt
pre-September crash telemetry as well as post-17-November exploitation attempts.

**Observed PoC ecosystem (18 Nov 2026, verified against repository metadata):** GitHub returns 32
repositories for "java4shell" and 31 for the CVE id. The most-starred is `ikow/java4shell-poc` (★104),
described by its author as "OpenJDK AVX-512 Base64 heap overflow PoC, scanner & detection rules
(Suricata, Sigma, ModSecurity)"; it is by the same author as the PHP2Shell PoC repository. Also
prominent is `theori-io/java4shell-runtime-patch-CVE-2026-114938` (★17), which is not a defensive
scanner but a **third-party temporary runtime patch** supplied by Xint that attaches an agent to a
running JVM to disable the vulnerable intrinsic, installed with a `curl | sh` one-liner and stated to
be memory-only and lost on restart. Treat that one as unvetted third-party code with supply-chain
risk, not as a substitute for a vendor patch. The remainder are low-star repositories.

**We have inspected repository metadata and READMEs but not reviewed or run any code from them**, and
none is evidence of working RCE. Star counts measure attention, not capability. Programme rule: no
capability claim from a repository until we have run it ourselves and recorded the conditions.

**Exploitation attempts, 17–18 November (verified from GreyNoise's live dashboard, read 18 Nov 20:00 UTC).**
GreyNoise reports scanning and exploitation attempts against CVE-2026-114938:

- **4 source IPs** sent a Java4Shell trigger-shaped value in an HTTP `Authorization` header (Basic or
  Bearer) by 22:00 UTC on 18 Nov: `31.76.87[.]52`, `217.138.216[.]145`, `45.13.212[.]209`,
  `134.82.73[.]91`. By **19 Nov 21:00 UTC the count was 7 IPs and 197 shaped requests**, still **0
  successful intrusions**.
- **69 shaped requests by 20:00 UTC, 117 by 22:00 UTC on 18 Nov, 125 at 07:00, 187 at 09:00, 192 at
  14:00 and 197 at 21:00 on 19 Nov**, against paths such as `/`, `/api/`,
  `/rest/api-application/1.0/application-info` and `/rpc/xml`.
- **0 successful intrusions**; GreyNoise states it has "not confirmed successful exploitation against
  GreyNoise gridpoints yet".
- GreyNoise tags in use: **"Base64 Heap Overflow RCE Attempt v2"** (malicious) and **"Scanner Check"**
  (suspicious). User-agents seen include `java4shell-scanner/1.0`, `Go-http-client/1.1` and `nerva/1.0`;
  one JA4H fingerprint clusters three Amazon-AS16509 addresses (`po11nn070000_466fa246f160_...`).
- Tenable's 18 November update also states "GreyNoise has reported exploitation attempts ... but has not
  confirmed any successful exploitation against its sensors".

Reading: attempts are real and automated, but scanners sending a trigger shape are not proof of a
worked chain. "0 successful intrusions" is a sensor-scoped statement, not a global all-clear. If
GreyNoise's successful-intrusion counter moves off zero, that is the strongest public signal available
and should change the advisory's status line immediately.

**Ecosystem progression, 18 November 15:00 UTC:** the public repository set is no longer just PoC
material. At least four repositories now advertise full chains or probes, all by different authors and
all unverified by us: `TahuCryptsi/poc-cve-2026-114938-java4shell-base64-oob` (★1, "local + remote HTTP
RCE chain"), `FebusAI/java4shell-poc` (★0, "PoC + RCE chain + remote probe"), `AweiMC/Java4Shell-
Deterministic-DoS-PoC` (★5, deterministic denial of service) and `r3dvei1/java4shell` (★1, analysis and
lab stack, explicitly **no** chain). `ikow/java4shell-poc` rose to ★128. Their appearance is consistent
with the disclosure's own timeline (Calif said product-specific exploits would be published later) and
is a meaningful change in the exploitability landscape: the raw trigger is public, and these claims
suggest others are working the chains. It is **not** evidence of in-the-wild exploitation, and none of
the claims has been independently confirmed. Re-check before citing any of them; do not download and run
them on operational systems.


---

## 6. Detection and hunting

### 6.1 Inventory first

- Find JDK/JRE installations: package managers, container images, application bundles, appliances,
  build agents, and third-party products that embed a JVM (Atlassian, Jenkins, JFrog, Ping, and many
  others).
- Determine the **runtime version** and the **CPU flags** of hosts. Both gates must be true for
  exploitation: affected JDK and AVX-512 VBMI.
- Prioritise internet-facing services and anything that decodes attacker-supplied Base64
  (authentication, SAML, uploads, template rendering).

### 6.2 Host indicators

- JVM crash artefacts: `hs_err_pid*.log`, `core.*`, sudden JVM exits without graceful shutdown.
- Unexpected JVM restarts on internet-facing services, especially in bursts.
- Child processes spawned by the JVM (rare in most deployments) and unusual outbound connections
  from Java processes.
- New or rogue `java` installations appearing on hosts.

### 6.3 Network indicators

Network signature coverage for this bug is inherently weak: the trigger is a locally decoded Base64
string, and legitimate Base64 is everywhere. Candidate high-signal patterns, to be tested before
shipping:

- HTTP `Authorization: Basic …` values whose decoded content is a run of `A` ending in a single `=`
  at the malformed lengths the disclosure names.
- Form or JSON fields carrying the same pattern.
- Repeated malformed-Base64 submissions followed by JVM connection resets or 5xx, suggesting
  exploitation attempts that crash the process.

These are hypotheses until we build and test rules; the initial detection package should mark them
as such and avoid claiming coverage it does not have.

Vendor detection coverage as of 18 Nov: Check Point reports IPS protection for the public PoC, without a
published signature ID. That is vendor-reported and product-specific; it does not substitute for the
patch or for host-side monitoring of your own stack.

---

## 7. Mitigation

**Patch.** The complete fix is a fixed JDK build (OpenJDK advisory; Oracle CPU; vendor builds such as
Corretto above). Rebuild and restart dependent applications; a JVM that keeps running old classes is
still vulnerable.

**Where patching is not immediate, CISA recommends:** restrict and validate Base64 input at the
application boundary, enforce input-size limits, and limit unauthenticated access. These are
compensating controls, not fixes; they reduce exposure of specific endpoints and do not remove the
bug from the JVM.

**CPU reality check.** Hosts on CPUs without AVX-512 VBMI cannot reach the vulnerable code path, but
this must be verified per host and is not a reason to leave old JDKs in place.

**Temporary JVM startup flag (vendor-reported, mechanism verified in OpenJDK source, 18 Nov).** Check
Point recommends "a startup flag where you cannot patch today", and the Xint runtime-patch README names
it explicitly: **`-XX:-UseBASE64Intrinsics`**. Verified against OpenJDK source rather than taken on
trust: `UseBASE64Intrinsics` is a false-by-default diagnostic flag that `vm_version_x86.cpp` sets to
true on CPUs with AVX2 or better; `stubGenerator_x86_64.cpp` generates `_base64_decodeBlock` only
**inside `if (UseBASE64Intrinsics)`**, and installs the AVX-512 VBMI tables only when
`supports_avx512_vbmi()`. Disabling the flag therefore prevents the vulnerable intrinsic from being
installed at all. Caveats: it is a **performance trade** for Base64-heavy workloads, it must be applied
to every JVM launch path (systemd unit, container entrypoint, application server wrapper, build agents),
it can be overridden by a later `-XX:+UseBASE64Intrinsics` on the same command line, and it is **not a
fix**; patch as soon as the vendor build is available. Confirm the effective setting with
`java -XX:+PrintFlagsFinal -version | grep UseBASE64Intrinsics` on a disposable instance before rolling
it out. Check Point separately states that **Check Point IPS protection for the public PoC is available**
(a vendor-reported detection control; the public blog does not name the signature ID).

---

## 8. Open questions

1. Resolve the 8/11 affected-version inconsistency in the OpenJDK advisory (text versus risk matrix).
2. ~~Locate the OpenJDK source fix and confirm the exact commit.~~ **Resolved 19 November.** The fix
   commit is public: **openjdk/jdk `5177a70b385c16f26ede191fdac7aaba0bed0f8b`**, "8393212: Base64
   optimization improvements", authored by Tobias Hartmann on **13 October 2026**, touching
   `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`. The patch adds a **`cmpl(length, 4)` / jump-to-
   brute-force guard** in `generate_base64_decodeBlock()` so a padded Base64 tail shorter than a
   complete block is handled by Java rather than the assembly fast path. Verified via the GitHub API;
   the oss-security post of 19 November (Solar Designer) supplied the reference. This closes the
   "no linked fix" gap noted on 17 November.
3. Which vendors have published fixed builds beyond Corretto and Oracle (Temurin, Zulu, Microsoft,
   Liberica, SapMachine, Red Hat), with version numbers.
4. Product advisories: Atlassian, Jenkins, JFrog, Keycloak/Red Hat, Ping Identity — what do they
   patch or mitigate, and do they ship updated JVMs?
5. Whether AVX-512 VBMI lists are complete and reliable per CPU generation.
6. KEV: watch for addition; a KEV row would impose a US federal deadline and change urgency framing.
7. Whether product-specific exploits are published when Calif said they would be, and what that does
   to the exposure curve.
8. Long-lived exposure through appliances that will never receive a JDK update.

---

## 9. Vendor advisories

These are product-vendor responses beyond the JDK patch itself. They matter where a product embeds a JVM.

**Cisco (verified, read directly 18 November 2026).** Advisory
`cisco-sa-nov2026-java-rce-eCa6ss9z`, "Vulnerability in Oracle OpenJDK (Java4Shell) Affecting Cisco
Products": first published **2026-11-18 16:00 GMT**, **Version 1.0, Interim**. At that version Cisco
states it "is investigating its product line to determine which products may be affected" and **has not
yet listed any affected products or fixed releases**; there are **no workarounds**. Cisco's stated
hardware scope matches the disclosure: x86-64 with AVX-512 VBMI is affected, while x86-64 without
AVX-512 and ARM or Cisco Silicon One are not. Exploitation: Cisco PSIRT "is aware that proof-of-concept
exploit code is available" and "is not aware of any malicious use". Treat this as an open, evolving
advisory; re-read before quoting Cisco product exposure.

**Check Point (vendor-reported, updated 19 Nov).** Its post now replaces the earlier IPS sentence with a
claim that **Check Point WAF** "provides comprehensive, multilayered protection against the currently
validated Java4Shell exploitation techniques", combining "preemptive AI-based RCE prevention" with WAF
signatures that block the public Base64-decoder PoC. That is a vendor product claim, not an independent
test; treat it as vendor-reported. It still recommends patching as the only complete fix.

**Check Point mitigation guidance (vendor-reported).** Recommends a startup flag where patching cannot happen immediately
and reports IPS protection for the public PoC; its own update says patching remains the only complete
fix. The flag is verified in OpenJDK source (see §7).

**Siemens, second advisory SSA-810379 (verified, read directly 19 November 2026).** Published and last
updated **19 November**, V1.0, CVSS 3.1 **8.1**. It covers **Siveillance Control** and **Siveillance
Control Pro, all versions**, both **affected with no fix available**. The conditions match the general
disclosure: affected JVM (including bundled runtimes), x86-64 with AVX-512 VBMI, untrusted Base64 reaching
the decoder, and a JIT-compiled decoder. Mitigation is the same temporary JVM flag
(`-XX:-UseBASE64Intrinsics`) until Siemens ships fixes. This is in addition to SSA-272816 (Industrial
Edge Management Pro V1/V2/Virtual, also no fix).

**Red Hat (verified, read directly from the Red Hat CVE API 19 November 2026).** Severity **Critical**,
public date 2026-11-17T21:00Z. Fixed builds released **2026-11-18**: **Red Hat Build of OpenJDK
17.0.21.1**, **21.0.13.1** and **25.0.5.1** (portable and Windows packages). **RHEL channel errata
followed on 19 November**: the Red Hat CVE record now lists **29 fixed channel entries**, including
RHEL 8/9/10 `java-17-openjdk` **17.0.21.1.2**, `java-21-openjdk` **21.0.13.1.2** and `java-25-openjdk`
**25.0.5.1.2**, plus EUS, E4S, TUS and SAP Solutions channels. That resolves the earlier "channels still
listed Affected" caveat, which applied before the errata landed. Also listed
affected: **Red Hat Build of Keycloak** (`rhbk/keycloak-rhel9`), OpenShift Pipelines, Quarkus native
builders (mandrel), JBoss EAP 7/8 and JBoss Web Server 7 (OpenJDK 17 images), Red Hat Hardened Images
and the Konflux UBI OpenJDK 21 container. Java 8 and 11 builds are listed **not affected**, matching the
OpenJDK advisory's 17+ scope.

**Eclipse Temurin / Adoptium (verified from the project's own release metadata 19 November).** Fixed
builds published **2026-11-18**: **jdk-17.0.21.1+2**, **jdk-21.0.13.1+2** and **jdk-25.0.5.1+2**.
Keycloak's guidance says Temurin **Linux** builds are released while other platforms are still in
progress, so do not assume every platform has a fixed Temurin build yet.

**Ubuntu (verified from ubuntu.com/security/CVE-2026-114938, 19 November).** Fixes published **18
November** for **openjdk-17** (`17.0.21.1+2-1~<release>.1`, 20.04 through 26.10), **openjdk-21**
(`21.0.13.1+2-1~<release>.1`; on 20.04 the fix is via **Ubuntu Pro ESM Apps**, with no public community
fix yet), **openjdk-25** (`25.0.5.1+2-1~<release>.1`, 22.04 through 26.10) and **openjdk-27**
(`27.0.1.1+4-1~26.10.1`, on 26.10 only). Ubuntu priority: High. **Two packages remain vulnerable:
`openjdk-21-crac` and `openjdk-25-crac`** (the CRaC variants), and `openjdk-26` needs evaluation —
worth knowing if CRaC images are in use. Ubuntu's page is our source; the earlier monitor reading of
"Not in release / Ignored" cells was a parsing artefact of the wrong table, now fixed.

**Debian (verified from the Debian security tracker, 19 November).** Debian 13 trixie: **openjdk-21
`21.0.13.1+2-1~deb13u1` fixed** and **openjdk-25 `25.0.5.1+2-1~deb13u1` fixed**. Debian 12 bookworm:
**openjdk-17 `17.0.21.1+2-1~deb12u1` fixed in the security suite via DLA-4917-1**, although the base
bookworm pocket still carries `17.0.19+10-1~deb12u2` until a point release, which is why summaries can
call Debian 12 vulnerable; patch through the security/DLA channel. sid/forky carry fixed packages for
the newer lines.

**Tenable (vendor-reported product statement, 19 November).** Tenable's update states that its product
statement lists **Tenable Enclave Security and Tenable OT as affected** by CVE-2026-114938; the full
statement is Tenable's to publish, and we have not verified affected versions or fixed builds. Tenable
also added to its key takeaways that **no universal exploit exists** and included Keycloak's fixed
container images.

**Cisco, advisory v1.2 (verified, read directly 19 November 2026 20:22 GMT).** Cisco continues to expand
the advisory, Version 1.2, Interim, with **fixed releases still TBD** and **no workarounds**. The affected
list now covers: **Smart PHY**; **Connected Mobile Experiences** (11.2 TBD); **Secure Network Analytics**
(7.6.0 TBD); **Secure Workload**; **Cisco IQ Virtual Appliance** (v1.3.2 TBD); **Crosswork Assurance User
Experience**; **Crosswork Workflow Manager**; **License / Smart Software Manager On-Prem** (CSCwx86829,
10-202701 TBD); **cnBNG** (CSCwx86764, 2027.01 TBD); **Optical Network Planner** (26.4.1 and later);
**Services as Code CAF** (CSCwx86765, CAF 1.33 TBD); **Splunk AppDynamics On-Premises Enterprise Console**
(CSCwx86817) and **Virtual Appliance** (CSCwx86817, 27.1.0 TBD); **NextFusion Platform**; **Ultra Cloud
Core Network Repository Function** (CSCwx86832); **Ultra Cloud Core Subscriber Microservices
Infrastructure**; **Intersight Virtual Appliance**; **Finesse** (CSCwx86820, 15.0(1)SU3 TBD); **Unified
Contact Center Enterprise** (CSCwx86838); **Unified Customer Voice Portal** (CSCwx86786); **Unified
Intelligence Center** (CSCwx86841, 15.0(1)SU3 TBD); **Virtualized Voice Browser** (CSCwx86842). Catalyst
Center has bug ID CSCwx86774. **IOS XE and UCS Central moved from "under investigation" to Not
affected** in v1.2. Many earlier "Not affected" entries stand (SD-WAN Controller/Manager/Validator, ISE,
IOS XR, Nexus Dashboard, NX-OS, ASA, FMC, FTD, UCS Director). No workarounds.

**Apache Shiro (verified, read directly 18 November 2026).** Not a vulnerability in Shiro itself, but
Shiro's `CookieRememberMeManager` Base64-encodes serialized identity data into the remember-me cookie and
decodes it on read via `java.util.Base64`, so a request through that path can reach the vulnerable decoder.
Exposure still depends on runtime, CPU and whether the application reaches it. Remediation is a fixed JDK;
changing the Shiro version does not fix it. Shiro repeats the JVM-option mitigation
(`JAVA_TOOL_OPTIONS='-XX:-UseBASE64Intrinsics'`) as temporary. Practical consequence: Shiro remember-me
cookies are another **pre-authentication** Base64 sink, alongside HTTP Basic auth.

**Siemens (verified, read directly 18 November 2026).** SSA-272816, "Java4Shell Vulnerability in
Industrial Edge", **V1.0, published 2026-11-18**, CVSS 3.1 8.1. **Affected with no fix available at V1.0:**
Industrial Edge Management Pro V1, IEM Pro V2 and IEM Virtual, all versions. Known not affected:
Industrial Edge Device Kit (no Java) and IEM Cloud (different platform). Siemens lists four required
conditions: an affected JVM (including bundled runtimes), x86-64 with AVX-512 VBMI, untrusted Base64
reaching `Base64.getDecoder()`/`getUrlDecoder()`, and a JIT-compiled decoder. Its mitigation is blunt:
**block direct internet access to IEM Pro/IEM Virtual, or shut instances down until a fix exists.** This
is the clearest "affected but unpatched" product case so far.

**Keycloak (verified, read directly 18 November 2026, last updated 09:29 UTC).** The Keycloak team
states that container images `26.8.2-1` and `26.8.2-2` bundle an affected **OpenJDK 21.0.13**; the ZIP/TAR
distribution can also be affected depending on its runtime and CPU. Keycloak decodes Base64 before
authentication, so a login requirement is not protection. Preferred interim mitigation is Red Hat's
`-XX:-UseBASE64Intrinsics` via `JAVA_OPTS_APPEND`, with `JDK_JAVA_OPTIONS` for the Operator, verified on
the live JVM with `jcmd ... VM.flags -all | grep UseBASE64Intrinsics` (expected
`UseBASE64Intrinsics = false`). **Update, 19 November 08:00 UTC: fixed images are now available.** The Keycloak team reports that
**Keycloak container images for 26.8 have been updated to Red Hat OpenJDK 21.0.13.1**, which includes
the fix for CVE-2026-114938; the updated tags include `latest`, `26.8`, `26.8.2` and **`26.8.2-3`**.
It names fixed versions **17.0.21.1, 21.0.13.1 and 25.0.5.1**, states that Oracle and Red Hat have
released updates, that **Eclipse Temurin for Linux** has been released while other platforms are "in
progress", and warns that older OpenJDK 17/21/25 releases remain affected. Treat Keycloak version
numbers alone as insufficient; verify the bundled runtime, and prefer moving to a fixed image over
keeping the flag.

No other product-vendor advisory has been verified by us as of 18 November 2026. Atlassian, Jenkins,
JFrog, Keycloak/Red Hat and Ping Identity advisories are being watched; absence here means unverified,
not that none exists.

## 10. Sources (accessed 18 November 2026)

Primary:

- Calif.io disclosure and trigger PoC: https://calif.io/java4shell
- Oracle Critical Security Patch Update, November 2026: https://www.oracle.com/security-alerts/cspunov2026.html
- OpenJDK vulnerability advisory 2026-11-17: https://openjdk.org/groups/vulnerability/advisories/2026-11-17
- NVD record: https://nvd.nist.gov/vuln/detail/CVE-2026-114938
- CISA alert, 17 November 2026: https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching
- Cisco advisory (interim, read directly): https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nov2026-java-rce-eCa6ss9z
- Siemens SSA-272816 (read directly): https://cert-portal.siemens.com/productcert/html/ssa-272816.html
- Siemens SSA-810379 (Siveillance Control / Control Pro): https://cert-portal.siemens.com/productcert/html/ssa-810379.html
- OpenJDK pre-disclosure fix PR (closed unmerged): https://github.com/openjdk/jdk/pull/32781
- Keycloak guidance: https://www.keycloak.org/2026/11/java4shell-vulnerability-cve-2026-114938
- Red Hat CVE API record: https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-114938.json
- Adoptium Temurin release metadata (temurin17/21/25-binaries, latest releases)
- Apache Shiro guidance: https://shiro.apache.org/blog/2026/11/apache-shiro-java4shell.html
- oss-security thread, 19 November (fix commit reference): http://www.openwall.com/lists/oss-security/2026/11/19/5
- OpenJDK fix commit: https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b
- GreyNoise live activity dashboard (read directly): https://java4shell.events.greynoise.io/
- Canadian Centre for Cyber Security AL26-029: https://www.cyber.gc.ca/en/alerts-advisories/al26-029-critical-vulnerability-impacting-oracle-java-cve-2026-114938
- Cisco Talos analysis: https://blog.talosintelligence.com/java4shell/
- CIRCL TR-104: https://www.circl.lu/pub/tr-104/
- NCSC New Zealand alert: https://www.ncsc.govt.nz/alerts/cve-2026-114938-affecting-openjdk/
- oss-security thread: http://www.openwall.com/lists/oss-security/2026/11/17/31
- Amazon Corretto changelogs: https://github.com/corretto (branches 8, 11, 17, 21, 25, 27)

Secondary (vendor analysis, treat as vendor-reported):

- Tenable FAQ: https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability
- Check Point: https://blog.checkpoint.com/security/java4shell-cve-2026-114938-check-your-java-services-now
- Qualys: https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now
- The Record: https://therecord.media/cisa-issues-java4shell-alert
- VulnCheck analysis (states commercial RCE exploit availability): https://www.vulncheck.io/blog/java4shell
- Aikido analysis: https://www.aikido.dev/blog/java-17-rce-vulnerability-cve-2026-114938
- POLITICO: https://www.politico.com/news/2026/11/17/java-cyber-programming-vulnerability-01171822

Context note (not for publication): Calif.io is the same research group that disclosed PHP2Shell,
which this monitoring programme already tracks. That is a fact about the researchers. No source has
established a shared campaign, common actor or coordinated targeting, and nothing in the Java4Shell
record should be presented as connected to the PHP2Shell exploitation campaign.
