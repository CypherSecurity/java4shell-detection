# Validation report — 18 November 2026

This report records what was actually tested, with versions and results. It exists because "the
rules look right" is not validation. Commands and outcomes below were run on 2026-11-18.

## 1. Sigma rules

Tooling: `sigma-cli 4.0.1` (pySigma), Python 3.12, in a disposable virtual environment.

`sigma check 02-detections/sigma/` → **0 rule errors, 0 condition errors, 0 validation issues**.

Conversion: `sigma convert -t splunk --without-pipeline 02-detections/sigma/` produced three queries
(one per rule), confirming the rules parse and translate. A full pipeline conversion was not used
because the Splunk CIM pipeline does not model generic `file_event` logs; this is a pipeline
limitation, not a rule defect.

Defect found and fixed during validation: the original restart-burst rule used the deprecated
in-detection pipe aggregation (`| count() by ... > 3`), which pySigma rejects. It was replaced with a
proper Sigma **correlation** rule (`event_count` over the base crash-file rule, grouped by `Computer`,
15-minute timespan, threshold 3). The base rule now carries a stable `name` for the correlation
reference.

## 2. Suricata rules

Tooling: `jasonish/suricata:latest` (Suricata 8.0.8 RELEASE) in Docker, default container config.

| Test | Result |
|---|---|
| Rule load (`suricata -T -S java4shell.rules`) | **2 rules successfully loaded, 0 failed, 0 skipped** |
| Negative control: deliberately malformed rule | **parse error reported and load failed** — the test detects real defects |
| Synthetic trigger pcap: HTTP request with `Authorization: Basic <64 A>=` over a complete TCP session | **2 alerts**, SIDs `2202611001` and `2202611002` |
| Benign control pcap: normal `Authorization: Basic dXNlcjpwYXNz` | **0 alerts** |

The trigger and benign captures were generated locally with Scapy and are retained under
`java4shell-intel/triage/pcaps/`; they are test fixtures, not exploit tooling. The trigger only
demonstrates that the rule matches the malformed shape; it does not exercise the bug.

Limitations: no production traffic was replayed, so false-positive rate on real customer traffic is
unknown. The rules remain marked experimental. Rule 1 can match legitimate traffic in which a
Base64-looking token begins with a long run of `A`; this is uncommon but possible, and is exactly
why the rules should start alert-only.

## 3. Exposure checker

`02-detections/common/check-java4shell-exposure.sh` was tested with eleven stub `java` binaries
covering the affected and patched lines:

| Stub version string | Verdict |
|---|---|
| `21.0.13` | AFFECTED_BASE |
| `21.0.13.1` | PATCHED_LIKELY |
| `17.0.5` | NOT_AFFECTED_PRE_17.0.6 |
| `17.0.21` | AFFECTED_BASE |
| `17.0.21.1` | PATCHED_LIKELY |
| `11.0.32` | AFFECTED_BASE |
| `11.0.33.1` | PATCHED_LIKELY |
| `1.8.0_512` | AFFECTED_BASE |
| `1.8.0_513` | PATCHED_LIKELY (following CCCS AL26-029, which names 8u513-perf as the fixed Oracle build) |
| `1.8.0_514` | PATCHED_LIKELY |
| `27.0.1` | AFFECTED_BASE |
| `27.0.1.1` | PATCHED_LIKELY |

Both text and `--json` output modes were exercised. On a host without Java the script reports zero
runtimes without error.

Limitations: the verdict is a **base-version heuristic**. Vendors with different numbering
(for example a build string `21.0.13+1` rather than `21.0.13.1`) may be classified as AFFECTED_BASE;
that errs toward caution, and the output tells the reader to verify the vendor build. The
"17.0.6 or newer" introduction line comes from a researcher statement reported by oss-security, not
from the OpenJDK advisory, and is labelled as such.

## 4. Published GitHub artifacts

| Check | Result |
|---|---|
| Repo tree | **15 blobs**, matching the package's 15 files |
| Release `v2026-11-17` | ZIP **26,230 bytes**, SHA256 sidecar present |
| Cache-busted re-download | SHA256 matches local `e6ce6d86d1742581…` |
| Page <https://f4n6.co.uk/java4shell/> | shows the same SHA and size, status lines present |

**Revalidation, 18 Nov 16:00 UTC:** classifier changed after the Canadian Centre published a fixed-build
table (8u513-perf for Oracle Java 8); stubs 8u512 / 8u513 / 8u514 now return AFFECTED_BASE /
PATCHED_LIKELY / PATCHED_LIKELY respectively, tested after the change.

## 5. Not validated

- No exploitation was attempted or reproduced; no crash or RCE was produced.
- No SIEM/EDR deployment test of the Sigma rules (conversion only).
- No Windows artifact test (rules are platform-neutral but the crash-path examples are Linux-heavy).
- No production-traffic false-positive measurement for the Suricata rules.
- Fixed builds beyond Corretto/Oracle remain unverified.
