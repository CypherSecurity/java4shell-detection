# Validation notes — package testing status

Honesty about what was tested matters more than rule counts here.

## Tested

See `VALIDATION-REPORT.md` for the full record with tool versions and outcomes.

- **Suricata rules**: loaded in Suricata 8.0.8 (2/2 rules, 0 failed); both rules fired on a synthetic
  malformed-Base64 request and neither fired on a benign Basic-auth control. A deliberately broken
  rule was correctly rejected, proving the test detects errors. Still **experimental**: no
  production traffic tested, so false-positive rate is unknown and rules should start alert-only.
- **Sigma rules**: `sigma check` with sigma-cli 4.0.1 returned 0 errors, 0 condition errors and 0
  validation issues; converted to Splunk queries. The original restart-burst rule used deprecated
  aggregation syntax and was replaced with a Sigma correlation rule during validation.
- **Exposure checker**: eleven stub JDK versions across the affected and patched lines produced the
  expected verdicts in text and JSON modes.
- Corretto fixed-version numbers: read from each branch's CHANGELOG (raw.githubusercontent.com).
- Oracle/OpenJDK/NVD/CISA/NCSC source facts: read directly on 18 November 2026.

## Not tested

- **Any exploitation**: we did not run the public trigger, PoCs or any chain. No crash or RCE was
  reproduced by us. Capability statements in the dossier are attributed, not our test results.
- **Production traffic** for the Suricata rules, and **SIEM deployment** for the Sigma rules.
- **Windows-specific artefacts**; examples are Linux-heavy.
- **The exposure checker on vendor builds with unusual version numbering**; the verdict is a
  heuristic and says so in its output.

## If you test the fix locally

Do it on a disposable VM. Confirm the JDK version before and after, then verify the CPU gate. The
public trigger is documented in prose and is not included here as a runnable script, deliberately.
