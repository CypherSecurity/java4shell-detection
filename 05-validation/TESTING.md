# Validation notes — package testing status

Honesty about what was tested matters more than rule counts here.

## Tested

- `02-detections/common/check-java4shell-exposure.sh`: run on a Linux host without Java and without
  AVX-512 VBMI. Output parsed correctly in text and JSON modes; no writes, no network calls.
- Corretto fixed-version numbers: read from each branch's CHANGELOG (raw.githubusercontent.com).
- Oracle/OpenJDK/NVD/CISA/NCSC source facts: read directly on 18 November 2026.

## Not tested

- **Suricata rules**: syntactically written but **not loaded or tested against traffic**. Treat as
  draft content. Expect false positives from legitimate Base64; run alert-only and tune. Do not
  enable as blocking without local validation.
- **Sigma rules**: written against standard Sigma schemas (`file_event`, `process_creation`,
  `systemd`). Not executed through a backend (no Splunk/Elastic/Sentinel conversion tested). The
  restart-burst rule depends on your systemd telemetry exposing `Unit`, which many pipelines do not
  by default; adapt it.
- **Any exploitation**: we did not run the public trigger, PoCs or any chain. No crash or RCE was
  reproduced by us. Capability statements in the dossier are attributed, not our test results.

## If you test the fix locally

Do it on a disposable VM. Confirm the JDK version before and after, then verify the CPU gate. The
public trigger is documented in prose and is not included here as a runnable script, deliberately.
