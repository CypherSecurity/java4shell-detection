# SOC triage playbook — Java4Shell (CVE-2026-114938)

## Alert classes you are likely to see

1. **JVM crash artefacts / crash loop** on a Java service.
2. **Malformed Base64 shape** in HTTP (experimental Suricata rules).
3. **Java process spawns shell** (post-exploitation).
4. **Java service restart anomaly** correlated with 5xx bursts.

## Triage steps

1. **Bound exposure**: is the host running an affected JDK (see `PATCH-AVAILABILITY.md`), does its
   CPU expose AVX-512 VBMI, and does the service decode attacker-influenced Base64?
2. **Establish timing**: when did crashes/restarts begin, and do request logs show malformed Base64
   to an authentication, upload or SAML endpoint in the same window?
3. **Assess impact**: is the JVM user able to read sensitive material (keys, tokens, environment
   secrets)? Did the process spawn anything, open new connections or write files?
4. **Contain if confirmed**: isolate or snapshot the host, rotate secrets the JVM could read, and
   preserve `hs_err_pid*.log` and core dumps for analysis.
5. **Report**: state what is verified versus suspected. A crash plus malformed requests is not proof
   of successful exploitation. Only a primary source (vendor IR, CISA/NCSC, forensic finding) justifies
   saying "exploited".

## Do not

- Do not classify a single JVM crash as exploitation without correlation.
- Do not claim the vulnerability is being exploited in the wild; no confirmed case exists as of
  18 November 2026.
