# Hunting guide — Java4Shell (CVE-2026-114938)

Hunting hypotheses, highest value first. The vulnerability is only reachable on an affected JDK on
an AVX-512 VBMI CPU, so start by bounding the population, then look for effects.

## H1: JVM crash artefacts on internet-facing Java services

Look for `hs_err_pid*.log`, core dumps and `java` processes that died without graceful shutdown:
- Linux: `find / -name 'hs_err_pid*' -newermt '-14 days' 2>/dev/null`
- Container/k8s: check terminated containers with exit code 134/139 (SIGABRT/SIGSEGV), restart counts
  and crash-loop backoffs.
- Windows: `%TEMP%`/application directory `hs_err_pid*.log`, Event Viewer application crash entries for
  `java.exe`.

A failed exploitation attempt often crashes the JVM. A single crash is common; a pattern on an
internet-facing service, especially clustered in time with malformed Base64 requests, is worth
escalating.

## H2: Restart and availability anomalies

- Restart counts for Java services in the last 7-14 days versus baseline.
- 5xx or connection-reset bursts on authentication/upload endpoints.
- Kubernetes `CrashLoopBackOff` transitions on Java workloads with no deployment change.

## H3: Post-exploitation process behaviour

- `java` spawning shells (`/bin/sh`, `bash`, `cmd.exe`, `powershell.exe`) or download utilities.
- New listening ports or outbound connections owned by the JVM user.
- New files in tmp/watch directories, new cron jobs or systemd units under the service account.

## H4: JVM inventory drift

- New `java` installations appearing outside the package manager, especially under `/tmp`, `/opt`,
  `/dev/shm` or user home directories.
- Containers running `openjdk`/`temurin`/`corretto` images older than 17 Nov 2026 where rebuild is
  feasible.

## H5: "JavaBleed" data exposure

The disclosure describes heap disclosure of private keys, tokens and credentials without code
execution. There is no reliable network signature for that, so hunt covers it indirectly:
- Unexpected authentication token reuse or key material appearing in subsequent access logs.
- Anomalous TLS or JWT signing behaviour from the Java service.
- For high-value identity providers, treat unexplained JVM crashes as potential disclosure attempts
  and review key rotation.

## False-positive discipline

JVM crashes occur for ordinary reasons (OOM, native library faults, application bugs). Correlate with
Base64-shaped request patterns and with exposure (affected JDK + VBMI CPU) before concluding
exploitation. We have not seen confirmed in-the-wild exploitation as of 18 November 2026; hunt
findings must not be reported as such without a primary source.
