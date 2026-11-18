# Mitigation guidance — Java4Shell (CVE-2026-114938)

## The fix

Apply the fixed JDK build for your platform (`PATCH-AVAILABILITY.md`). Rebuild and restart the
dependent applications: replacing files on disk without restarting leaves the vulnerable JVM running.

Frequency of patch cadence does not matter here; a CPU path in the runtime is not mitigated by
application configuration.

## While patching is in progress

CISA recommends restricting and validating Base64 input at the application boundary, enforcing
input-size limits and limiting unauthenticated access. Practical interpretation:

- Put authentication in front of internet-facing Java management interfaces and APIs where you can
  (reverse proxy, mesh policy, network ACLs). This does not fix the bug but removes unauthenticated
  reach.
- Enforce request size limits and reject obviously malformed Base64 at the edge where your proxy can
  do it safely. Do not try to pattern-match the trigger at the WAF as a primary control; legitimate
  Base64 is common and the trigger is only 65 characters.
- Reduce exposure of secondary endpoints that decode Base64 before authentication: file uploads,
  SAML endpoints, password-reset and token endpoints.
- Segment build agents and internal CI, which often run older JVMs than production.

## Detection while patching

- Watch for `hs_err_pid*.log` files and JVM crash loops on internet-facing Java services.
- Watch for unexpected JVM restarts and for Java processes spawning shells.
- Review authentication and upload endpoint logs for abnormal volumes of malformed Base64.
- If you have EDR, look for unexpected child processes of `java` and for outbound connections from
  JVM processes that are not your application's normal dependencies.

## What not to do

- Do not disable Base64 decoding globally; the JDK has no such switch and applications depend on it.
- Do not rely on disabling the AVX-512 path alone. There is no supported per-application switch, and
  vendor patches are the only complete fix.
- Do not claim the host is safe because an AVX-512 VBMI check fails unless the check was run on the
  actual host, under the account and container the service uses.
