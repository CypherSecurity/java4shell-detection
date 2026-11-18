# Mitigation guidance — Java4Shell (CVE-2026-114938)

## The fix

Apply the fixed JDK build for your platform (`PATCH-AVAILABILITY.md`). Rebuild and restart the
dependent applications: replacing files on disk without restarting leaves the vulnerable JVM running.

Frequency of patch cadence does not matter here; a CPU path in the runtime is not mitigated by
application configuration.

## Temporary JVM startup flag (verified mechanism, temporary mitigation)

`-XX:-UseBASE64Intrinsics` disables the HotSpot Base64 intrinsic. Verified against OpenJDK source on
18 November 2026: the flag gates generation of `_base64_decodeBlock` in `stubGenerator_x86_64.cpp`, and
the AVX-512 VBMI tables are only installed when the CPU supports VBMI. With the flag off, the
vulnerable intrinsic is not installed at all.

Apply it to every JVM launch path: systemd units, container entrypoints, application-server wrappers,
build agents, and anything that bundles its own JRE. Example:

    JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"   # honoured by most JVMs
    java -XX:-UseBASE64Intrinsics ...              # or directly in the launch command

Confirm the effective value per host on a disposable instance:

    java -XX:+PrintFlagsFinal -version | grep UseBASE64Intrinsics

Caveats: it costs Base64 decode throughput; it can be overridden by a later
`-XX:+UseBASE64Intrinsics`; it is **not a fix** and must not delay patching. Ensure no other
JVM-level option re-enables the intrinsic.

## Product-specific interim steps (verified from vendor guidance, 18 Nov)

**Keycloak.** The Keycloak team reports that images `26.8.2-1` and `26.8.2-2` bundle an affected
OpenJDK 21.0.13, and that session protection is not enough because Keycloak decodes Base64 before
authentication. Set the flag through the startup options the image already honours and restart every
instance:

    JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics"      # Keycloak server
    JDK_JAVA_OPTIONS="-XX:-UseBASE64Intrinsics"      # Keycloak Operator (separate JVM)

For the Operator, set the variable on the Deployment or in the OLM Subscription so it survives
reconciliation. Verify the running JVM, not the environment variable:

    jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics
    # expected: bool UseBASE64Intrinsics = false {product} {command line}

Check every pod and failover node. At the time of writing the Keycloak team had not published a
recommended fixed image; take rebuilt images when they appear.

**Siemens Industrial Edge.** SSA-272816 lists Industrial Edge Management Pro V1, Pro V2 and Virtual as
affected with **no fix available at V1.0**. Siemens' mitigation is to block direct internet access to
IEM Pro / IEM Virtual, or shut the instances down, until a fix is released. Do not expose these
management interfaces while unpatched.

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
