# Java4Shell (CVE-2026-114938) — start here

Read this in two minutes, then do the four actions in order.

## What it is

A memory-corruption bug in OpenJDK's AVX-512 Base64 decoder. A short malformed Base64 input
causes a write of about 62 bytes past a 50-byte buffer. The JVM rejects the input after the write.
Consequences range from heap disclosure of secrets ("JavaBleed") to remote code execution with an
application-specific chain. Disclosed 17 November 2026 by Calif.io; fixed builds are out.

## Two gates, both required

1. **Vulnerable JDK**: OpenJDK 27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3, 17.0.21.0.3, 11.0.33, 8u512 and
   earlier (the advisory also marks only 17-27 in its risk matrix; see dossier section 3).
2. **CPU with AVX-512 VBMI**: Intel Ice Lake / Sapphire Rapids / Emerald Rapids / Granite Rapids,
   AMD Zen 4 or newer. Without VBMI the vulnerable assembly path is not executed.

A host is exploitable only if both are true **and** it runs code that Base64-decodes
attacker-influenced data.

## Do these four things

1. **Inventory** — run `02-detections/common/check-java4shell-exposure.sh` on representative hosts
   (see `03-guidance/INVENTORY.md`). It reports installed Java versions, a base-version verdict
   (AFFECTED_BASE / PATCHED_LIKELY / NOT_AFFECTED_PRE_17.0.6 / UNKNOWN) and the CPU gate. The verdict
   is a heuristic: verify the vendor build. It is read-only and contains no exploit code.
2. **Patch** — apply the vendor build for your platform (`PATCH-AVAILABILITY.md`). Rebuild and
   restart dependent applications.

   If you cannot patch immediately, `-XX:-UseBASE64Intrinsics` prevents the vulnerable intrinsic from
   being installed. It is a **temporary performance trade, not a fix**; details and caveats in
   `03-guidance/MITIGATION.md`.
3. **Detect** — deploy `02-detections/` rules. The Suricata rules are **experimental** and marked as
   such: they match malformed Base64 trigger shapes, which legitimately occur in some traffic.
   Test in a SPAN before blocking. The Sigma rules monitor JVM crash artefacts and unusual Java
   process behaviour and are safer to enable immediately.
4. **Hunt** — use `04-hunting/HUNTING.md` to look for JVM crashes, restarts and post-exploitation
   behaviour on internet-facing Java services.

## What this package does not contain

No exploit code, no product-specific chains, no weaponised test. The public trigger is described in
prose for detection purposes only. We have not reproduced RCE; see `BUILD-INFO.md` for exactly what
was verified.
