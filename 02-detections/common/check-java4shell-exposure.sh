#!/usr/bin/env bash
# check-java4shell-exposure.sh — read-only exposure check for CVE-2026-114938.
#
# Reports: every Java runtime found in common locations, its version, and whether the CPU exposes
# the AVX-512 VBMI gate required to reach the vulnerable code. Contains no exploit code and triggers
# nothing; it reads files and versions only.
#
# Usage: bash check-java4shell-exposure.sh [--json]
# Exit: 0 = report produced (look at it), 2 = missing basic tooling.
set -uo pipefail
JSON=0; [ "${1:-}" = "--json" ] && JSON=1
CPU_OK="no"; FLAGS=""
if [ -r /proc/cpuinfo ] && grep -m1 '^flags' /proc/cpuinfo >/dev/null 2>&1; then
  FLAGS=$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2)
  n=0; for f in avx512f avx512bw avx512vbmi bmi2; do case " $FLAGS " in *" $f "*) n=$((n+1));; esac; done
  [ "$n" -eq 4 ] && CPU_OK="yes"
fi
JAVAS=()
while IFS= read -r j; do [ -n "$j" ] && JAVAS+=("$j"); done < <(
  { command -v java 2>/dev/null || true
    ls -1 /usr/lib/jvm/*/bin/java /opt/*/bin/java /opt/*/*/bin/java 2>/dev/null || true
    find /usr/local -maxdepth 4 -type f -name java -perm -u+x 2>/dev/null | head -20
  } | sort -u
)
declare -a VER=()
for j in ${JAVAS[@]+"${JAVAS[@]}"}; do
  v=$("$j" -version 2>&1 | head -1 | tr -d '\r')
  VER+=("$j|${v:-version-unreadable}")
done
if [ "$JSON" -eq 1 ]; then
  printf '{"cpu_vbmi":"%s","runtimes":[' "$CPU_OK"
  first=1
  for row in "${VER[@]}"; do
    p=${row%%|*}; v=${row#*|}
    [ $first -eq 0 ] && printf ','; first=0
    printf '{"path":"%s","version":"%s"}' "$p" "$v"
  done
  printf ']}\n'
  exit 0
fi
echo "Java4Shell (CVE-2026-114938) exposure check"
echo "Date: $(date -u +%FT%TZ)"
echo "CPU AVX-512 VBMI gate: $CPU_OK   (needs avx512f, avx512bw, avx512vbmi, bmi2)"
if [ "$CPU_OK" = "no" ]; then
  echo "  This CPU does not reach the vulnerable decoder path. Keep the JDK patched anyway."
fi
echo "Java runtimes found: ${#VER[@]}"
for row in ${VER[@]+"${VER[@]}"}; do echo "  ${row%%|*}  ->  ${row#*|}"; done
echo
echo "Affected-fix line (from vendor advisories): 27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3,"
echo "17.0.21.0.3, 11.0.33, 8u512 and earlier are affected. Fixed builds per vendor are in"
echo "PATCH-AVAILABILITY.md. A host with an affected JDK and the VBMI gate is exposed if any"
echo "process Base64-decodes attacker-influenced data."
exit 0
