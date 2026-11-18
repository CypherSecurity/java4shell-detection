#!/usr/bin/env bash
# check-java4shell-exposure.sh — read-only exposure check for CVE-2026-114938.
#
# Reports every Java runtime found in common locations, its version, a base-version verdict against
# the affected/fixed line, and whether the CPU exposes the AVX-512 VBMI gate required to reach the
# vulnerable code. Contains no exploit code and triggers nothing; it reads files and versions only.
#
# The verdict is a HEURISTIC on the base version string, because vendors number their patched builds
# differently (for example Corretto 21.0.13.1.2 versus OpenJDK 21.0.13). Treat AFFECTED as "investigate
# and verify the vendor build"; treat PATCHED as "has a patch-level component above the affected base".
#
# Usage: bash check-java4shell-exposure.sh [--json]
set -uo pipefail
JSON=0; [ "${1:-}" = "--json" ] && JSON=1

CPU_OK="no"
if [ -r /proc/cpuinfo ] && grep -m1 '^flags' /proc/cpuinfo >/dev/null 2>&1; then
  FLAGS=$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2)
  n=0; for f in avx512f avx512bw avx512vbmi bmi2; do case " $FLAGS " in *" $f "*) n=$((n+1));; esac; done
  [ "$n" -eq 4 ] && CPU_OK="yes"
fi

# compare dotted numeric versions: returns 0 if $1 >= $2
ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

classify() {
  local v="$1" verdict="UNKNOWN"
  if [[ "$v" =~ ^1\.8\.0_([0-9]+) ]]; then
    local u="${BASH_REMATCH[1]}"
    if [ "$u" -le 512 ]; then verdict="AFFECTED_BASE"; elif [ "$u" -le 513 ]; then verdict="UNKNOWN"; else verdict="PATCHED_LIKELY"; fi
  elif [[ "$v" =~ ^8u([0-9]+) ]]; then
    local u="${BASH_REMATCH[1]}"
    if [ "$u" -le 512 ]; then verdict="AFFECTED_BASE"; elif [ "$u" -le 513 ]; then verdict="UNKNOWN"; else verdict="PATCHED_LIKELY"; fi
  elif [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
    local maj="${BASH_REMATCH[1]}" min="${BASH_REMATCH[2]}" pat="${BASH_REMATCH[3]}"
    local extra="${BASH_REMATCH[5]}"
    local base="$maj.$min.$pat"
    case "$maj" in
      11) [ -n "$extra" ] && verdict="PATCHED_LIKELY" || verdict="AFFECTED_BASE" ;;
      17) if ! ge "$base" "17.0.6"; then verdict="NOT_AFFECTED_PRE_17.0.6"
          elif [ -n "$extra" ]; then verdict="PATCHED_LIKELY"
          else verdict="AFFECTED_BASE"; fi ;;
      21|25|27) [ -n "$extra" ] && verdict="PATCHED_LIKELY" || verdict="AFFECTED_BASE" ;;
      *)  ge "$base" "17.0.6" && verdict="UNKNOWN_VERIFY_VENDOR" || verdict="NOT_AFFECTED_PRE_17.0.6" ;;
    esac
  fi
  printf '%s' "$verdict"
}

JAVAS=()
while IFS= read -r j; do [ -n "$j" ] && JAVAS+=("$j"); done < <(
  { command -v java 2>/dev/null || true
    ls -1 /usr/lib/jvm/*/bin/java /opt/*/bin/java /opt/*/*/bin/java 2>/dev/null || true
    find /usr/local -maxdepth 4 -type f -name java -perm -u+x 2>/dev/null | head -20
  } | sort -u
)
ROWS=()
for j in ${JAVAS[@]+"${JAVAS[@]}"}; do
  line=$("$j" -version 2>&1 | head -1 | tr -d '\r')
  ver=$(printf '%s' "$line" | sed -n 's/.*version "\([^"]*\)".*/\1/p')
  [ -n "$ver" ] || ver="unknown"
  verdict=$(classify "$ver")
  ROWS+=("$j|$ver|$verdict")
done

if [ "$JSON" -eq 1 ]; then
  printf '{"cpu_vbmi":"%s","affected_base_versions":"27.0.1 / 25.0.5 / 21.0.13 / 17.0.21 / 11.0.33 / 8u512 and earlier","runtimes":[' "$CPU_OK"
  first=1
  for row in ${ROWS[@]+"${ROWS[@]}"}; do
    IFS='|' read -r p v d <<<"$row"
    [ $first -eq 0 ] && printf ','; first=0
    printf '{"path":"%s","version":"%s","verdict":"%s"}' "$p" "$v" "$d"
  done
  printf ']}\n'; exit 0
fi
echo "Java4Shell (CVE-2026-114938) exposure check — $(date -u +%FT%TZ)"
echo "CPU AVX-512 VBMI gate: $CPU_OK   (needs avx512f, avx512bw, avx512vbmi, bmi2)"
echo "Java runtimes found: ${#ROWS[@]}"
for row in ${ROWS[@]+"${ROWS[@]}"}; do
  IFS='|' read -r p v d <<<"$row"
  printf '  %-42s %-16s %s\n' "$p" "$v" "$d"
done
echo
echo "AFFECTED_BASE = base version at or below the affected line; verify the vendor build."
echo "PATCHED_LIKELY = has a patch-level component above the affected base (vendor builds vary)."
echo "Exposure also needs the CPU gate and an application that Base64-decodes attacker input."
echo "Fixed builds and vendor numbering: PATCH-AVAILABILITY.md."
exit 0
