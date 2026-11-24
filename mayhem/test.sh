#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# 1) Upstream's own test suite (tests/qttest, tests/catch, tests/modal-quit-regression), built by
#    build.sh in mayhem/build-tests with the project's normal flags, run with ctest offscreen; each
#    test counts once in the CTRF report (ctest's JUnit status: run / fail / notrun+disabled = skipped).
#    Not run here:
#      * the run_*_probe.py tests: not registered (build.sh hides Python3), since each one compiles
#        and links a probe with ninja at test time;
#      * the scripting (--run) tests: not registered (Qt Qml off, as in the fuzz build);
#      * QET_CTEST_EXCLUDE below: these fail in this image under QT_QPA_PLATFORM=offscreen with no X
#        server (upstream CI runs ctest under xvfb-run), so they are excluded rather than counted.
# 2) Known-answer checks of QElectroTech's headless command line (the sanitized /mayhem/qelectrotech
#    build.sh produced) on upstream's own fixtures (tests/qttest/fixtures): project counts, net lists,
#    DXF blocks, BOM rows, symbol-check verdicts, and .qet/.qetz round trips.
QET_CTEST_EXCLUDE='^(tst_connectionsymbols|tst_conductordefinitionmark|tst_uprighttexts)$'
QET="$SRC/qelectrotech"
[ -x "$QET" ] || { echo "missing $QET — build.sh must produce it" >&2; emit_ctrf qet-cli 0 1; exit 1; }
FX="$SRC/tests/qttest/fixtures"
export QT_QPA_PLATFORM=offscreen LC_ALL=C.UTF-8
T="$(mktemp -d "${TMPDIR:-/tmp}/qet-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
export QET_SETTINGS_DIR="$T/settings"
q() { timeout 300 "$QET" "$@" >>"$T/log" 2>&1; }

passed=0; failed=0; skipped=0
check() { # check <name> <command...>
  local name="$1"; shift
  if "$@"; then echo "PASS $name"; passed=$((passed+1)); else echo "FAIL $name"; failed=$((failed+1)); fi
}
json_is() { # json_is <file> <python expr on d> — expression must be True
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8-sig")); sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2" 2>/dev/null
}

t_info_qetz() {
  q --info "$FX/qetz_format2.qetz" "$T/i.json" &&
  json_is "$T/i.json" 'd["diagrams"]==3 and d["elements"]==37 and d["conductors"]==35 and d["free_terminals"]==8 and d["pages"][0]["title"]=="General" and d["pages"][1]["elements"]==16'
}
t_nets() {
  q --export-nets "$FX/wiring_list_arrows.qet" "$T/n.json" --ignore-lock &&
  json_is "$T/n.json" 'd["nets"]==3 and len(d["list"])==3 and d["list"][0]["terminals"][0]=={"element":"PA","folio":1,"terminal":"A1"}'
}
t_resave_no_orientation() { # upstream fix ae151b35: a terminal with no orientation
  q --resave "$FX/terminal_no_orientation.qet" "$T/r.qet" --ignore-lock &&
  [ "$(grep -c '<terminal' "$T/r.qet")" -eq 5 ] &&
  q --info "$T/r.qet" "$T/r.json" &&
  json_is "$T/r.json" 'd["project"]=="Bugtracker 345" and d["diagrams"]==1 and d["elements"]==1 and d["free_terminals"]==2 and d["pages"][0]["width_px"]==1041'
}
t_qetz_roundtrip() {
  q --resave "$FX/linked_reports.qet" "$T/lr.qetz" --ignore-lock &&
  q --info "$FX/linked_reports.qet" "$T/a.json" && q --info "$T/lr.qetz" "$T/b.json" &&
  python3 -I -c 'import json,sys; a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2])); sys.exit(0 if a==b and a["diagrams"]>=1 and a["elements"]>0 else 1)' "$T/a.json" "$T/b.json"
}
t_check_elements() {
  timeout 300 "$QET" --check-elements "$SRC/misc/qet-mcp/fixtures/plc_master_test.elmt" --grid >"$T/c.txt" 2>&1
  grep -q '^1 file(s), 1 warning(s), 0 failure(s)$' "$T/c.txt" && grep -q 'frame off the grid (hotspot 17,32, size 40x60)' "$T/c.txt"
}
t_dxf_blocks() {
  mkdir -p "$T/dxf" && q --export-dxf "$FX/dxf_blocks.qet" "$T/dxf" --dxf-blocks --ignore-lock &&
  [ "$(cat "$T"/dxf/*.dxf | grep -c '^INSERT')" -eq 2 ] && [ "$(cat "$T"/dxf/*.dxf | grep -c '^BLOCK')" -eq 2 ]
}
t_bom() {
  q --export-bom "$FX/device_types.qet" "$T/b.csv" --ignore-lock &&
  [ "$(wc -l < "$T/b.csv")" -eq 3 ] && grep -q '^"K1";' "$T/b.csv"
}

# 1) upstream ctest suite
TB="$SRC/mayhem/build-tests"
if [ -f "$TB/CTestTestfile.cmake" ]; then
  ctest --test-dir "$TB" -j"$MAYHEM_JOBS" --timeout 1500 --output-on-failure \
        -E "$QET_CTEST_EXCLUDE" --output-junit "$T/ctest.xml" >"$T/ctest.log" 2>&1
  tail -15 "$T/ctest.log"
  read -r cp cf cs < <(python3 -I -c '
import sys, xml.etree.ElementTree as ET
p = f = s = 0
for tc in ET.parse(sys.argv[1]).getroot().iter("testcase"):
    st = tc.get("status", "")
    if st == "run": p += 1
    elif st == "fail": f += 1
    else: s += 1
print(p, f, s)' "$T/ctest.xml" 2>/dev/null || echo "0 1 0")
  # a ctest run that registered nothing is a broken build, not a pass
  [ $((cp + cf + cs)) -gt 0 ] || { echo "ctest ran no tests" >&2; cf=1; }
  passed=$cp; failed=$cf; skipped=$cs
  [ "$cf" -eq 0 ] || grep -E 'Failed|\*\*\*|Not Run' "$T/ctest.log" >&2
else
  echo "missing $TB/CTestTestfile.cmake — build.sh must build the test suite" >&2
  failed=1; skipped=0
fi

# 2) CLI known-answer checks
check info_qetz t_info_qetz
check export_nets t_nets
check resave_terminal_no_orientation t_resave_no_orientation
check qetz_roundtrip t_qetz_roundtrip
check check_elements t_check_elements
check export_dxf_blocks t_dxf_blocks
check export_bom t_bom
[ "$failed" -eq 0 ] || tail -40 "$T/log" >&2
emit_ctrf cmake-ctest "$passed" "$failed" "$skipped"
