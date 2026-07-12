#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral functional oracle for pcapfix.
#
# pcapfix ships NO upstream test suite (its Makefile has no check/test target and
# the repo has no test directory), so this is a genuine known-answer oracle built
# for RL: it runs the REAL pcapfix CLI (mayhem/build.sh produced /mayhem/pcapfix-oracle
# with the project's NORMAL flags) on committed capture fixtures and ASSERTS the
# documented repair behaviour — golden stdout messages, exit codes, and the bytes
# of the repaired output. A patch that no-ops the program (exit(0), empty output)
# FAILS every assertion, so the oracle is not reward-hackable (verify-repo's
# sabotage check proves this). Emits a CTRF summary the board reads.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# CTRF summary (ctrf.io) — writes the report file + a compact stdout marker line;
# returns non-zero iff failed>0.
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

BIN=/mayhem/pcapfix-oracle
T=mayhem/tests
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcapfix-oracle.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$BIN" ]; then
  echo "FATAL: $BIN missing — mayhem/build.sh must build the oracle binary" >&2
  emit_ctrf "pcapfix-behavioral-oracle" 0 1
  exit 1
fi

PASS=0; FAIL=0

# check <name> <expected-exit|any> <input> <assert-fn...>
# runs the oracle on a COPY of the fixture (so no writes touch the read-only
# image dir), captures stdout+exit, then evaluates the golden assertions.
run_case() {
  local name="$1" want_rc="$2" input="$3"; shift 3
  local in="$WORK/$(basename "$input")" out="$WORK/fixed_$(basename "$input")" log="$WORK/log"
  cp "$T/$input" "$in"
  rm -f "$out"
  ( cd "$WORK" && "$BIN" -d -o "fixed_$(basename "$input")" "$(basename "$input")" ) >"$log" 2>&1
  local rc=$?
  local ok=1 reason=""
  if [ "$want_rc" = "nonzero" ]; then
    [ "$rc" -ne 0 ] || { ok=0; reason="expected nonzero exit, got 0"; }
  else
    [ "$rc" = "$want_rc" ] || { ok=0; reason="expected exit $want_rc, got $rc"; }
  fi
  local assert
  for assert in "$@"; do
    case "$assert" in
      stdout:*)  grep -qF -- "${assert#stdout:}" "$log" || { ok=0; reason="missing stdout '${assert#stdout:}'"; } ;;
      out_exists) [ -s "$out" ] || { ok=0; reason="expected non-empty repaired output"; } ;;
      out_absent) [ ! -e "$out" ] || { ok=0; reason="repaired output should NOT exist"; } ;;
      out_magic_pcap)
        [ -s "$out" ] && [ "$(od -An -tx1 -N4 "$out" | tr -d ' \n')" = "d4c3b2a1" ] \
          || { ok=0; reason="repaired output does not start with pcap magic"; } ;;
    esac
  done
  if [ "$ok" = 1 ]; then
    PASS=$((PASS+1)); echo "  ok   $name"
  else
    FAIL=$((FAIL+1)); echo "  FAIL $name: $reason"; echo "    --- output ---"; sed 's/^/    /' "$log"
  fi
}

# ── Known-answer cases (golden behaviour captured from pcapfix 1.1.7) ────────────
# 1) A well-formed PCAP: pcapfix reports it is proper and writes NO fixed file.
run_case "pcap-valid-nothing-to-fix" 0 good.pcap \
  "stdout:This is a PCAP file." "stdout:Nothing to fix" out_absent

# 2) A PCAP with a corrupt global header: pcapfix repairs it and writes a valid pcap.
run_case "pcap-corrupt-header-repaired" 0 bad_hdr.pcap \
  "stdout:global pcap header seems to be corrupt" "stdout:Corruption(s) fixed" \
  out_exists out_magic_pcap

# 3) A PCAP whose packets can't be recovered: pcapfix fails (nonzero) and says so.
run_case "pcap-unrepairable-fails" nonzero bad_pkt.pcap \
  "stdout:does not seem to be a pcap/pcapng file"

# 4) A PCAPNG with an invalid block size: pcapfix repairs it (nonzero corruptions).
run_case "pcapng-corrupt-repaired" 0 bad.pcapng \
  "stdout:This is a PCAPNG file." "stdout:Corruption(s) fixed" out_exists

# 5) An unsupported format (snoop): pcapfix rejects it with a clear error, nonzero.
run_case "snoop-unsupported-rejected" nonzero snoop.bin \
  "stdout:SNOOP file, which is not supported"

echo "pcapfix oracle: $PASS passed, $FAIL failed"
emit_ctrf "pcapfix-behavioral-oracle" "$PASS" "$FAIL"
