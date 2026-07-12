#!/usr/bin/env bash
#
# mayhem/build.sh — build pcapfix's fuzz harness, standalone reproducer, and the
# functional-test oracle binary. Runs inside the commit image (mayhem/Dockerfile)
# as `mayhem` in /mayhem. Build contract comes from the base image ENV; see the
# template header for the full list (CC, SANITIZER_FLAGS, DEBUG_FLAGS, …).
#
# Layout produced:
#   /mayhem/fuzz_pcapfix              libFuzzer target (ASan+UBSan, DWARF-3)
#   /mayhem/fuzz_pcapfix-standalone   run-once reproducer (same code, no libFuzzer)
#   /mayhem/pcapfix-oracle            real CLI built with NORMAL flags (for test.sh)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# ── 3) Functional-test oracle: the REAL pcapfix CLI, NORMAL flags ───────────────
#    Built first (and stashed) so its objects don't collide with the sanitized
#    build below — pcapfix's Makefile shares *.o in the source tree. test.sh runs
#    this binary and asserts its repair behaviour/output.
make -j"$MAYHEM_JOBS" clean >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS" CFLAGS="-O2 -std=gnu99 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
cp -f pcapfix /mayhem/pcapfix-oracle
make -j"$MAYHEM_JOBS" clean >/dev/null 2>&1 || true

# ── 1+2) Build the fuzzer and the standalone reproducer ─────────────────────────
#    Every TU is instrumented for SanitizerCoverage (fuzzer binary via
#    -fsanitize=fuzzer-no-link, so the FUZZED code — pcap.c / pcap_kuznet.c /
#    pcapng.c / pcapfix.c — reports coverage, not just the harness: compiling it
#    without leaves only ~23 counters and Mayhem sees no coverage).
#    The target TUs are additionally compiled with -Dmalloc=bounded_malloc
#    -Drealloc=bounded_realloc so the harness caps pcapfix's unbounded,
#    length-field-driven allocations (see fuzz_pcapfix.c); the harness TU itself
#    is compiled WITHOUT those defines so bounded_malloc()'s own malloc() call is
#    the real one (no self-recursion).
#    -Dmain=pcapfix_main renames the CLI's main() out of the way so the harness
#    can reuse pcapfix.c's globals + conint/conshort/print_progress while libFuzzer
#    (or the standalone driver) supplies the real main(). $DEBUG_FLAGS AFTER
#    $SANITIZER_FLAGS so -gdwarf-3 wins over the base's -g (DWARF-5).
common_flags=( $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" )
tgt_defs=( -Dmain=pcapfix_main -Dmalloc=bounded_malloc -Drealloc=bounded_realloc )
tgt_units=( pcap pcap_kuznet pcapng pcapfix )

compile_target_objs() {  # $1 = extra flag (e.g. -fsanitize=fuzzer-no-link), $2 = suffix
  local extra="$1" sfx="$2" u
  for u in "${tgt_units[@]}"; do
    $CC "${common_flags[@]}" $extra "${tgt_defs[@]}" -c "$SRC/$u.c" -o "/tmp/$u$sfx.o"
  done
}

# fuzzer binary: coverage on harness + all target TUs, linked with libFuzzer
$CC "${common_flags[@]}" -fsanitize=fuzzer-no-link -c "$SRC/mayhem/fuzz_pcapfix.c" -o /tmp/harness.cov.o
compile_target_objs "-fsanitize=fuzzer-no-link" ".cov"
$CC "${common_flags[@]}" $LIB_FUZZING_ENGINE \
    /tmp/harness.cov.o /tmp/pcap.cov.o /tmp/pcap_kuznet.cov.o /tmp/pcapng.cov.o /tmp/pcapfix.cov.o \
    -o /mayhem/fuzz_pcapfix

# standalone reproducer: no coverage runtime, StandaloneFuzzTargetMain supplies main()
$CC "${common_flags[@]}" -c "$SRC/mayhem/fuzz_pcapfix.c" -o /tmp/harness.o
compile_target_objs "" ""
$CC "${common_flags[@]}" -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC "${common_flags[@]}" \
    /tmp/standalone_main.o /tmp/harness.o /tmp/pcap.o /tmp/pcap_kuznet.o /tmp/pcapng.o /tmp/pcapfix.o \
    -o /mayhem/fuzz_pcapfix-standalone

echo "[build] done: $(ls -1 /mayhem/fuzz_pcapfix /mayhem/fuzz_pcapfix-standalone /mayhem/pcapfix-oracle)"
