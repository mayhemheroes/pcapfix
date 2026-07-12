/*
 * fuzz_pcapfix.c — in-process libFuzzer harness for pcapfix.
 *
 * pcapfix ships as a CLI that reads a (potentially corrupt) capture file and
 * writes a repaired copy. A raw file-input CLI target barely fuzzes (a fork/exec
 * per input, output written to disk), so per the port-repo skill this drives the
 * SAME code path in-process instead: it reproduces main()'s magic-based dispatch
 * (pcapfix.c switch on header_magic) and calls the exact repair routines
 * fix_pcap() / fix_pcapng() / fix_pcap_kuznetzov() the CLI calls.
 *
 * Input/output are memory streams (fmemopen / open_memstream) so nothing touches
 * the read-only image dir, and the fuzzer iterates fast. The upstream repair code
 * is compiled unmodified; the CLI's globals + helpers (conint/conshort/
 * print_progress) come from pcapfix.c compiled with -Dmain=pcapfix_main so its
 * main() is renamed out of the way (libFuzzer supplies main()).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>

#include "pcap.h"
#include "pcapng.h"
#include "pcap_kuznet.h"

/* extra file magics recognised by main() (defined locally in pcapfix.c) */
#define BTSNOOP_MAGIC   0x6E737462
#define SNOOP_MAGIC     0x6f6f6e73
#define NETMON_MAGIC    0x55424d47
#define NETMON11_MAGIC  0x53535452
#define ETHERPEEK_MAGIC 0x7265767f

/* upstream repair entry points (pcap.c / pcapng.c / pcap_kuznet.c) */
extern int fix_pcap(FILE *pcap, FILE *pcap_fix);
extern int fix_pcapng(FILE *pcap, FILE *pcap_fix);
extern int fix_pcap_kuznetzov(FILE *pcap, FILE *pcap_fix);

/* CLI configuration globals (pcapfix.c) — reset per input for determinism */
extern int deep_scan;
extern int soft_mode;
extern int verbose;
extern int swapped;
extern int data_link_type;
extern int pcapng;

/* pcapfix is an allocate-and-exit batch CLI: its repair routines malloc
 * scratch buffers (e.g. fix_pcap_kuznetzov's 1 MB writebuffer, pcap_kuznet.c:200)
 * that are never freed — the real program reclaims them at process exit.
 * Driven in-process those allocations accumulate and LeakSanitizer aborts the
 * fuzzer on the first kuznetzov input, so leak detection is disabled (the
 * sanctioned exception for allocate-and-exit batch tools). ASan/UBSan
 * memory-safety checks stay fully enabled and halting. */
const char *__asan_default_options(void) { return "detect_leaks=0"; }
/* __lsan_is_turned_off() cannot be overridden by an ASAN_OPTIONS=detect_leaks=1
 * set in the runner's environment, so it reliably keeps LSan off in Mayhem. */
int __lsan_is_turned_off(void) { return 1; }

/*
 * Allocation guard. pcapfix sizes almost every allocation directly from
 * attacker-controlled length fields (pcapng block total_length / caplen,
 * pcap incl_len, …) with no upper bound and no NULL check, so a single mutated
 * length byte makes it malloc()/realloc() up to 4 GiB. In the real CLI that just
 * makes the process die once; driven in-process it makes libFuzzer OOM on the
 * first such input and never completes 5 smoke iterations. The target .c files
 * are compiled with -Dmalloc=bounded_malloc -Drealloc=bounded_realloc (mayhem
 * build only, upstream sources untouched) so these wrappers cap the DoS-class
 * unbounded allocations while every real memory-safety bug (overflows, UAF,
 * bad reads) is still exercised and still halts under ASan/UBSan. On an absurd
 * request we longjmp back to the harness and drop the input.
 */
#define PCAPFIX_ALLOC_CAP (256u * 1024u * 1024u)   /* 256 MiB */
static jmp_buf alloc_bail;
static int alloc_guard_active;

void *bounded_malloc(size_t n) {
  if (alloc_guard_active && n > PCAPFIX_ALLOC_CAP) longjmp(alloc_bail, 1);
  return malloc(n);
}
void *bounded_realloc(void *p, size_t n) {
  if (alloc_guard_active && n > PCAPFIX_ALLOC_CAP) longjmp(alloc_bail, 1);
  return realloc(p, n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* need at least the 4-byte magic that main() reads before dispatch */
  if (size < 4) return 0;

  /* reset the CLI globals to their default state for a reproducible run.
     deep_scan + soft_mode ON exercise the heavy brute-force reconstruction
     paths (the most interesting code); this matches `pcapfix -d -s`. */
  deep_scan = 1;
  soft_mode = 1;
  verbose = 0;
  swapped = 0;
  data_link_type = -1;
  pcapng = 0;

  FILE *in = fmemopen((void *)data, size, "rb");
  if (in == NULL) return 0;

  char *outbuf = NULL;
  size_t outlen = 0;
  FILE *out = open_memstream(&outbuf, &outlen);
  if (out == NULL) {
    fclose(in);
    return 0;
  }

  uint32_t magic = 0;
  memcpy(&magic, data, sizeof(magic));

  /* bail out cleanly if the repair code requests an absurd allocation */
  if (setjmp(alloc_bail)) {
    alloc_guard_active = 0;
    fclose(in);
    fclose(out);
    free(outbuf);
    return 0;
  }
  alloc_guard_active = 1;

  switch (magic) {
    /* unsupported formats — main() rejects these before calling any fixer */
    case ETHERPEEK_MAGIC:
    case NETMON_MAGIC:
    case NETMON11_MAGIC:
    case SNOOP_MAGIC:
    case BTSNOOP_MAGIC:
      break;

    case PCAP_EXT_MAGIC:
    case PCAP_EXT_MAGIC_SWAPPED:
      fix_pcap_kuznetzov(in, out);
      break;

    case PCAPNG_MAGIC:
      fix_pcapng(in, out);
      break;

    case PCAP_MAGIC:
    case PCAP_MAGIC_SWAPPED:
      fix_pcap(in, out);
      break;

    /* unknown magic — main() assumes classic PCAP (deep-scan reconstruction) */
    default:
      fix_pcap(in, out);
      break;
  }

  alloc_guard_active = 0;
  fclose(in);
  fclose(out);
  free(outbuf);
  return 0;
}
