#ifndef AXEHUB_SHA_FAST_H
#define AXEHUB_SHA_FAST_H

#ifdef AXEHUB_HW_FAST

#include <Arduino.h>

// One-shot per-job init: SHA_MODE + zero-fill TEXT[9..14]. Call between
// esp_sha_acquire_hardware() and axehub_sha_fast_mine_batch().
void axehub_sha_fast_init_job(void);

// Optimised inner loop. Returns true on candidate (H[7] high 16 == 0);
// caller MUST SW-reverify before submitting.
bool axehub_sha_fast_mine_batch(
    const uint32_t *midstate,           // 8 words, byte-swapped midstate
    const uint32_t *block2_words,       // 3 words: header bytes 64..75, byte-swapped
    uint32_t       *nonce_io,           // in/out: current nonce, big-endian
    uint32_t        nonce_end,
    uint8_t        *out_hash,           // 32 bytes — only populated if return is true
    volatile uint32_t *hash_counter,
    volatile bool  *mining_active);

// Single-iteration variant — runs phases A through G of the fast loop on a
// single nonce and ALWAYS reads out the full 32-byte H register (no
// early-reject filter). For the boot-time selftest only.
void axehub_sha_fast_compute_one(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash);

// Boot-time correctness check (HW vs reference SW SHA-256d on a known
// header). Must run before miner tasks start. Result surfaced in /info.
bool axehub_sha_fast_selftest(void);
bool axehub_sha_fast_get_selftest_status(void);  // -> last selftest result
bool axehub_sha_fast_get_selftest_ran(void);     // -> has selftest been called?
const uint8_t* axehub_sha_fast_get_selftest_expected(void);  // 32B mbedtls reference
const uint8_t* axehub_sha_fast_get_selftest_got(void);       // 32B fast-path
const uint8_t* axehub_sha_fast_get_selftest_baseline(void);  // 32B baseline-style replica

// Canary: writes TEXT during a pending compute, compares H to clean hash.
// Equal → peripheral snapshots TEXT on trigger (overlap safe).
bool axehub_sha_fast_overlap_canary(void);
bool axehub_sha_fast_get_overlap_safe(void);
bool axehub_sha_fast_get_overlap_ran(void);

// Companion test: does writing H during compute corrupt the hash? If safe,
// Phase A (H=midstate) can move from sequential path into WAIT2 overlap.
bool axehub_sha_fast_hwrite_canary(void);
bool axehub_sha_fast_get_hwrite_safe(void);
bool axehub_sha_fast_get_hwrite_ran(void);

#ifdef AXEHUB_HW_ASM
// Hand-tuned LX7 inline-asm batch loop with TEXT-overlap during busy-wait.
// Caller SW-verifies candidates.
bool axehub_sha_fast_mine_batch_asm(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t       *nonce_io,
    uint32_t        nonce_end,
    uint8_t        *out_hash,
    volatile uint32_t *hash_counter,
    volatile bool  *mining_active);

// Single-iter variant for selftest — no overlap, no early reject, always
// reads full H register.
void axehub_sha_fast_compute_one_asm(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash);

bool axehub_sha_fast_get_asm_selftest_passed(void);
const uint8_t* axehub_sha_fast_get_asm_selftest_got(void);
#endif

#ifdef AXEHUB_HW_ASM_PURE
// Pure-asm variant in src/axehub_sha_asm_s3.S. Same contract as the
// inline-asm path but caller maintains hash_counter / mining_active.
#ifdef __cplusplus
extern "C" {
#endif
int32_t axehub_sha_asm_s3_mine_batch(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t       *nonce_io,
    uint32_t        nonce_end,
    uint8_t        *out_hash);
#ifdef __cplusplus
}
#endif

bool axehub_sha_fast_get_pure_selftest_passed(void);
const uint8_t* axehub_sha_fast_get_pure_selftest_got(void);

// Pure LX7 asm SHA-256 block-compression primitive (src/axehub_sha_sw_asm_s3.S).
// state[8] in/out (BE words), msg[16] in (BE words; caller byte-swaps).
#ifdef __cplusplus
extern "C" {
#endif
void axehub_sha_sw_asm_compress_block(uint32_t state[8], const uint32_t msg[16]);

// Second-hash variant with round-60 early-reject. Returns 1 on pass
// (state = final digest), 0 on reject (state unmodified). State must be
// SHA-256 IV on entry — the 0x32E7 magic derives from IV h[7] = 0x5BE0CD19.
int  axehub_sha_sw_asm_compress_block2_reject(uint32_t state[8], const uint32_t msg[16]);
#ifdef __cplusplus
}
#endif

// Boot-time correctness check for the compress_block asm against the SHA-256
// "abc" FIPS test vector (single-block input). Result surfaced in /info.
bool axehub_sha_sw_asm_selftest(void);
bool axehub_sha_sw_asm_get_selftest_ran(void);
bool axehub_sha_sw_asm_get_selftest_passed(void);
const uint8_t* axehub_sha_sw_asm_get_selftest_got(void);  // 32B compress output

// Unconditional double-SHA-256 — always produces the full 32-byte hash.
// Used by the boot-time selftest (mbedtls comparison). For production mining
// use axehub_sha_sw_asm_mine which adds the round-60 early-reject.
void axehub_sha_sw_asm_double_hash(const uint32_t midstate[8],
                                   const uint8_t  tail[16],
                                   uint8_t        out_hash[32]);

// Production mining wrapper — same signature contract as nerd_sha256d_baked.
// Runs the asm double-SHA with round-60 reject; returns true if the candidate
// passes the filter (out_hash filled) and false otherwise (out_hash untouched).
bool axehub_sha_sw_asm_mine(const uint32_t midstate[8],
                            const uint8_t  tail[16],
                            uint8_t        out_hash[32]);

// One-shot FreeRTOS bench task: baked C vs asm path back-to-back, prints
// cyc/call to Serial. Self-deletes.
void axehub_sha_sw_asm_start_bench(void);

// Boot-time selftest for the double-hash wrapper — computes double-SHA of a
// known 80-byte header via asm and via mbedtls, compares. Result in /info.
bool axehub_sha_sw_asm_double_selftest(void);
bool axehub_sha_sw_asm_get_double_selftest_ran(void);
bool axehub_sha_sw_asm_get_double_selftest_passed(void);
const uint8_t* axehub_sha_sw_asm_get_double_selftest_got(void);       // 32B asm output
const uint8_t* axehub_sha_sw_asm_get_double_selftest_expected(void);  // 32B mbedtls reference

// Brute-force selftest for round-60 reject: sweeps ~200K nonces, validates
// pass-filter nonces produce the same hash as the no-reject path.
bool axehub_sha_sw_asm_reject_selftest(void);

// Per-fragment SHA-256 round microbench (SIGMA1, CH, add-chain). Boot-time, ~1ms.
void axehub_sha_round_microbench(void);

// S3 HW SHA peripheral CONTINUE/START/wait timing. Peripheral cycles vs CPU overhead.
void axehub_sha_hw_microbench(void);

// axehub_sha_asm_s3_mine_batch in isolation (200K nonces, no FreeRTOS).
void axehub_sha_hw_batch_microbench(void);

// Per-phase HW mining loop profiling — cycles per OVERLAP1/Wait1/Phase E/etc.
void axehub_sha_hw_phase_microbench(void);

// DMA mode SHA microbench — checks whether esp_sha_dma() is faster than DPort.
void axehub_sha_hw_dma_microbench(void);

#endif

#endif // AXEHUB_HW_FAST

#endif
