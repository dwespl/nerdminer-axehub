#ifndef AXEHUB_SHA_FAST_H
#define AXEHUB_SHA_FAST_H

#ifdef AXEHUB_HW_FAST

#include <Arduino.h>

// One-shot per-job init: writes SHA_MODE = SHA2_256 and pre-zeros TEXT[9..14]
// (the 6 input slots that are constant 0 for both the first and inter hashes).
// Must be called *after* esp_sha_acquire_hardware() and before
// axehub_sha_fast_mine_batch().
void axehub_sha_fast_init_job(void);

// Run the optimised inner loop.
//
// Returns true if a candidate hash (where H[7]'s upper 16 bits are zero,
// the standard 32-bit-share filter) was found before the loop exited. When
// true, *out_hash holds the 32-byte double-SHA result and *nonce_io holds
// the nonce that produced it. Caller MUST recompute the hash in software
// and verify before submitting to the pool — the HW path is faster but
// less defensible against silent corruption from the persistent-zeros
// optimisation.
//
// Returns false if the loop exited because *mining_active turned false or
// the nonce range was exhausted (*nonce_io == nonce_end).
//
// hash_counter is bumped once per nonce attempted, regardless of outcome.
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

// Boot-time correctness check. Computes a SHA-256d on a known 80-byte test
// header via both the fast HW path and the reference software path
// (nerd_sha256d), compares byte-for-byte. Returns true if they match.
//
// Must be called before any miner task starts so the HW peripheral state
// isn't being shared. Stores result in a static so /info can surface it
// at runtime — see axehub_sha_fast_get_selftest_status().
bool axehub_sha_fast_selftest(void);
bool axehub_sha_fast_get_selftest_status(void);  // -> last selftest result
bool axehub_sha_fast_get_selftest_ran(void);     // -> has selftest been called?
const uint8_t* axehub_sha_fast_get_selftest_expected(void);  // 32B mbedtls reference
const uint8_t* axehub_sha_fast_get_selftest_got(void);       // 32B fast-path
const uint8_t* axehub_sha_fast_get_selftest_baseline(void);  // 32B baseline-style replica

// Canary test for the TEXT-overlap technique. Triggers a SHA hash, then
// overwrites a TEXT register while the peripheral is still computing.
// Compares final H against a clean hash of the original input. If equal,
// peripheral snapshots TEXT at trigger time and overlap is safe. If not,
// TEXT is read continuously during compute and overlap can't be used.
bool axehub_sha_fast_overlap_canary(void);
bool axehub_sha_fast_get_overlap_safe(void);
bool axehub_sha_fast_get_overlap_ran(void);

// Companion test: does writing H during compute corrupt the hash? If safe,
// Phase A (H=midstate) can move from sequential path into WAIT2 overlap.
bool axehub_sha_fast_hwrite_canary(void);
bool axehub_sha_fast_get_hwrite_safe(void);
bool axehub_sha_fast_get_hwrite_ran(void);

#ifdef AXEHUB_HW_ASM
// Hand-tuned Xtensa LX7 inline-asm batch loop. Narrow s32i.n / l32i.n for
// all peripheral writes; each SHA register held in its own literal-loaded
// pointer; memw only before MODE/CONTINUE/START; TEXT-overlap during
// busy-wait. SW verify is the caller's responsibility on candidate.
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
// Pure-assembly variant — defined in src/axehub_sha_asm_s3.S, compiled by
// xtensa-esp32s3-elf-as directly (no inline-asm compiler involvement).
// Same contract as axehub_sha_fast_mine_batch_asm except no hash_counter /
// mining_active args — caller maintains those between calls.
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

// Pure Xtensa LX7 SHA-256 block-compression primitive (src/axehub_sha_sw_asm_s3.S).
// Single 64-byte block:
//   state[8]   in/out — 8 big-endian state words
//   msg[16]    in     — 16 big-endian message words (caller byte-swaps)
#ifdef __cplusplus
extern "C" {
#endif
void axehub_sha_sw_asm_compress_block(uint32_t state[8], const uint32_t msg[16]);

// Second-hash variant with round-60 early-reject. Returns 1 if filter passed
// (state contains the final digest), 0 if rejected (state is left unmodified).
// MUST only be called for the second hash (state initialised to SHA-256 IV)
// — the magic constant 0x32E7 is derived from IV's h[7] = 0x5BE0CD19.
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

// Spawns a one-shot FreeRTOS benchmark task on core 0 that waits 5s for the
// system to settle, then runs N iterations of the baked C path and the asm
// path back-to-back, printing cycles-per-call to Serial. Self-deletes after.
// Used to pin down the per-round speed gap between the two implementations.
void axehub_sha_sw_asm_start_bench(void);

// Boot-time selftest for the double-hash wrapper — computes double-SHA of a
// known 80-byte header via asm and via mbedtls, compares. Result in /info.
bool axehub_sha_sw_asm_double_selftest(void);
bool axehub_sha_sw_asm_get_double_selftest_ran(void);
bool axehub_sha_sw_asm_get_double_selftest_passed(void);
const uint8_t* axehub_sha_sw_asm_get_double_selftest_got(void);       // 32B asm output
const uint8_t* axehub_sha_sw_asm_get_double_selftest_expected(void);  // 32B mbedtls reference

// Brute-force selftest for the round-60 reject path in compress_block2_reject.
// Sweeps ~200K nonces, validates that nonces passing the filter produce the
// SAME hash as the no-reject double-hash path. Diagnostic only — not invoked
// from the active boot path.
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
