// AxeHub fast HW SHA path for ESP32-S3.
// Technique: memw discipline + per-register address literals + persistent
// zeros for the constant padding slots between block-2 and inter blocks.

#ifdef AXEHUB_HW_FAST

#include "axehub_sha_fast.h"
#include <Arduino.h>
#include <soc/soc.h>
#include <sha/sha_dma.h>           // esp_sha_acquire/release_hardware
#include "mbedtls/sha256.h"        // reference SW path for selftest (no early-reject)
#include "ShaTests/nerdSHA256plus.h"  // for nerd_mids — computing midstate

#if !defined(CONFIG_IDF_TARGET_ESP32S3)
#  error "AXEHUB_HW_FAST currently targets ESP32-S3 only"
#endif

// ESP32-S3 SHA peripheral register layout (TRM 8.6).
#define S3_SHA_BASE         0x6003B000UL
#define SHA_MODE_REG        (S3_SHA_BASE + 0x00)
#define SHA_START_REG       (S3_SHA_BASE + 0x10)
#define SHA_CONTINUE_REG    (S3_SHA_BASE + 0x14)
#define SHA_BUSY_REG        (S3_SHA_BASE + 0x18)
#define SHA_H_BASE          (S3_SHA_BASE + 0x40)  // H[0..7] at +0..+28
#define SHA_TEXT_BASE       (S3_SHA_BASE + 0x80)  // TEXT[0..15] at +0..+60

#define SHA2_256_MODE       2

static inline void memw(void) {
    __asm__ __volatile__("memw\n");
}

#pragma GCC push_options
#pragma GCC optimize("O3")

void IRAM_ATTR axehub_sha_fast_init_job(void)
{
    memw();
    REG_WRITE(SHA_MODE_REG, SHA2_256_MODE);
    memw();

    // Pre-zero TEXT[9..14] — constant 0 in both block-2 padding (after
    // nonce+0x80) and inter padding (after 32-byte digest). Peripheral
    // preserves these across compute, saving 12 stores per nonce.
    volatile uint32_t *text = (volatile uint32_t *)SHA_TEXT_BASE;
    for (int i = 9; i <= 14; i++) {
        text[i] = 0;
    }
    memw();
}

bool IRAM_ATTR axehub_sha_fast_mine_batch(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t       *nonce_io,
    uint32_t        nonce_end,
    uint8_t        *out_hash,
    volatile uint32_t *hash_counter,
    volatile bool  *mining_active)
{
    // Pre-load midstate into locals so the compiler keeps them in registers
    // across the loop. Xtensa LX7 has 16 ARs, this leaves enough for the
    // peripheral pointers + nonce + scratch.
    const uint32_t mid0 = midstate[0];
    const uint32_t mid1 = midstate[1];
    const uint32_t mid2 = midstate[2];
    const uint32_t mid3 = midstate[3];
    const uint32_t mid4 = midstate[4];
    const uint32_t mid5 = midstate[5];
    const uint32_t mid6 = midstate[6];
    const uint32_t mid7 = midstate[7];
    const uint32_t blk0 = block2_words[0];
    const uint32_t blk1 = block2_words[1];
    const uint32_t blk2 = block2_words[2];

    // Same idea for the peripheral pointers — the compiler should keep
    // these in registers (loaded once via l32r from the literal pool).
    volatile uint32_t * const sha_continue = (volatile uint32_t *)SHA_CONTINUE_REG;
    volatile uint32_t * const sha_start    = (volatile uint32_t *)SHA_START_REG;
    volatile uint32_t * const sha_busy     = (volatile uint32_t *)SHA_BUSY_REG;
    volatile uint32_t * const sha_mode     = (volatile uint32_t *)SHA_MODE_REG;
    volatile uint32_t * const sha_h        = (volatile uint32_t *)SHA_H_BASE;
    volatile uint32_t * const sha_text     = (volatile uint32_t *)SHA_TEXT_BASE;

    uint32_t nonce = *nonce_io;
    bool     candidate = false;

    while (nonce != nonce_end) {

        // Cooperative early-exit. Checked once per nonce — costs ~4 cycles.
        if (!*mining_active) break;

        // memw discipline (verified by deep-research 2026-04-21):
        //   * TEXT[i] writes are FIFO-ordered to the same MMIO region — no
        //     memw needed between them
        //   * memw IS needed before writes to MODE / CONTINUE / START (the
        //     state-changing control registers) so the data writes are
        //     visible to the peripheral before the trigger fires
        //   * BUSY-poll naturally serialises the read with subsequent ops

        // ---- PHASE A: Restore midstate to H[0..7] ----
        sha_h[0] = mid0;
        sha_h[1] = mid1;
        sha_h[2] = mid2;
        sha_h[3] = mid3;
        sha_h[4] = mid4;
        sha_h[5] = mid5;
        sha_h[6] = mid6;
        sha_h[7] = mid7;

        // ---- PHASE B: Fill block 2 (TEXT[0..15] full) ----
        sha_text[0]  = blk0;
        sha_text[1]  = blk1;
        sha_text[2]  = blk2;
        sha_text[3]  = nonce;
        sha_text[4]  = 0x00000080U;
        sha_text[5]  = 0;
        sha_text[6]  = 0;
        sha_text[7]  = 0;
        sha_text[8]  = 0;
        sha_text[9]  = 0;
        sha_text[10] = 0;
        sha_text[11] = 0;
        sha_text[12] = 0;
        sha_text[13] = 0;
        sha_text[14] = 0;
        sha_text[15] = 0x80020000U;          // 640 bits = 80-byte block, BE

        // ---- PHASE C: Trigger first hash ----
        memw();
        *sha_mode     = SHA2_256_MODE;
        *sha_continue = 1;

        // ---- PHASE D: Wait first hash ----
        while (*sha_busy != 0) { /* spin */ }

        // ---- PHASE E: Copy H[0..7] -> TEXT[0..7] for the inter hash ----
        const uint32_t h0 = sha_h[0];
        const uint32_t h1 = sha_h[1];
        const uint32_t h2 = sha_h[2];
        const uint32_t h3 = sha_h[3];
        const uint32_t h4 = sha_h[4];
        const uint32_t h5 = sha_h[5];
        const uint32_t h6 = sha_h[6];
        const uint32_t h7 = sha_h[7];
        sha_text[0]  = h0;
        sha_text[1]  = h1;
        sha_text[2]  = h2;
        sha_text[3]  = h3;
        sha_text[4]  = h4;
        sha_text[5]  = h5;
        sha_text[6]  = h6;
        sha_text[7]  = h7;
        sha_text[8]  = 0x00000080U;          // padding start for 32-byte input
        sha_text[9]  = 0;
        sha_text[10] = 0;
        sha_text[11] = 0;
        sha_text[12] = 0;
        sha_text[13] = 0;
        sha_text[14] = 0;
        sha_text[15] = 0x00010000U;          // 256 bits = 32-byte block, BE

        // ---- PHASE F: Trigger inter hash (fresh start, IV reset) ----
        memw();
        *sha_mode  = SHA2_256_MODE;
        *sha_start = 1;

        // ---- PHASE G: Wait inter hash ----
        while (*sha_busy != 0) { /* spin */ }

        const uint32_t h7_final = sha_h[7];
        if ((h7_final >> 16) == 0U) {
            // Candidate. Read the rest of H so the caller can SW-verify.
            const uint32_t f0 = sha_h[0];
            const uint32_t f1 = sha_h[1];
            const uint32_t f2 = sha_h[2];
            const uint32_t f3 = sha_h[3];
            const uint32_t f4 = sha_h[4];
            const uint32_t f5 = sha_h[5];
            const uint32_t f6 = sha_h[6];
            ((uint32_t *)out_hash)[0] = f0;
            ((uint32_t *)out_hash)[1] = f1;
            ((uint32_t *)out_hash)[2] = f2;
            ((uint32_t *)out_hash)[3] = f3;
            ((uint32_t *)out_hash)[4] = f4;
            ((uint32_t *)out_hash)[5] = f5;
            ((uint32_t *)out_hash)[6] = f6;
            ((uint32_t *)out_hash)[7] = h7_final;
            (*hash_counter)++;
            nonce++;
            candidate = true;
            break;
        }

        // ---- PHASE I: Bookkeeping ----
        (*hash_counter)++;
        nonce++;
    }

    *nonce_io = nonce;
    return candidate;
}

void IRAM_ATTR axehub_sha_fast_compute_one(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash)
{
    volatile uint32_t * const sha_continue = (volatile uint32_t *)SHA_CONTINUE_REG;
    volatile uint32_t * const sha_start    = (volatile uint32_t *)SHA_START_REG;
    volatile uint32_t * const sha_busy     = (volatile uint32_t *)SHA_BUSY_REG;
    volatile uint32_t * const sha_mode     = (volatile uint32_t *)SHA_MODE_REG;
    volatile uint32_t * const sha_h        = (volatile uint32_t *)SHA_H_BASE;
    volatile uint32_t * const sha_text     = (volatile uint32_t *)SHA_TEXT_BASE;

    memw();
    for (int i = 0; i < 8; ++i) sha_h[i] = midstate[i];

    memw();
    sha_text[0]  = block2_words[0];
    sha_text[1]  = block2_words[1];
    sha_text[2]  = block2_words[2];
    sha_text[3]  = nonce;
    sha_text[4]  = 0x00000080U;
    sha_text[5]  = 0;
    sha_text[6]  = 0;
    sha_text[7]  = 0;
    sha_text[8]  = 0;
    sha_text[9]  = 0;
    sha_text[10] = 0;
    sha_text[11] = 0;
    sha_text[12] = 0;
    sha_text[13] = 0;
    sha_text[14] = 0;
    sha_text[15] = 0x80020000U;

    memw();
    *sha_mode     = SHA2_256_MODE;
    memw();
    *sha_continue = 1;
    memw();

    while (*sha_busy != 0) {}
    memw();

    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = sha_h[i];
    memw();
    for (int i = 0; i < 8; ++i) sha_text[i] = h[i];
    sha_text[8]  = 0x00000080U;
    sha_text[9]  = 0;
    sha_text[10] = 0;
    sha_text[11] = 0;
    sha_text[12] = 0;
    sha_text[13] = 0;
    sha_text[14] = 0;
    sha_text[15] = 0x00010000U;

    memw();
    *sha_mode  = SHA2_256_MODE;
    memw();
    *sha_start = 1;
    memw();

    while (*sha_busy != 0) {}
    memw();

    for (int i = 0; i < 8; ++i) {
        ((uint32_t *)out_hash)[i] = sha_h[i];
    }
}

// ---- Boot-time selftest ----------------------------------------------------

static bool s_selftest_ran    = false;
static bool s_selftest_passed = false;
static uint8_t s_selftest_expected[32] = {0};
static uint8_t s_selftest_got[32]      = {0};
static uint8_t s_selftest_baseline[32] = {0};
static bool s_overlap_ran    = false;
static bool s_overlap_safe   = false;

bool axehub_sha_fast_get_overlap_safe(void) { return s_overlap_safe; }
bool axehub_sha_fast_get_overlap_ran(void)  { return s_overlap_ran; }

bool axehub_sha_fast_overlap_canary(void)
{
    volatile uint32_t * const sha_continue = (volatile uint32_t *)SHA_CONTINUE_REG;
    volatile uint32_t * const sha_start    = (volatile uint32_t *)SHA_START_REG;
    volatile uint32_t * const sha_busy     = (volatile uint32_t *)SHA_BUSY_REG;
    volatile uint32_t * const sha_mode     = (volatile uint32_t *)SHA_MODE_REG;
    volatile uint32_t * const sha_h        = (volatile uint32_t *)SHA_H_BASE;
    volatile uint32_t * const sha_text     = (volatile uint32_t *)SHA_TEXT_BASE;

    static const uint32_t test_input[16] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444,
        0x55555555, 0x66666666, 0x77777777, 0x88888888,
        0x00000080, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x80020000,
    };

    esp_sha_acquire_hardware();
    REG_WRITE(SHA_MODE_REG, SHA2_256_MODE);

    memw();
    for (int i = 0; i < 16; ++i) sha_text[i] = test_input[i];
    memw();
    *sha_mode  = SHA2_256_MODE;
    memw();
    *sha_start = 1;
    memw();
    while (*sha_busy != 0) {}
    memw();
    uint32_t h_clean[8];
    for (int i = 0; i < 8; ++i) h_clean[i] = sha_h[i];

    memw();
    for (int i = 0; i < 16; ++i) sha_text[i] = test_input[i];
    memw();
    *sha_mode  = SHA2_256_MODE;
    memw();
    *sha_start = 1;
    sha_text[10] = 0xDEADBEEFU;
    memw();
    while (*sha_busy != 0) {}
    memw();
    uint32_t h_stomp[8];
    for (int i = 0; i < 8; ++i) h_stomp[i] = sha_h[i];

    esp_sha_release_hardware();

    s_overlap_safe = true;
    for (int i = 0; i < 8; ++i) {
        if (h_clean[i] != h_stomp[i]) { s_overlap_safe = false; break; }
    }
    s_overlap_ran = true;
    Serial.printf("[AxeHub] SHA overlap canary: %s (clean h0=%08x stomp h0=%08x)\n",
                  s_overlap_safe ? "SAFE (peripheral snapshots TEXT)" : "UNSAFE (peripheral reads TEXT during compute)",
                  h_clean[0], h_stomp[0]);
    return s_overlap_safe;
}

static bool    s_hwrite_ran    = false;
static bool    s_hwrite_safe   = false;

bool axehub_sha_fast_hwrite_canary(void)
{
    volatile uint32_t * const sha_start    = (volatile uint32_t *)SHA_START_REG;
    volatile uint32_t * const sha_busy     = (volatile uint32_t *)SHA_BUSY_REG;
    volatile uint32_t * const sha_mode     = (volatile uint32_t *)SHA_MODE_REG;
    volatile uint32_t * const sha_h        = (volatile uint32_t *)SHA_H_BASE;
    volatile uint32_t * const sha_text     = (volatile uint32_t *)SHA_TEXT_BASE;

    static const uint32_t test_input[16] = {
        0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC,
        0xDEADBEEF, 0xCAFEBABE, 0x01010101, 0xFEEDFACE,
        0x00000080, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x80020000,
    };

    esp_sha_acquire_hardware();
    REG_WRITE(SHA_MODE_REG, SHA2_256_MODE);

    memw();
    for (int i = 0; i < 16; ++i) sha_text[i] = test_input[i];
    memw();
    *sha_mode  = SHA2_256_MODE;
    memw();
    *sha_start = 1;
    memw();
    while (*sha_busy != 0) {}
    memw();
    uint32_t h_clean[8];
    for (int i = 0; i < 8; ++i) h_clean[i] = sha_h[i];

    memw();
    for (int i = 0; i < 16; ++i) sha_text[i] = test_input[i];
    memw();
    *sha_mode  = SHA2_256_MODE;
    memw();
    *sha_start = 1;
    sha_h[0] = 0xDEADBEEFU;
    memw();
    while (*sha_busy != 0) {}
    memw();
    uint32_t h_stomp[8];
    for (int i = 0; i < 8; ++i) h_stomp[i] = sha_h[i];

    esp_sha_release_hardware();

    s_hwrite_safe = true;
    for (int i = 0; i < 8; ++i) {
        if (h_clean[i] != h_stomp[i]) { s_hwrite_safe = false; break; }
    }
    s_hwrite_ran = true;
    Serial.printf("[AxeHub] SHA H-write canary: %s (clean h0=%08x stomp h0=%08x)\n",
                  s_hwrite_safe ? "SAFE (H writes ignored during compute)"
                                 : "UNSAFE (H writes corrupt live state)",
                  h_clean[0], h_stomp[0]);
    return s_hwrite_safe;
}

bool axehub_sha_fast_get_hwrite_safe(void) { return s_hwrite_safe; }
bool axehub_sha_fast_get_hwrite_ran(void)  { return s_hwrite_ran;  }

#ifdef AXEHUB_HW_ASM

static bool s_asm_selftest_passed = false;
static uint8_t s_asm_selftest_got[32] = {0};
bool axehub_sha_fast_get_asm_selftest_passed(void) { return s_asm_selftest_passed; }
const uint8_t* axehub_sha_fast_get_asm_selftest_got(void) { return s_asm_selftest_got; }

#ifdef AXEHUB_HW_ASM_PURE
static bool s_pure_selftest_passed = false;
static uint8_t s_pure_selftest_got[32] = {0};
bool axehub_sha_fast_get_pure_selftest_passed(void) { return s_pure_selftest_passed; }
const uint8_t* axehub_sha_fast_get_pure_selftest_got(void) { return s_pure_selftest_got; }
#endif

static inline __attribute__((always_inline)) void compute_one_asm_inline(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash);

void IRAM_ATTR axehub_sha_fast_compute_one_asm(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash)
{
    compute_one_asm_inline(midstate, block2_words, nonce, out_hash);
}

static inline __attribute__((always_inline)) void compute_one_asm_inline(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t        nonce,
    uint8_t        *out_hash)
{
    __asm__ __volatile__ (
        ".literal_position\n"
        ".literal    .Lsha_base_co_%=, 0x6003B000\n"
        ".literal    .Ltext_base_co_%=, 0x6003B080\n"
        ".literal    .Lh_base_co_%=, 0x6003B040\n"
        ".literal    .Lt15_first_co_%=, 0x80020000\n"
        ".literal    .Lt15_inter_co_%=, 0x00010000\n"
        "l32r       a8, .Lsha_base_co_%=\n"   // SHA_BASE (MODE/START/CONT/BUSY)
        "l32r       a9, .Ltext_base_co_%=\n"  // SHA_TEXT_BASE
        "l32r       a10, .Lh_base_co_%=\n"    // SHA_H_BASE

        "l32i.n     a11, %[mid], 0\n"
        "s32i.n     a11, a10, 0\n"
        "l32i.n     a11, %[mid], 4\n"
        "s32i.n     a11, a10, 4\n"
        "l32i.n     a11, %[mid], 8\n"
        "s32i.n     a11, a10, 8\n"
        "l32i.n     a11, %[mid], 12\n"
        "s32i.n     a11, a10, 12\n"
        "l32i.n     a11, %[mid], 16\n"
        "s32i.n     a11, a10, 16\n"
        "l32i.n     a11, %[mid], 20\n"
        "s32i.n     a11, a10, 20\n"
        "l32i.n     a11, %[mid], 24\n"
        "s32i.n     a11, a10, 24\n"
        "l32i.n     a11, %[mid], 28\n"
        "s32i.n     a11, a10, 28\n"

        "l32i.n     a11, %[blk2], 0\n"
        "s32i.n     a11, a9, 0\n"
        "l32i.n     a11, %[blk2], 4\n"
        "s32i.n     a11, a9, 4\n"
        "l32i.n     a11, %[blk2], 8\n"
        "s32i.n     a11, a9, 8\n"
        "s32i.n     %[nonce], a9, 12\n"
        "movi.n     a11, 0x80\n"
        "s32i.n     a11, a9, 16\n"
        "movi.n     a11, 0\n"
        "s32i.n     a11, a9, 20\n"
        "s32i.n     a11, a9, 24\n"
        "s32i.n     a11, a9, 28\n"
        "s32i.n     a11, a9, 32\n"
        "s32i.n     a11, a9, 36\n"
        "s32i.n     a11, a9, 40\n"
        "s32i.n     a11, a9, 44\n"
        "s32i.n     a11, a9, 48\n"
        "s32i.n     a11, a9, 52\n"
        "s32i.n     a11, a9, 56\n"
        "l32r       a11, .Lt15_first_co_%=\n"
        "s32i.n     a11, a9, 60\n"

        "memw\n"
        "movi.n     a11, 2\n"
        "s32i.n     a11, a8, 0\n"
        "movi.n     a11, 1\n"
        "s32i.n     a11, a8, 20\n"

        "1:\n"
        "l32i.n     a11, a8, 24\n"
        "bnez.n     a11, 1b\n"

        "l32i.n     a11, a10, 0\n"
        "s32i.n     a11, a9, 0\n"
        "l32i.n     a11, a10, 4\n"
        "s32i.n     a11, a9, 4\n"
        "l32i.n     a11, a10, 8\n"
        "s32i.n     a11, a9, 8\n"
        "l32i.n     a11, a10, 12\n"
        "s32i.n     a11, a9, 12\n"
        "l32i.n     a11, a10, 16\n"
        "s32i.n     a11, a9, 16\n"
        "l32i.n     a11, a10, 20\n"
        "s32i.n     a11, a9, 20\n"
        "l32i.n     a11, a10, 24\n"
        "s32i.n     a11, a9, 24\n"
        "l32i.n     a11, a10, 28\n"
        "s32i.n     a11, a9, 28\n"

        "movi.n     a11, 0x80\n"
        "s32i.n     a11, a9, 32\n"
        "movi.n     a11, 0\n"
        "s32i.n     a11, a9, 36\n"
        "s32i.n     a11, a9, 40\n"
        "s32i.n     a11, a9, 44\n"
        "s32i.n     a11, a9, 48\n"
        "s32i.n     a11, a9, 52\n"
        "s32i.n     a11, a9, 56\n"
        "l32r       a11, .Lt15_inter_co_%=\n"
        "s32i.n     a11, a9, 60\n"

        "memw\n"
        "movi.n     a11, 2\n"
        "s32i.n     a11, a8, 0\n"
        "movi.n     a11, 1\n"
        "s32i.n     a11, a8, 16\n"


        "2:\n"
        "l32i.n     a11, a8, 24\n"
        "bnez.n     a11, 2b\n"

        "l32i.n     a11, a10, 0\n"
        "s32i.n     a11, %[out], 0\n"
        "l32i.n     a11, a10, 4\n"
        "s32i.n     a11, %[out], 4\n"
        "l32i.n     a11, a10, 8\n"
        "s32i.n     a11, %[out], 8\n"
        "l32i.n     a11, a10, 12\n"
        "s32i.n     a11, %[out], 12\n"
        "l32i.n     a11, a10, 16\n"
        "s32i.n     a11, %[out], 16\n"
        "l32i.n     a11, a10, 20\n"
        "s32i.n     a11, %[out], 20\n"
        "l32i.n     a11, a10, 24\n"
        "s32i.n     a11, %[out], 24\n"
        "l32i.n     a11, a10, 28\n"
        "s32i.n     a11, %[out], 28\n"
        :
        : [mid] "r"(midstate),
          [blk2] "r"(block2_words),
          [nonce] "r"(nonce),
          [out] "r"(out_hash)
        : "a8", "a9", "a10", "a11", "memory"
    );
}

bool IRAM_ATTR axehub_sha_fast_mine_batch_asm(
    const uint32_t *midstate,
    const uint32_t *block2_words,
    uint32_t       *nonce_io,
    uint32_t        nonce_end,
    uint8_t        *out_hash,
    volatile uint32_t *hash_counter,
    volatile bool  *mining_active)
{

    uint32_t local_nonce = *nonce_io;
    uint32_t total_done  = 0;
    bool     found       = false;

    while (local_nonce != nonce_end) {
        if (!*mining_active) break;

        uint32_t sub_end = local_nonce + 256;
        if ((int32_t)(sub_end - nonce_end) > 0 || sub_end < local_nonce) {
            sub_end = nonce_end;
        }

        uint32_t before = local_nonce;
        uint32_t candidate = 0;
        uint8_t hash[32] __attribute__((aligned(4)));

        __asm__ __volatile__ (
            ".literal_position\n"
            ".literal    .Lsha_base_mb_%=, 0x6003B000\n"
            ".literal    .Ltext_base_mb_%=, 0x6003B080\n"
            ".literal    .Lh_base_mb_%=, 0x6003B040\n"
            ".literal    .Lt15_first_mb_%=, 0x80020000\n"
            ".literal    .Lt15_inter_mb_%=, 0x00010000\n"

            "l32r       a8,  .Lsha_base_mb_%=\n"
            "l32r       a9,  .Ltext_base_mb_%=\n"
            "l32r       a10, .Lh_base_mb_%=\n"

            "mb_loop_%=:\n"
            "l32i.n     a11, %[mid], 0\n"
            "s32i.n     a11, a10, 0\n"
            "l32i.n     a11, %[mid], 4\n"
            "s32i.n     a11, a10, 4\n"
            "l32i.n     a11, %[mid], 8\n"
            "s32i.n     a11, a10, 8\n"
            "l32i.n     a11, %[mid], 12\n"
            "s32i.n     a11, a10, 12\n"
            "l32i.n     a11, %[mid], 16\n"
            "s32i.n     a11, a10, 16\n"
            "l32i.n     a11, %[mid], 20\n"
            "s32i.n     a11, a10, 20\n"
            "l32i.n     a11, %[mid], 24\n"
            "s32i.n     a11, a10, 24\n"
            "l32i.n     a11, %[mid], 28\n"
            "s32i.n     a11, a10, 28\n"

            "l32i.n     a11, %[blk2], 0\n"
            "s32i.n     a11, a9, 0\n"
            "l32i.n     a11, %[blk2], 4\n"
            "s32i.n     a11, a9, 4\n"
            "l32i.n     a11, %[blk2], 8\n"
            "s32i.n     a11, a9, 8\n"
            "s32i.n     %[nonce], a9, 12\n"
            "movi.n     a11, 0x80\n"
            "s32i.n     a11, a9, 16\n"
            "movi.n     a11, 0\n"
            "s32i.n     a11, a9, 20\n"
            "s32i.n     a11, a9, 24\n"
            "s32i.n     a11, a9, 28\n"
            "s32i.n     a11, a9, 32\n"
            "s32i.n     a11, a9, 36\n"
            "s32i.n     a11, a9, 40\n"
            "s32i.n     a11, a9, 44\n"
            "s32i.n     a11, a9, 48\n"
            "s32i.n     a11, a9, 52\n"
            "s32i.n     a11, a9, 56\n"
            "l32r       a11, .Lt15_first_mb_%=\n"
            "s32i.n     a11, a9, 60\n"

            "memw\n"
            "movi.n     a11, 2\n"
            "s32i.n     a11, a8, 0\n"
            "movi.n     a11, 1\n"
            "s32i.n     a11, a8, 20\n"

            "mb_w1_%=:\n"
            "l32i.n     a11, a8, 24\n"
            "bnez.n     a11, mb_w1_%=\n"

            "l32i.n     a11, a10, 0\n"
            "s32i.n     a11, a9, 0\n"
            "l32i.n     a11, a10, 4\n"
            "s32i.n     a11, a9, 4\n"
            "l32i.n     a11, a10, 8\n"
            "s32i.n     a11, a9, 8\n"
            "l32i.n     a11, a10, 12\n"
            "s32i.n     a11, a9, 12\n"
            "l32i.n     a11, a10, 16\n"
            "s32i.n     a11, a9, 16\n"
            "l32i.n     a11, a10, 20\n"
            "s32i.n     a11, a9, 20\n"
            "l32i.n     a11, a10, 24\n"
            "s32i.n     a11, a9, 24\n"
            "l32i.n     a11, a10, 28\n"
            "s32i.n     a11, a9, 28\n"


            "movi.n     a11, 0x80\n"
            "s32i.n     a11, a9, 32\n"
            "movi.n     a11, 0\n"
            "s32i.n     a11, a9, 36\n"
            "s32i.n     a11, a9, 40\n"
            "s32i.n     a11, a9, 44\n"
            "s32i.n     a11, a9, 48\n"
            "s32i.n     a11, a9, 52\n"
            "s32i.n     a11, a9, 56\n"
            "l32r       a11, .Lt15_inter_mb_%=\n"
            "s32i.n     a11, a9, 60\n"

            "memw\n"
            "movi.n     a11, 2\n"
            "s32i.n     a11, a8, 0\n"
            "movi.n     a11, 1\n"
            "s32i.n     a11, a8, 16\n"

            "mb_w2_%=:\n"
            "l32i.n     a11, a8, 24\n"
            "bnez.n     a11, mb_w2_%=\n"
            "memw\n"

            "addi.n     %[nonce], %[nonce], 1\n"

            // Early reject: read H[7], check upper 16 bits
            "l32i.n     a11, a10, 28\n"
            "extui      a11, a11, 16, 16\n"
            "beqz.n     a11, mb_cand_%=\n"

            "memw\n"
            "bne        %[nonce], %[end], mb_loop_%=\n"
            "j          mb_done_%=\n"

            "mb_cand_%=:\n"
            "movi.n     %[cand], 1\n"
            "l32i.n     a11, a10, 0\n"
            "s32i.n     a11, %[out], 0\n"
            "l32i.n     a11, a10, 4\n"
            "s32i.n     a11, %[out], 4\n"
            "l32i.n     a11, a10, 8\n"
            "s32i.n     a11, %[out], 8\n"
            "l32i.n     a11, a10, 12\n"
            "s32i.n     a11, %[out], 12\n"
            "l32i.n     a11, a10, 16\n"
            "s32i.n     a11, %[out], 16\n"
            "l32i.n     a11, a10, 20\n"
            "s32i.n     a11, %[out], 20\n"
            "l32i.n     a11, a10, 24\n"
            "s32i.n     a11, %[out], 24\n"
            "l32i.n     a11, a10, 28\n"
            "s32i.n     a11, %[out], 28\n"

            "mb_done_%=:\n"
            : [nonce] "+r"(local_nonce),
              [cand]  "+r"(candidate)
            : [mid]   "r"(midstate),
              [blk2]  "r"(block2_words),
              [end]   "r"(sub_end),
              [out]   "r"(hash)
            : "a8", "a9", "a10", "a11", "memory"
        );

        total_done += (local_nonce - before);
        if (candidate) {
            memcpy(out_hash, hash, 32);
            local_nonce -= 1;  // candidate produced the previous nonce
            found = true;
            local_nonce += 1;  // resume from next on caller's next call
            break;
        }
    }

    *nonce_io = local_nonce;
    *hash_counter += total_done;
    return found;
}

#endif

bool axehub_sha_fast_get_selftest_status(void) { return s_selftest_passed; }
bool axehub_sha_fast_get_selftest_ran(void)    { return s_selftest_ran; }
const uint8_t* axehub_sha_fast_get_selftest_expected(void) { return s_selftest_expected; }
const uint8_t* axehub_sha_fast_get_selftest_got(void)      { return s_selftest_got; }
const uint8_t* axehub_sha_fast_get_selftest_baseline(void) { return s_selftest_baseline; }

static void IRAM_ATTR baseline_compute_one(const uint32_t *midstate,
                                           const uint8_t *sha_buffer_64bytes,
                                           uint32_t nonce,
                                           uint8_t *out_hash)
{
    volatile uint32_t * const sha_continue = (volatile uint32_t *)SHA_CONTINUE_REG;
    volatile uint32_t * const sha_start    = (volatile uint32_t *)SHA_START_REG;
    volatile uint32_t * const sha_busy     = (volatile uint32_t *)SHA_BUSY_REG;
    volatile uint32_t * const sha_h        = (volatile uint32_t *)SHA_H_BASE;
    volatile uint32_t * const sha_text     = (volatile uint32_t *)SHA_TEXT_BASE;

    REG_WRITE(SHA_MODE_REG, SHA2_256_MODE);

    for (int i = 0; i < 8; ++i) sha_h[i] = midstate[i];

    const uint32_t *data_words = (const uint32_t *)sha_buffer_64bytes;
    sha_text[0]  = data_words[0];
    sha_text[1]  = data_words[1];
    sha_text[2]  = data_words[2];
    sha_text[3]  = nonce;
    sha_text[4]  = 0x00000080U;
    sha_text[5]  = 0;
    sha_text[6]  = 0;
    sha_text[7]  = 0;
    sha_text[8]  = 0;
    sha_text[9]  = 0;
    sha_text[10] = 0;
    sha_text[11] = 0;
    sha_text[12] = 0;
    sha_text[13] = 0;
    sha_text[14] = 0;
    sha_text[15] = 0x80020000U;

    *sha_continue = 1;
    while (*sha_busy != 0) {}

    for (int i = 0; i < 8; ++i) sha_text[i] = sha_h[i];
    sha_text[8]  = 0x00000080U;
    sha_text[9]  = 0;
    sha_text[10] = 0;
    sha_text[11] = 0;
    sha_text[12] = 0;
    sha_text[13] = 0;
    sha_text[14] = 0;
    sha_text[15] = 0x00010000U;

    *sha_start = 1;
    while (*sha_busy != 0) {}

    for (int i = 0; i < 8; ++i) ((uint32_t *)out_hash)[i] = sha_h[i];
}

bool axehub_sha_fast_selftest(void)
{

    static const uint8_t test_header[80] = {
        0x00, 0x00, 0x00, 0x22, 0x99, 0x44, 0xbb, 0xff, 0xbb, 0x00, 0x00, 0x77,
        0x44, 0xcc, 0x11, 0x77, 0x88, 0x55, 0xbb, 0x44, 0x55, 0x00, 0x77, 0x88,
        0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0xbb, 0x66, 0x11, 0x88, 0x33, 0x44, 0x99, 0xcc, 0x33, 0xff, 0x22,
        0x11, 0xaa, 0x77, 0xee, 0xbb, 0x66, 0xee, 0xcc, 0xee, 0x66, 0xee, 0xdd,
        0x77, 0x55, 0x22, 0x22, 0xcc, 0xcc, 0x66, 0xee, 0x22, 0xdd, 0x99, 0x66,
        0x66, 0x88, 0x00, 0x11, 0x2e, 0x33, 0x41, 0x19,
    };
    const uint32_t test_nonce = 0xCAFEBABEU;

    uint8_t header_with_nonce[80];
    memcpy(header_with_nonce, test_header, 80);
    ((uint32_t *)header_with_nonce)[19] = test_nonce;  // word 19 = bytes 76..79

    nerdSHA256_context ctx;
    nerd_mids(ctx.digest, header_with_nonce);

    uint8_t intermediate[32];
    uint8_t reference_hash[32];
    mbedtls_sha256_context mctx;
    mbedtls_sha256_init(&mctx);
    mbedtls_sha256_starts_ret(&mctx, 0);
    mbedtls_sha256_update_ret(&mctx, header_with_nonce, 80);
    mbedtls_sha256_finish_ret(&mctx, intermediate);
    mbedtls_sha256_free(&mctx);
    mbedtls_sha256_init(&mctx);
    mbedtls_sha256_starts_ret(&mctx, 0);
    mbedtls_sha256_update_ret(&mctx, intermediate, 32);
    mbedtls_sha256_finish_ret(&mctx, reference_hash);
    mbedtls_sha256_free(&mctx);

    uint32_t midstate_words[8];
    memcpy(midstate_words, ctx.digest, sizeof(midstate_words));
    uint32_t block2_words[3];
    memcpy(block2_words, test_header + 64, sizeof(block2_words));

    esp_sha_acquire_hardware();

    uint8_t baseline_hash[32] __attribute__((aligned(4)));
    baseline_compute_one(midstate_words, header_with_nonce + 64, test_nonce, baseline_hash);

    axehub_sha_fast_init_job();
    uint8_t fast_hash[32] __attribute__((aligned(4)));
    axehub_sha_fast_compute_one(midstate_words, block2_words, test_nonce, fast_hash);

#ifdef AXEHUB_HW_ASM
    uint8_t asm_hash[32] __attribute__((aligned(4)));
    axehub_sha_fast_compute_one_asm(midstate_words, block2_words, test_nonce, asm_hash);
    memcpy(s_asm_selftest_got, asm_hash, 32);
    s_asm_selftest_passed = (memcmp(asm_hash, baseline_hash, 32) == 0);
    Serial.printf("[AxeHub] ASM selftest: %s\n", s_asm_selftest_passed ? "PASS" : "FAIL");
#endif

#ifdef AXEHUB_HW_ASM_PURE
    uint32_t pure_nonce_io = test_nonce;
    uint8_t pure_hash[32] __attribute__((aligned(4)));
    memset(pure_hash, 0xEE, 32);  // canary so we can tell if it was written
    int32_t pure_ret = axehub_sha_asm_s3_mine_batch(
        midstate_words, block2_words, &pure_nonce_io, test_nonce + 1, pure_hash);
    if (pure_ret == 0) {
        volatile uint32_t *sha_h = (volatile uint32_t *)SHA_H_BASE;
        for (int i = 0; i < 8; ++i) ((uint32_t *)pure_hash)[i] = sha_h[i];
    }
    memcpy(s_pure_selftest_got, pure_hash, 32);
    s_pure_selftest_passed = (memcmp(pure_hash, baseline_hash, 32) == 0);
    Serial.printf("[AxeHub] PURE-ASM selftest: %s (ret=%d)\n",
                  s_pure_selftest_passed ? "PASS" : "FAIL", (int)pure_ret);
#endif

    esp_sha_release_hardware();

    memcpy(s_selftest_expected, reference_hash, 32);
    memcpy(s_selftest_got,      fast_hash,      32);
    memcpy(s_selftest_baseline, baseline_hash,  32);
    s_selftest_passed = (memcmp(fast_hash, baseline_hash, 32) == 0);
    s_selftest_ran    = true;
    Serial.printf("[AxeHub] SHA fast selftest: %s\n",
                  s_selftest_passed ? "PASS" : "FAIL");
    if (!s_selftest_passed) {
        Serial.print("  expected: ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", reference_hash[i]);
        Serial.print("\n  got:      ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", fast_hash[i]);
        Serial.println();
    }
    return s_selftest_passed;
}

#ifdef AXEHUB_HW_ASM_PURE

static bool    s_sw_asm_selftest_ran    = false;
static bool    s_sw_asm_selftest_passed = false;
static uint8_t s_sw_asm_selftest_got[32];

bool axehub_sha_sw_asm_selftest(void)
{
    uint32_t state[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    uint32_t msg[16] = {
        0x61626380, 0, 0, 0, 0, 0, 0, 0,
        0,          0, 0, 0, 0, 0, 0, 0x00000018
    };
    static const uint32_t expected[8] = {
        0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223,
        0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD
    };

    axehub_sha_sw_asm_compress_block(state, msg);

    for (int i = 0; i < 8; ++i) {
        s_sw_asm_selftest_got[i*4 + 0] = (uint8_t)(state[i] >> 24);
        s_sw_asm_selftest_got[i*4 + 1] = (uint8_t)(state[i] >> 16);
        s_sw_asm_selftest_got[i*4 + 2] = (uint8_t)(state[i] >>  8);
        s_sw_asm_selftest_got[i*4 + 3] = (uint8_t)(state[i]      );
    }

    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        if (state[i] != expected[i]) { ok = false; break; }
    }

    s_sw_asm_selftest_passed = ok;
    s_sw_asm_selftest_ran    = true;
    Serial.printf("[AxeHub] SHA SW-asm compress selftest: %s\n", ok ? "PASS" : "FAIL");
    if (!ok) {
        Serial.print("  expected: ");
        for (int i = 0; i < 8; ++i) Serial.printf("%08x ", expected[i]);
        Serial.print("\n  got:      ");
        for (int i = 0; i < 8; ++i) Serial.printf("%08x ", state[i]);
        Serial.println();
    }
    return ok;
}

bool axehub_sha_sw_asm_get_selftest_ran(void)    { return s_sw_asm_selftest_ran; }
bool axehub_sha_sw_asm_get_selftest_passed(void) { return s_sw_asm_selftest_passed; }
const uint8_t* axehub_sha_sw_asm_get_selftest_got(void) { return s_sw_asm_selftest_got; }

void IRAM_ATTR axehub_sha_sw_asm_double_hash(const uint32_t midstate[8],
                                             const uint8_t  tail[16],
                                             uint8_t        out_hash[32])
{
    uint32_t state[8];
    uint32_t msg[16];

    for (int i = 0; i < 8; ++i) state[i] = midstate[i];
    for (int i = 0; i < 4; ++i) {
        msg[i] = ((uint32_t)tail[i*4+0] << 24)
               | ((uint32_t)tail[i*4+1] << 16)
               | ((uint32_t)tail[i*4+2] <<  8)
               |  (uint32_t)tail[i*4+3];
    }
    msg[4] = 0x80000000U;
    for (int i = 5; i < 15; ++i) msg[i] = 0;
    msg[15] = 640;

    axehub_sha_sw_asm_compress_block(state, msg);

    for (int i = 0; i < 8; ++i) msg[i] = state[i];
    msg[8] = 0x80000000U;
    for (int i = 9; i < 15; ++i) msg[i] = 0;
    msg[15] = 256;

    state[0] = 0x6A09E667; state[1] = 0xBB67AE85;
    state[2] = 0x3C6EF372; state[3] = 0xA54FF53A;
    state[4] = 0x510E527F; state[5] = 0x9B05688C;
    state[6] = 0x1F83D9AB; state[7] = 0x5BE0CD19;

    axehub_sha_sw_asm_compress_block(state, msg);

    for (int i = 0; i < 8; ++i) {
        out_hash[i*4+0] = (uint8_t)(state[i] >> 24);
        out_hash[i*4+1] = (uint8_t)(state[i] >> 16);
        out_hash[i*4+2] = (uint8_t)(state[i] >>  8);
        out_hash[i*4+3] = (uint8_t)(state[i]      );
    }
}

bool IRAM_ATTR axehub_sha_sw_asm_mine(const uint32_t midstate[8],
                                      const uint8_t  tail[16],
                                      uint8_t        out_hash[32])
{
    uint32_t state[8];
    uint32_t msg[16];

    for (int i = 0; i < 8; ++i) state[i] = midstate[i];
    for (int i = 0; i < 4; ++i) {
        msg[i] = ((uint32_t)tail[i*4+0] << 24)
               | ((uint32_t)tail[i*4+1] << 16)
               | ((uint32_t)tail[i*4+2] <<  8)
               |  (uint32_t)tail[i*4+3];
    }
    msg[4] = 0x80000000U;
    for (int i = 5; i < 15; ++i) msg[i] = 0;
    msg[15] = 640;

    axehub_sha_sw_asm_compress_block(state, msg);

    for (int i = 0; i < 8; ++i) msg[i] = state[i];
    msg[8] = 0x80000000U;
    for (int i = 9; i < 15; ++i) msg[i] = 0;
    msg[15] = 256;

    state[0] = 0x6A09E667; state[1] = 0xBB67AE85;
    state[2] = 0x3C6EF372; state[3] = 0xA54FF53A;
    state[4] = 0x510E527F; state[5] = 0x9B05688C;
    state[6] = 0x1F83D9AB; state[7] = 0x5BE0CD19;

    if (axehub_sha_sw_asm_compress_block2_reject(state, msg) == 0) {
        return false;
    }

    for (int i = 0; i < 8; ++i) {
        out_hash[i*4+0] = (uint8_t)(state[i] >> 24);
        out_hash[i*4+1] = (uint8_t)(state[i] >> 16);
        out_hash[i*4+2] = (uint8_t)(state[i] >>  8);
        out_hash[i*4+3] = (uint8_t)(state[i]      );
    }
    return true;
}

static bool    s_sw_asm_double_ran      = false;
static bool    s_sw_asm_double_passed   = false;
static uint8_t s_sw_asm_double_got[32];
static uint8_t s_sw_asm_double_expected[32];

bool axehub_sha_sw_asm_double_selftest(void)
{
    static const uint8_t test_header[80] = {
        0x00, 0x00, 0x00, 0x22, 0x99, 0x44, 0xbb, 0xff, 0xbb, 0x00, 0x00, 0x77,
        0x44, 0xcc, 0x11, 0x77, 0x88, 0x55, 0xbb, 0x44, 0x55, 0x00, 0x77, 0x88,
        0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0xbb, 0x66, 0x11, 0x88, 0x33, 0x44, 0x99, 0xcc, 0x33, 0xff, 0x22,
        0x11, 0xaa, 0x77, 0xee, 0xbb, 0x66, 0xee, 0xcc, 0xee, 0x66, 0xee, 0xdd,
        0x77, 0x55, 0x22, 0x22, 0xcc, 0xcc, 0x66, 0xee, 0x22, 0xdd, 0x99, 0x66,
        0x66, 0x88, 0x00, 0x11, 0x2e, 0x33, 0x41, 0x19,
    };

    uint8_t intermediate[32];
    uint8_t reference[32];
    mbedtls_sha256_context mctx;
    mbedtls_sha256_init(&mctx);
    mbedtls_sha256_starts_ret(&mctx, 0);
    mbedtls_sha256_update_ret(&mctx, test_header, 80);
    mbedtls_sha256_finish_ret(&mctx, intermediate);
    mbedtls_sha256_free(&mctx);
    mbedtls_sha256_init(&mctx);
    mbedtls_sha256_starts_ret(&mctx, 0);
    mbedtls_sha256_update_ret(&mctx, intermediate, 32);
    mbedtls_sha256_finish_ret(&mctx, reference);
    mbedtls_sha256_free(&mctx);

    uint32_t midstate[8];
    nerd_mids(midstate, test_header);
    uint8_t asm_hash[32];
    axehub_sha_sw_asm_double_hash(midstate, test_header + 64, asm_hash);

    memcpy(s_sw_asm_double_expected, reference, 32);
    memcpy(s_sw_asm_double_got,      asm_hash,  32);
    bool ok = (memcmp(asm_hash, reference, 32) == 0);
    s_sw_asm_double_passed = ok;
    s_sw_asm_double_ran    = true;
    Serial.printf("[AxeHub] SHA SW-asm double-hash selftest: %s\n", ok ? "PASS" : "FAIL");
    if (!ok) {
        Serial.print("  expected: ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", reference[i]);
        Serial.print("\n  got:      ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", asm_hash[i]);
        Serial.println();
    }
    return ok;
}

bool axehub_sha_sw_asm_get_double_selftest_ran(void)    { return s_sw_asm_double_ran; }
bool axehub_sha_sw_asm_get_double_selftest_passed(void) { return s_sw_asm_double_passed; }
const uint8_t* axehub_sha_sw_asm_get_double_selftest_got(void)      { return s_sw_asm_double_got; }
const uint8_t* axehub_sha_sw_asm_get_double_selftest_expected(void) { return s_sw_asm_double_expected; }

extern "C" {
#include "sha/sha_dma.h"
}
void axehub_sha_hw_dma_microbench(void)
{
    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    static uint8_t input_block[64] __attribute__((aligned(16)));
    for (int i = 0; i < 64; ++i) input_block[i] = (uint8_t)(0xAA + i);

    esp_sha_acquire_hardware();

    const uint32_t N = 200;
    uint32_t min_first = 0xFFFFFFFF, sum_first = 0;
    uint32_t min_cont  = 0xFFFFFFFF, sum_cont  = 0;
    uint32_t min_2blk  = 0xFFFFFFFF, sum_2blk  = 0;

    for (uint32_t i = 0; i < N; ++i) {
        input_block[60] = (uint8_t)i;  // mod data per iter
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input_block, 64, NULL, 0, true);
        uint32_t dt = rdcc() - t0;
        sum_first += dt;
        if (dt < min_first) min_first = dt;
    }
    Serial.printf("[uBenchHW-DMA] single block first (IV reset): avg=%u min=%u cyc\n",
                  sum_first/N, min_first);

    for (uint32_t i = 0; i < N; ++i) {
        input_block[60] = (uint8_t)i;
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input_block, 64, NULL, 0, false);
        uint32_t dt = rdcc() - t0;
        sum_cont += dt;
        if (dt < min_cont) min_cont = dt;
    }
    Serial.printf("[uBenchHW-DMA] single block continue:        avg=%u min=%u cyc\n",
                  sum_cont/N, min_cont);

    static uint8_t input_2blk[128] __attribute__((aligned(16)));
    for (int i = 0; i < 128; ++i) input_2blk[i] = (uint8_t)(0xBB + i);
    for (uint32_t i = 0; i < N; ++i) {
        input_2blk[60] = (uint8_t)i;
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input_2blk, 128, NULL, 0, true);
        uint32_t dt = rdcc() - t0;
        sum_2blk += dt;
        if (dt < min_2blk) min_2blk = dt;
    }
    Serial.printf("[uBenchHW-DMA] 2 blocks (128B):              avg=%u min=%u cyc\n",
                  sum_2blk/N, min_2blk);

    esp_sha_release_hardware();
    Serial.printf("[uBenchHW-DMA] Current manual DPort per-nonce: ~868 cyc. DMA per-nonce target: %u\n",
                  min_2blk);
    Serial.flush();
}

void axehub_sha_hw_phase_microbench(void)
{
    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    volatile uint32_t * const sha_base = (uint32_t *)0x6003B000;
    volatile uint32_t * const sha_text = (uint32_t *)0x6003B080;
    volatile uint32_t * const sha_h    = (uint32_t *)0x6003B040;

    sha_base[0] = 2;
    for (int i = 0; i < 8; ++i) sha_h[i] = 0x6A09E667 + i*0x11111111;
    for (int i = 0; i < 16; ++i) sha_text[i] = 0xDEADBEEF + i;
    sha_base[16/4] = 1;
    while (sha_base[24/4]) ;

    const uint32_t N = 1000;
    uint64_t s_overlap1=0, s_wait1=0, s_phaseE=0, s_trig=0;
    uint64_t s_overlap2=0, s_wait2=0, s_filter=0, s_phaseA=0, s_trigC=0;

    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        sha_base[20/4] = 1;  // CONTINUE -- start "block-2 hash"

        uint32_t t0 = rdcc();
        sha_text[8]=0x80; sha_text[9]=0; sha_text[10]=0; sha_text[11]=0;
        sha_text[12]=0; sha_text[13]=0; sha_text[14]=0; sha_text[15]=0x10000;
        uint32_t t1 = rdcc();
        s_overlap1 += t1-t0;

        t0 = rdcc();
        while (sha_base[24/4]) ;
        t1 = rdcc();
        s_wait1 += t1-t0;

        t0 = rdcc();
        sha_text[0]=sha_h[0]; sha_text[1]=sha_h[1]; sha_text[2]=sha_h[2]; sha_text[3]=sha_h[3];
        sha_text[4]=sha_h[4]; sha_text[5]=sha_h[5]; sha_text[6]=sha_h[6]; sha_text[7]=sha_h[7];
        t1 = rdcc();
        s_phaseE += t1-t0;

        t0 = rdcc();
        __asm__ __volatile__("memw" ::: "memory");
        sha_base[0] = 2;
        sha_base[16/4] = 1;
        t1 = rdcc();
        s_trig += t1-t0;

        t0 = rdcc();
        sha_text[0]=0xAAA0; sha_text[1]=0xAAA1; sha_text[2]=0xAAA2; sha_text[3]=i;
        sha_text[4]=0x80; sha_text[5]=0; sha_text[6]=0; sha_text[7]=0;
        sha_text[8]=0; sha_text[9]=0; sha_text[10]=0; sha_text[11]=0;
        sha_text[12]=0; sha_text[13]=0; sha_text[14]=0; sha_text[15]=0x20000;
        t1 = rdcc();
        s_overlap2 += t1-t0;

        t0 = rdcc();
        while (sha_base[24/4]) ;
        t1 = rdcc();
        s_wait2 += t1-t0;

        t0 = rdcc();
        uint32_t h7 = sha_h[7];
        bool reject = ((h7 >> 16) != 0);
        (void)reject;
        t1 = rdcc();
        s_filter += t1-t0;

        t0 = rdcc();
        sha_h[0]=0x6A09E667; sha_h[1]=0xBB67AE85; sha_h[2]=0x3C6EF372; sha_h[3]=0xA54FF53A;
        sha_h[4]=0x510E527F; sha_h[5]=0x9B05688C; sha_h[6]=0x1F83D9AB; sha_h[7]=0x5BE0CD19;
        t1 = rdcc();
        s_phaseA += t1-t0;

        t0 = rdcc();
        __asm__ __volatile__("memw" ::: "memory");
        sha_base[0] = 2;
        sha_base[20/4] = 1;
        t1 = rdcc();
        s_trigC += t1-t0;

        while (sha_base[24/4]) ;
    }

    Serial.printf("[uBenchHW-Phase] Per nonce avg cykli (N=%u):\n", N);
    Serial.printf("  OVERLAP 1 (8 stores TEXT pad):    %u\n", (uint32_t)(s_overlap1/N));
    Serial.printf("  Wait 1 (block-2 hash done):       %u\n", (uint32_t)(s_wait1/N));
    Serial.printf("  Phase E  (H->TEXT, 16 ops):       %u\n", (uint32_t)(s_phaseE/N));
    Serial.printf("  Trigger INTER (memw+mode+start):  %u\n", (uint32_t)(s_trig/N));
    Serial.printf("  OVERLAP 2 (16 stores next nonce): %u\n", (uint32_t)(s_overlap2/N));
    Serial.printf("  Wait 2 (inter hash done):         %u\n", (uint32_t)(s_wait2/N));
    Serial.printf("  Filter check:                     %u\n", (uint32_t)(s_filter/N));
    Serial.printf("  Phase A  (midstate->H, 8 stores): %u\n", (uint32_t)(s_phaseA/N));
    Serial.printf("  Trigger CONTINUE next nonce:      %u\n", (uint32_t)(s_trigC/N));
    uint64_t total = s_overlap1+s_wait1+s_phaseE+s_trig+s_overlap2+s_wait2+s_filter+s_phaseA+s_trigC;
    Serial.printf("  TOTAL per nonce:                  %u cykli (= %u kH/s)\n",
                  (uint32_t)(total/N), (uint32_t)(240000000ull/(total/N)/1000));
    Serial.flush();
}

void axehub_sha_hw_batch_microbench(void)
{
    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    static const uint8_t test_header[80] = {
        0x00, 0x00, 0x00, 0x22, 0x99, 0x44, 0xbb, 0xff, 0xbb, 0x00, 0x00, 0x77,
        0x44, 0xcc, 0x11, 0x77, 0x88, 0x55, 0xbb, 0x44, 0x55, 0x00, 0x77, 0x88,
        0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0xbb, 0x66, 0x11, 0x88, 0x33, 0x44, 0x99, 0xcc, 0x33, 0xff, 0x22,
        0x11, 0xaa, 0x77, 0xee, 0xbb, 0x66, 0xee, 0xcc, 0xee, 0x66, 0xee, 0xdd,
        0x77, 0x55, 0x22, 0x22, 0xcc, 0xcc, 0x66, 0xee, 0x22, 0xdd, 0x99, 0x66,
        0x66, 0x88, 0x00, 0x11, 0x2e, 0x33, 0x41, 0x19,
    };
    uint32_t midstate[8];
    nerd_mids(midstate, test_header);

    esp_sha_acquire_hardware();
    REG_WRITE(SHA_MODE_REG, SHA2_256);
    axehub_sha_fast_init_job();

    const uint32_t *block2_words = (const uint32_t *)(test_header + 64);

    {
        uint32_t fast_nonce = 0;
        uint8_t hash[32];
        axehub_sha_asm_s3_mine_batch(midstate, block2_words, &fast_nonce, 4096, hash);
    }

    const uint32_t NONCES_PER_BATCH = 50000;
    const uint32_t N_BATCHES = 4;
    uint64_t total_cycles = 0;
    uint64_t total_nonces = 0;

    for (uint32_t b = 0; b < N_BATCHES; ++b) {
        uint32_t fast_nonce = b * NONCES_PER_BATCH;
        uint32_t fast_end = fast_nonce + NONCES_PER_BATCH;
        uint8_t hash[32];

        uint32_t t0 = rdcc();
        while (fast_nonce < fast_end) {
            uint32_t batch_end_inner = fast_nonce + 4096;
            if (batch_end_inner > fast_end) batch_end_inner = fast_end;
            uint32_t nonce_before = fast_nonce;
            int32_t pret = axehub_sha_asm_s3_mine_batch(
                midstate, block2_words, &fast_nonce, batch_end_inner, hash);
            if (pret != 0) {
                fast_nonce++;
            }
        }
        uint32_t dt = rdcc() - t0;
        total_cycles += dt;
        total_nonces += NONCES_PER_BATCH;
        Serial.printf("[uBenchHWB] batch %u: %u nonces in %u cyc = %u cyc/nonce\n",
                      b, NONCES_PER_BATCH, dt, dt / NONCES_PER_BATCH);
    }

    Serial.printf("[uBenchHWB] AVG: %u cyc/nonce (= %u kH/s @240MHz)\n",
                  (uint32_t)(total_cycles / total_nonces),
                  (uint32_t)(240000000ull / (total_cycles / total_nonces) / 1000));

    esp_sha_release_hardware();
    Serial.flush();
}

void axehub_sha_hw_microbench(void)
{
    const uint32_t N = 1000;
    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    volatile uint32_t * const sha_base = (uint32_t *)0x6003B000;
    volatile uint32_t * const sha_text = (uint32_t *)0x6003B080;
    volatile uint32_t * const sha_h    = (uint32_t *)0x6003B040;

    sha_base[0] = 2;  // SHA_MODE
    for (int i = 0; i < 16; ++i) sha_text[i] = 0xDEADBEEF + i;
    for (int i = 0; i < 8; ++i) sha_h[i] = 0x12345678 + i;
    sha_base[16/4] = 1;  // SHA_START at offset 0x10
    while (sha_base[24/4]) ;  // wait BUSY at offset 0x18

    uint32_t min_full = 0xFFFFFFFF, sum_full = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;  // change nonce
        uint32_t t0 = rdcc();
        sha_base[20/4] = 1;  // SHA_CONTINUE at offset 0x14
        while (sha_base[24/4]) ;  // wait BUSY
        uint32_t dt = rdcc() - t0;
        sum_full += dt;
        if (dt < min_full) min_full = dt;
    }
    Serial.printf("[uBenchHW] CONTINUE+wait: avg=%u min=%u cyc/iter\n", sum_full/N, min_full);

    uint32_t min_trig = 0xFFFFFFFF, sum_trig = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        uint32_t t0 = rdcc();
        sha_base[20/4] = 1;
        uint32_t dt = rdcc() - t0;
        sum_trig += dt;
        if (dt < min_trig) min_trig = dt;
        while (sha_base[24/4]) ;  // wait outside measurement
    }
    Serial.printf("[uBenchHW] CONTINUE alone: avg=%u min=%u cyc/iter\n", sum_trig/N, min_trig);

    uint32_t min_wait = 0xFFFFFFFF, sum_wait = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        sha_base[20/4] = 1;  // trigger
        uint32_t t0 = rdcc();
        while (sha_base[24/4]) ;
        uint32_t dt = rdcc() - t0;
        sum_wait += dt;
        if (dt < min_wait) min_wait = dt;
    }
    Serial.printf("[uBenchHW] wait-only: avg=%u min=%u cyc/iter\n", sum_wait/N, min_wait);

    uint32_t min_start = 0xFFFFFFFF, sum_start = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        uint32_t t0 = rdcc();
        sha_base[16/4] = 1;  // SHA_START
        while (sha_base[24/4]) ;
        uint32_t dt = rdcc() - t0;
        sum_start += dt;
        if (dt < min_start) min_start = dt;
    }
    Serial.printf("[uBenchHW] START+wait: avg=%u min=%u cyc/iter\n", sum_start/N, min_start);

    Serial.flush();
}

void axehub_sha_round_microbench(void)
{
    const uint32_t N = 100000;
    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    uint32_t aa=0x6A09E667, bb=0xBB67AE85, cc=0x3C6EF372, dd=0xA54FF53A;
    uint32_t ee=0x510E527F, ff=0x9B05688C, gg=0x1F83D9AB, hh=0x5BE0CD19;
    uint32_t W=0xDEADBEEF, K=0x428A2F98;

    uint32_t t0 = rdcc();
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t s1, t1;
        __asm__ __volatile__(
            "ssai 6\n\t"  "src %[t1], %[e], %[e]\n\t"
            "ssai 11\n\t" "src %[s1], %[e], %[e]\n\t"
            "xor %[t1], %[t1], %[s1]\n\t"
            "ssai 25\n\t" "src %[s1], %[e], %[e]\n\t"
            "xor %[s1], %[t1], %[s1]\n\t"
            : [s1]"=&r"(s1), [t1]"=&r"(t1)
            : [e]"r"(ee)
        );
        ee ^= s1;
    }
    uint32_t t1c = rdcc();
    Serial.printf("[uBench] SIGMA1 (8 instr ssai+src):  %4u cyc/iter (loop+sink ovh ~3) sink=%08x\n", (t1c-t0)/N, ee);

    ee=0x510E527F; ff=0x9B05688C; gg=0x1F83D9AB;
    t0 = rdcc();
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t ch, t;
        __asm__ __volatile__(
            "xor %[t], %[f], %[g]\n\t"
            "and %[t], %[t], %[e]\n\t"
            "xor %[ch], %[t], %[g]\n\t"
            : [ch]"=&r"(ch), [t]"=&r"(t)
            : [e]"r"(ee), [f]"r"(ff), [g]"r"(gg)
        );
        ee ^= ch;
    }
    t1c = rdcc();
    Serial.printf("[uBench] CH (3 instr):                %4u cyc/iter sink=%08x\n", (t1c-t0)/N, ee);

    uint32_t v = 0x12345678;
    t0 = rdcc();
    for (uint32_t i = 0; i < N; ++i) {
        __asm__ __volatile__(
            "add.n %[v], %[v], %[a]\n\t"
            "add.n %[v], %[v], %[b]\n\t"
            "add.n %[v], %[v], %[c]\n\t"
            "add.n %[v], %[v], %[d]\n\t"
            : [v]"+r"(v)
            : [a]"r"(0x111u), [b]"r"(0x222u), [c]"r"(0x333u), [d]"r"(0x444u)
        );
    }
    t1c = rdcc();
    Serial.printf("[uBench] 4-deep sequential add.n:    %4u cyc/iter sink=%08x\n", (t1c-t0)/N, v);

    v = 0x12345678;
    t0 = rdcc();
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t v2 = 0x333u;
        __asm__ __volatile__(
            "add.n %[v],  %[v],  %[a]\n\t"
            "add.n %[v2], %[v2], %[c]\n\t"
            "add.n %[v],  %[v],  %[b]\n\t"
            "add.n %[v],  %[v],  %[v2]\n\t"
            : [v]"+r"(v), [v2]"+r"(v2)
            : [a]"r"(0x111u), [b]"r"(0x222u), [c]"r"(0x444u)
        );
    }
    t1c = rdcc();
    Serial.printf("[uBench] rebalansed add-chain:        %4u cyc/iter sink=%08x\n", (t1c-t0)/N, v);

    t0 = rdcc();
    for (uint32_t i = 0; i < N; ++i) {
        __asm__ __volatile__("nop\n\t" :::);
    }
    t1c = rdcc();
    Serial.printf("[uBench] empty loop (1 nop):          %4u cyc/iter\n", (t1c-t0)/N);

    Serial.flush();
}

bool axehub_sha_sw_asm_reject_selftest(void)
{
    static const uint8_t test_header_proto[80] = {
        0x00, 0x00, 0x00, 0x22, 0x99, 0x44, 0xbb, 0xff, 0xbb, 0x00, 0x00, 0x77,
        0x44, 0xcc, 0x11, 0x77, 0x88, 0x55, 0xbb, 0x44, 0x55, 0x00, 0x77, 0x88,
        0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0xbb, 0x66, 0x11, 0x88, 0x33, 0x44, 0x99, 0xcc, 0x33, 0xff, 0x22,
        0x11, 0xaa, 0x77, 0xee, 0xbb, 0x66, 0xee, 0xcc, 0xee, 0x66, 0xee, 0xdd,
        0x77, 0x55, 0x22, 0x22, 0xcc, 0xcc, 0x66, 0xee, 0x22, 0xdd, 0x99, 0x66,
        0x66, 0x88, 0x00, 0x11, 0x2e, 0x33, 0x41, 0x19,
    };
    uint8_t test_header[80];
    memcpy(test_header, test_header_proto, 80);

    uint32_t midstate[8];
    nerd_mids(midstate, test_header);
    uint32_t bake[15];
    nerd_sha256_bake(midstate, test_header + 64, bake);

    uint8_t  asm_out[32];
    uint8_t  baked_out[32];
    uint32_t mismatches = 0;
    uint32_t reject_baked = 0;
    uint32_t reject_asm   = 0;
    const uint32_t SWEEP = 200;
    Serial.printf("[AxeHub] reject selftest: starting %u nonces...\n", SWEEP);
    Serial.flush();
    for (uint32_t nonce = 0; nonce < SWEEP; ++nonce) {
        ((uint32_t*)test_header)[19] = nonce;
        bool baked_hit = nerd_sha256d_baked(midstate, test_header + 64, bake, baked_out);
        bool asm_hit   = axehub_sha_sw_asm_mine(midstate, test_header + 64, asm_out);
        if (!baked_hit) ++reject_baked;
        if (!asm_hit)   ++reject_asm;
        if (baked_hit != asm_hit) {
            ++mismatches;
            Serial.printf("[AxeHub] FILTER MISMATCH nonce=%u baked=%d asm=%d\n",
                          nonce, baked_hit, asm_hit);
            if (mismatches >= 3) break;
        } else if (baked_hit && memcmp(baked_out, asm_out, 32) != 0) {
            ++mismatches;
            Serial.printf("[AxeHub] HASH MISMATCH nonce=%u\n", nonce);
            Serial.print("  baked: ");
            for (int i = 0; i < 32; ++i) Serial.printf("%02x", baked_out[i]);
            Serial.print("\n  asm:   ");
            for (int i = 0; i < 32; ++i) Serial.printf("%02x", asm_out[i]);
            Serial.println();
            if (mismatches >= 3) break;
        }
    }
    bool ok = (mismatches == 0);
    Serial.printf("[AxeHub] SHA SW-asm reject selftest: %s (rej baked=%u asm=%u, %u mismatch / %u nonces)\n",
                  ok ? "PASS" : "FAIL", reject_baked, reject_asm, mismatches, SWEEP);
    Serial.flush();
    return ok;
}

static inline uint32_t read_ccount(void) {
    uint32_t c;
    __asm__ __volatile__("rsr.ccount %0" : "=r"(c));
    return c;
}

static void axehub_bench_task(void *arg) {
    vTaskDelay(5000 / portTICK_PERIOD_MS);
    Serial.println("[AxeHub] BENCH task started");
    Serial.flush();

bench_loop:
    {

    uint8_t test_header[80] = {
        0x00, 0x00, 0x00, 0x22, 0x99, 0x44, 0xbb, 0xff, 0xbb, 0x00, 0x00, 0x77,
        0x44, 0xcc, 0x11, 0x77, 0x88, 0x55, 0xbb, 0x44, 0x55, 0x00, 0x77, 0x88,
        0x99, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0xbb, 0x66, 0x11, 0x88, 0x33, 0x44, 0x99, 0xcc, 0x33, 0xff, 0x22,
        0x11, 0xaa, 0x77, 0xee, 0xbb, 0x66, 0xee, 0xcc, 0xee, 0x66, 0xee, 0xdd,
        0x77, 0x55, 0x22, 0x22, 0xcc, 0xcc, 0x66, 0xee, 0x22, 0xdd, 0x99, 0x66,
        0x66, 0x88, 0x00, 0x11, 0x2e, 0x33, 0x41, 0x19,
    };

    uint32_t midstate[8];
    nerd_mids(midstate, test_header);
    uint32_t bake[15];
    nerd_sha256_bake(midstate, test_header + 64, bake);

    uint8_t hash[32];
    const int N = 50;            // small enough to fit in WDT margin

    uint32_t t0 = read_ccount();
    for (int i = 0; i < N; ++i) {
        ((uint32_t*)test_header)[19] = (uint32_t)i;
        nerd_sha256d_baked(midstate, test_header + 64, bake, hash);
    }
    uint32_t t1 = read_ccount();

    uint32_t t2 = read_ccount();
    for (int i = 0; i < N; ++i) {
        ((uint32_t*)test_header)[19] = (uint32_t)i;
        axehub_sha_sw_asm_double_hash(midstate, test_header + 64, hash);
    }
    uint32_t t3 = read_ccount();

    uint32_t state_b[8];
    uint32_t msg_b[16];
    for (int i = 0; i < 16; ++i) msg_b[i] = (uint32_t)i;
    msg_b[15] = 640;
    uint32_t t4 = read_ccount();
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < 8; ++j) state_b[j] = midstate[j];
        msg_b[0] = (uint32_t)i;
        axehub_sha_sw_asm_compress_block(state_b, msg_b);
    }
    uint32_t t5 = read_ccount();

    uint32_t mid_b[8];
    uint32_t t6 = read_ccount();
    for (int i = 0; i < N; ++i) {
        ((uint32_t*)test_header)[0] = (uint32_t)i;
        nerd_mids(mid_b, test_header);
    }
    uint32_t t7 = read_ccount();

    uint32_t baked_cyc  = (t1 - t0) / N;
    uint32_t asm_dbl    = (t3 - t2) / N;
    uint32_t asm_one    = (t5 - t4) / N;
    uint32_t c_one      = (t7 - t6) / N;

    Serial.printf("[AxeHub] BENCH (N=%d, core 0):\n", N);
    Serial.printf("  baked C double-hash : %5u cycles/call (%4u kH/s @240MHz)\n",
                  (unsigned)baked_cyc, (unsigned)(baked_cyc ? 240000UL/baked_cyc : 0));
    Serial.printf("  asm double_hash     : %5u cycles/call (%4u kH/s @240MHz)\n",
                  (unsigned)asm_dbl, (unsigned)(asm_dbl ? 240000UL/asm_dbl : 0));
    Serial.printf("  --- single 64-round compress (apples-to-apples) ---\n");
    Serial.printf("  C nerd_mids         : %5u cycles/call\n", (unsigned)c_one);
    Serial.printf("  asm compress_block  : %5u cycles/call\n", (unsigned)asm_one);
    if (c_one) {
        Serial.printf("  ratio asm/C         : %u.%02ux\n",
                      (unsigned)(asm_one / c_one),
                      (unsigned)(((asm_one * 100ULL) / c_one) % 100));
    }
    Serial.flush();
    }
    vTaskDelay(30000 / portTICK_PERIOD_MS);
    goto bench_loop;
}

void axehub_sha_sw_asm_start_bench(void) {
    xTaskCreatePinnedToCore(axehub_bench_task, "AxehubBench", 8192, NULL, 1, NULL, 0);
}
#endif

#pragma GCC pop_options

#endif
