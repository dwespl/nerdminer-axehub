// C-side helpers (init, K table, expansion, KW precompute, reset) for the
// pipelined HW SHA mining loop in axehub_hw_pipelined_classic_v3.S.
// Gated by AXEHUB_HW_PIPELINED_FRONT_C; default OFF.

#ifdef AXEHUB_HW_PIPELINED_FRONT_C

#include <Arduino.h>
#include <stdint.h>
#include <string.h>
#include <soc/dport_reg.h>
#include <soc/hwcrypto_reg.h>

#include "axehub_hw_pipelined_classic_v2.h"

// SHA-256 round constants. IRAM_ATTR pins to internal SRAM (referenced
// ~1.4M times/sec from the asm hot path).
extern "C" {
const uint32_t IRAM_ATTR axehub_front_c_K[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
    0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u,
    0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
    0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u,
    0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u,
    0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u,
    0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u,
    0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
    0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
};
}

// Initial SHA-256 H constants (used by C wrapper to reset SW state when
// starting a new SW double-hash chain).
static const uint32_t kFrontCH0[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

extern "C" IRAM_ATTR void axehub_front_c_init(AxehubFrontCState *st)
{
    memset(st, 0, sizeof(*st));
    for (int i = 0; i < 8; ++i) st->state[i] = kFrontCH0[i];
    st->round_idx = 0;
    st->sw_ext_nonce = 0;
    st->sw_hit_pending = 0;
}

// Precompute KW[i] = K[i] + W[i] for a SHA-256 block message. The asm hot
// path consumes one KW entry per round body inside Wait2.
extern "C" IRAM_ATTR void axehub_front_c_compute_kw(
    uint32_t *kw_dst, const uint32_t *msg_in)
{
    uint32_t W[64];
    axehub_front_c_expand_w(W, msg_in);
    for (int i = 0; i < 64; ++i) kw_dst[i] = axehub_front_c_K[i] + W[i];
}

// Reset SW state to H0 and rewind round_idx to 0. Called by C wrapper at
// SW double-hash boundary (asm exit at round_idx == 128).
extern "C" IRAM_ATTR void axehub_front_c_reset_block(AxehubFrontCState *st)
{
    for (int i = 0; i < 8; ++i) st->state[i] = kFrontCH0[i];
    st->round_idx = 0;
}

// Standard SHA-256 message-schedule expansion (16 -> 64 words).
extern "C" IRAM_ATTR void axehub_front_c_expand_w(uint32_t W[64], const uint32_t msg[16])
{
    for (int i = 0; i < 16; ++i) W[i] = msg[i];
    for (int i = 16; i < 64; ++i) {
        uint32_t a = W[i - 15];
        uint32_t b = W[i - 2];
        uint32_t s0 = ((a >> 7)  | (a << 25)) ^ ((a >> 18) | (a << 14)) ^ (a >> 3);
        uint32_t s1 = ((b >> 17) | (b << 15)) ^ ((b >> 19) | (b << 13)) ^ (b >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
}

// Reference C round body (asm path is production; this validates the asm
// produces bitwise-identical state for the same inputs).
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

extern "C" IRAM_ATTR void axehub_front_c_round_ref(
    uint32_t st[8], uint32_t k_i, uint32_t w_i)
{
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];

    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t Ch = (e & f) ^ ((~e) & g);
    uint32_t T1 = h + S1 + Ch + k_i + w_i;

    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t Mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t T2 = S0 + Mj;

    st[7] = g;
    st[6] = f;
    st[5] = e;
    st[4] = d + T1;
    st[3] = c;
    st[2] = b;
    st[1] = a;
    st[0] = T1 + T2;
}


extern "C" IRAM_ATTR void axehub_hw_pipelined_reinit_v2(void)
{
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);
}

#endif // AXEHUB_HW_PIPELINED_FRONT_C
