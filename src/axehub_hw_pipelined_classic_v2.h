// Front C real — public interface for the v2 pipelined HW SHA mining loop.
// Gated by AXEHUB_HW_PIPELINED_FRONT_C; default OFF.

#pragma once

#ifdef AXEHUB_HW_PIPELINED_FRONT_C

#include <stdint.h>

// SW SHA-256 chain state for the HW busy-poll round body. state + KW
// laid out for LX6 l32i.n 8-bit immediate range; KW = pre-summed K+W.
struct AxehubFrontCState {
    uint32_t state[8];               // offset   0..28  (l32i.n range)
    uint32_t KW[128];                // offset  32..540 (KW[0..7] = l32i.n; KW[8..127] = l32i + base shift)
    uint32_t round_idx;              // offset 544 — current N rounds done (0..128); asm exits when 64 or 128
    uint32_t digest1[8];             // offset 548..576 — snapshot of state + H0 at round_idx == 64 (Stage-2)
    uint32_t sw_ext_nonce;           // offset 580 — advances per completed SW double-hash
    uint32_t sw_hit_pending;         // offset 584 — set at round_idx == 128 if digest2 passes h7 == 0 gate
    uint32_t sw_hit_nonce;           // offset 588 — sw_ext_nonce at the moment of the hit
    uint8_t  sw_hit_hash[32];        // offset 592..623 — final digest2 bytes for SW share submission
    uint32_t reserved[4];            // offset 624..639
};

#ifdef __cplusplus
extern "C" {
#endif

// Init SW state (H0 + zero counters); call once per local job.
void axehub_front_c_init(struct AxehubFrontCState *st);

// Standard SHA-256 message-schedule expansion (16 -> 64 words).
void axehub_front_c_expand_w(uint32_t W[64], const uint32_t msg[16]);

// Reference C round body for self-tests against the asm path.
void axehub_front_c_round_ref(uint32_t st[8], uint32_t k_i, uint32_t w_i);

// Compute KW[i] = K[i] + W[i] over a 16-word message (W expansion inside).
void axehub_front_c_compute_kw(uint32_t *kw_dst, const uint32_t *msg_in);

// Reset SW state to H0 and rewind round_idx; called at SW double-hash boundary.
void axehub_front_c_reset_block(struct AxehubFrontCState *st);

// Pipelined HW SHA double-hash mining loop with Front C SW round overlap.
// Returns true if mining_flag still set, false on flag drop.
bool axehub_hw_pipelined_mine_classic_frontc(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_swapped_inout,
    volatile uint32_t *hash_count_low,
    volatile bool *mining_flag,
    struct AxehubFrontCState *sw);

// Re-init SHA peripheral after a candidate hit (DPORT clk_en + reset clr).
void axehub_hw_pipelined_reinit_v2(void);

#ifdef __cplusplus
}
#endif

#endif // AXEHUB_HW_PIPELINED_FRONT_C
