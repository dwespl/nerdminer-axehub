/*
 * Xtensa LX7 scalar assembly SHA-256 block compression for ESP32-S3.
 *
 *   void axehub_sha_sw_asm_compress_block(
 *       uint32_t       state[8],    // a2 — in/out
 *       const uint32_t msg[16]);    // a3 — big-endian words (caller handles
 *                                          GET_UINT32_BE on the 64 input bytes)
 *
 * State A..H pinned in a8..a15 across all 64 rounds (no spills). W[64]
 * message schedule on stack (256 bytes). Scratch a4-a7.
 */

/* Gate: HW_ASM_PURE on S3 (where this lives alongside the HW SHA peripheral
 * fast path), or SW_ASM_PURE on classic ESP32 (where it's the ONLY asm path —
 * the HW SHA peripheral has its own driver, no asm overlap). All instructions
 * used here are base Xtensa LX ISA available on both LX6 (classic) and LX7
 * (S3); LX7-specific dual-issue scheduling is a microarchitectural perf hint,
 * not a correctness requirement, so the same code runs correctly on LX6. */
#if defined(AXEHUB_HW_ASM_PURE) || defined(AXEHUB_SW_ASM_PURE)

    .section .iram1.axehub_sha_sw_asm, "ax"
    .align 4
    .global axehub_sha_sw_asm_compress_block
    .type   axehub_sha_sw_asm_compress_block, @function

/*
 * ------------------------------------------------------------------------
 * ROTR(dst, src, n) — rotate src right by n, store in dst.
 *   ssr #n puts the shift amount into SAR. src r, Rs, Rs is a 64-bit
 *   funnel shift of {Rs,Rs} right by SAR — effectively rotate-right by n.
 * Clobbers SAR. 2 instructions.
 * ------------------------------------------------------------------------
 */
.macro ROTR dst src n
    ssr     \n
    src     \dst, \src, \src
.endm

/* SIGMA0 S2(x) = ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) */
.macro SIGMA0 dst src tmp1 tmp2
    ssai    2
    src     \tmp1, \src, \src
    ssai    13
    src     \tmp2, \src, \src
    xor     \tmp1, \tmp1, \tmp2
    ssai    22
    src     \tmp2, \src, \src
    xor     \dst,  \tmp1, \tmp2
.endm

/*
 * SIGMA1 S3(x) = ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)
 */
.macro SIGMA1 dst src tmp1 tmp2
    ssai    6
    src     \tmp1, \src, \src
    ssai    11
    src     \tmp2, \src, \src
    xor     \tmp1, \tmp1, \tmp2
    ssai    25
    src     \tmp2, \src, \src
    xor     \dst,  \tmp1, \tmp2
.endm

/*
 * sigma0 s0(x) = ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3)     — for message schedule
 * sigma1 s1(x) = ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10)
 */
.macro SMALL_SIG0 dst src tmp1 tmp2
    ssai    7
    src     \tmp1, \src, \src
    ssai    18
    src     \tmp2, \src, \src
    xor     \tmp1, \tmp1, \tmp2
    srli    \tmp2, \src, 3
    xor     \dst,  \tmp1, \tmp2
.endm

.macro SMALL_SIG1 dst src tmp1 tmp2
    ssai    17
    src     \tmp1, \src, \src
    ssai    19
    src     \tmp2, \src, \src
    xor     \tmp1, \tmp1, \tmp2
    srli    \tmp2, \src, 10
    xor     \dst,  \tmp1, \tmp2
.endm

/*
 * ------------------------------------------------------------------------
 * Ch(e, f, g) = g ^ (e & (f ^ g))       (3 ops)
 * Maj(a, b, c) = (a & b) | (c & (a | b)) (3 ops; equivalent to the standard
 *   FIPS 180-4 form `(a & b) ^ (a & c) ^ (b & c)` which needs 5 ops).
 * ------------------------------------------------------------------------
 */
.macro CH dst e f g tmp
    xor     \tmp, \f, \g
    and     \tmp, \tmp, \e
    xor     \dst, \tmp, \g
.endm

.macro MAJ dst a b c tmp1 tmp2
    and     \tmp1, \a, \b
    or      \tmp2, \a, \b
    and     \tmp2, \tmp2, \c
    or      \dst,  \tmp1, \tmp2
.endm

/*
 * ------------------------------------------------------------------------
 * SHA_ROUND(a, b, c, d, e, f, g, h, W_off, K_off) — one SHA-256 round.
 *   temp1 = h + S3(e) + Ch(e,f,g) + K[i] + W[i]
 *   temp2 = S2(a) + Maj(a,b,c)
 *   d += temp1 ; h = temp1 + temp2
 *   Uses a4=temp1, a5=temp2, a6=tmp1, a7=tmp2 as scratch.
 *   Loads W[i] from stack offset W_off, K[i] from K_ptr (a3 preserved as
 *   K-table pointer throughout the function — see prologue).
 * ------------------------------------------------------------------------
 */
.macro SHA_ROUND a b c d e f g h W_off K_off
    /* temp1 = h + S3(e) + Ch(e,f,g) + K + W
     * temp2 = S2(a) + Maj(a,b,c)
     *
     * SCHEDULE: loads W,K early (latency hide). Rebalanced add-chain:
     * instead of 4-deep (a4+=a5; a4+=a6; a4+=a7; a4+=h), pair them:
     *   (a4+a5), (a6+a7), (a4+h) — path depth 3 instead of 4.
     * LX7 can dual-issue narrow ops, so independent pairs run in parallel.
     */
    l32i    a4, sp, \W_off              /* a4 = W[i] */
    l32i    a5, a3, \K_off              /* a5 = K[i] */
    SIGMA1  a6, \e, a7, a2              /* a6 = S3(e); 8 instr ALU overlap with load */
    CH      a7, \e, \f, \g, a2          /* a7 = Ch(e,f,g); 3 instr */
    add.n   a4, a4, a5                  /* a4 = W + K */
    add.n   a6, a6, a7                  /* a6 = S3 + Ch (independent of a4) */
    add.n   a4, a4, \h                  /* a4 = W + K + h */
    add.n   a4, a4, a6                  /* a4 = temp1 */
    /* temp2 = S2(a) + Maj(a,b,c) */
    SIGMA0  a5, \a, a6, a7              /* a5 = S2(a) */
    MAJ     a6, \a, \b, \c, a7, a2      /* a6 = Maj(a,b,c) */
    add.n   a5, a5, a6                  /* a5 = temp2 */
    add.n   \d, \d, a4                  /* d += temp1 */
    add.n   \h, a4, a5                  /* h = temp1 + temp2 */
.endm

/*
 * ------------------------------------------------------------------------
 * SHA_ROUND_REJECT — round 60 with reject-check between temp1 and temp2 commit.
 * Reject (miss) → branch out of round (state untouched). Pass → finish normally.
 * ------------------------------------------------------------------------
 */
.macro SHA_ROUND_REJECT a b c d e f g h W_off K_off reject_label
    l32i    a4, sp, \W_off
    l32i    a5, a3, \K_off
    SIGMA1  a6, \e, a7, a2
    CH      a7, \e, \f, \g, a2
    add.n   a4, a4, a5
    add.n   a4, a4, a6
    add.n   a4, a4, a7
    add.n   a4, a4, \h                  /* a4 = temp1 */
    add.n   a6, \d, a4                  /* candidate new_d */
    extui   a7, a6, 0, 16
    l32r    a6, .L_magic_32E7
    bne     a7, a6, \reject_label
    SIGMA0  a5, \a, a6, a7
    MAJ     a6, \a, \b, \c, a7, a2
    add.n   a5, a5, a6
    add.n   \d, \d, a4
    add.n   \h, a4, a5
.endm

/*
 * ------------------------------------------------------------------------
 * SHA_ROUND_T1ONLY — partial round (T1 + d-update). Skip SIGMA0+MAJ + h-write.
 * On PASS path the caller restores a8..a15 from snapshot and reruns full rounds.
 * T1 save is omitted — not needed with the restore-and-rerun strategy.
 * ------------------------------------------------------------------------
 */
.macro SHA_ROUND_T1ONLY a b c d e f g h W_off K_off
    l32i    a4, sp, \W_off
    l32i    a5, a3, \K_off
    SIGMA1  a6, \e, a7, a2
    CH      a7, \e, \f, \g, a2
    add.n   a4, a4, a5                  /* a4 = W + K */
    add.n   a6, a6, a7                  /* a6 = S3 + Ch (parallel) */
    add.n   a4, a4, \h                  /* a4 = W + K + h */
    add.n   a4, a4, a6                  /* a4 = temp1 */
    add.n   \d, \d, a4
.endm

/*
 * SHA_ROUND_REJECT_T1 — round 60 partial: T1 + filter-check + d-update on PASS.
 * On REJECT: branch (state untouched). On PASS: a4=T1, a5=new A[7], d updated.
 */
.macro SHA_ROUND_REJECT_T1 d e f g h W_off K_off h_check reject_label
    l32i    a4, sp, \W_off
    l32i    a5, a3, \K_off
    SIGMA1  a6, \e, a7, a2
    CH      a7, \e, \f, \g, a2
    add.n   a4, a4, a5                  /* W + K */
    add.n   a6, a6, a7                  /* S3 + Ch (parallel) */
    add.n   a4, a4, \h                  /* W + K + h */
    add.n   a4, a4, a6                  /* a4 = temp1 */
    add.n   a5, \h_check, a4            /* a5 = candidate A[7] + T1 */
    /* [axehub fix] Tightened from low-16-bits-only check (`a5 & 0xFFFF ==
       0x32E7`) to the full 32-bit constant 0xA41F32E7. Reason: the partial
       check left bytes 30..31 of the final hash random, so pool-side diff
       was random e-10 → reject. Full constant means output[7] (=
       0x5BE0CD19 + a5) is exactly zero → diff > ~1.0 floor. Mirrors HW
       peripheral filter `text[7] != 0 → reject`. */
    l32r    a7, .L_magic_a41f32e7
    bne     a5, a7, \reject_label
    add.n   \d, \d, a4                  /* PASS: commit d += T1 */
.endm


/* -------------------------------------------------------------------------
 * axehub_sha_sw_asm_compress_block
 *   a2: state[8] (in/out)
 *   a3: msg[16]  (big-endian words, not byte-swapped here)
 *
 * Prologue:
 *   reserve stack for W[64] = 256 bytes + saved state ptr + K ptr
 *   total 272 bytes, round to multiple of 16 -> 288.
 * ------------------------------------------------------------------------- */
axehub_sha_sw_asm_compress_block:
    entry   a1, 288                     /* reserve 288B stack; windowed entry */

    /* Save state ptr and msg ptr to stack so we can reuse a2/a3 */
    s32i    a2, a1, 256                 /* save state ptr at sp+256 */
    mov     a4, a3                      /* a4 = msg ptr (temp) */

    /* Load SHA-256 K[] table pointer into a3 */
    l32r    a3, .LK_TABLE

    /* Copy msg[0..15] into W[0..15] on stack */
    l32i.n  a6, a4, 0
    s32i    a6, a1, 0
    l32i.n  a6, a4, 4
    s32i    a6, a1, 4
    l32i.n  a6, a4, 8
    s32i    a6, a1, 8
    l32i.n  a6, a4, 12
    s32i    a6, a1, 12
    l32i.n  a6, a4, 16
    s32i    a6, a1, 16
    l32i.n  a6, a4, 20
    s32i    a6, a1, 20
    l32i.n  a6, a4, 24
    s32i    a6, a1, 24
    l32i.n  a6, a4, 28
    s32i    a6, a1, 28
    l32i.n  a6, a4, 32
    s32i    a6, a1, 32
    l32i.n  a6, a4, 36
    s32i    a6, a1, 36
    l32i.n  a6, a4, 40
    s32i    a6, a1, 40
    l32i.n  a6, a4, 44
    s32i    a6, a1, 44
    l32i.n  a6, a4, 48
    s32i    a6, a1, 48
    l32i.n  a6, a4, 52
    s32i    a6, a1, 52
    l32i.n  a6, a4, 56
    s32i    a6, a1, 56
    l32i.n  a6, a4, 60
    s32i    a6, a1, 60

    /* Expand W[16..63] — fully unrolled (48 iterations).
     * For i in 16..63: W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16].
     * Eliminates loop overhead (~4 cyc/iter × 48 = 192 cyc saved).
     * Direct sp-relative addressing (l32i offset = (i-N)*4, fits in u8). */
    .set _i_, 16
    .rept 48
        l32i    a8,  a1, (_i_-2)*4
        SMALL_SIG1 a6, a8, a9, a10
        l32i    a8,  a1, (_i_-7)*4
        add.n   a6, a6, a8
        l32i    a8,  a1, (_i_-15)*4
        SMALL_SIG0 a9, a8, a10, a12
        add.n   a6, a6, a9
        l32i    a8,  a1, (_i_-16)*4
        add.n   a6, a6, a8
        s32i    a6, a1, _i_*4
        .set _i_, _i_+1
    .endr

    /* Load state[0..7] into a8-a15 (A..H), will stay there for all 64 rounds */
    l32i    a4, a1, 256                 /* state ptr */
    l32i.n  a8,  a4, 0                  /* A */
    l32i.n  a9,  a4, 4                  /* B */
    l32i.n  a10, a4, 8                  /* C */
    l32i.n  a11, a4, 12                 /* D */
    l32i.n  a12, a4, 16                 /* E */
    l32i.n  a13, a4, 20                 /* F */
    l32i.n  a14, a4, 24                 /* G */
    l32i.n  a15, a4, 28                 /* H */

    /*
     * 64 SHA-256 rounds, unrolled in groups of 8. Each group shifts the
     * role assignment by one register so no MOVs needed between rounds.
     *
     * Rounds 0..7:
     *   Round 0: a=A, b=B, c=C, d=D, e=E, f=F, g=G, h=H
     *   Round 1: a=H, b=A, c=B, d=C, e=D, f=E, g=F, h=G  (H rotates into A, etc.)
     *   ...
     *   Round 7: a=B, b=C, c=D, d=E, e=F, f=G, g=H, h=A
     *
     * After 8 rounds, the role "a" has returned to its starting register
     * assignment — so rounds 8..15 repeat the pattern with different W/K.
     */

    /* ---- Rounds 0..7 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15,  0,  0
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14,  4,  4
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13,  8,  8
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 12, 12
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 16, 16
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 20, 20
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  24, 24
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  28, 28

    /* ---- Rounds 8..15 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 32, 32
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 36, 36
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 40, 40
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 44, 44
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 48, 48
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 52, 52
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  56, 56
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  60, 60

    /* ---- Rounds 16..23 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 64, 64
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 68, 68
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 72, 72
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 76, 76
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 80, 80
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 84, 84
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  88, 88
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  92, 92

    /* ---- Rounds 24..31 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15,  96,  96
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 100, 100
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 104, 104
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 108, 108
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 112, 112
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 116, 116
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  120, 120
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  124, 124

    /* ---- Rounds 32..39 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 128, 128
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 132, 132
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 136, 136
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 140, 140
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 144, 144
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 148, 148
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  152, 152
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  156, 156

    /* ---- Rounds 40..47 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 160, 160
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 164, 164
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 168, 168
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 172, 172
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 176, 176
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 180, 180
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  184, 184
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  188, 188

    /* ---- Rounds 48..55 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 192, 192
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 196, 196
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 200, 200
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 204, 204
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 208, 208
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 212, 212
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  216, 216
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  220, 220

    /* ---- Rounds 56..63 ---- */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 224, 224
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 228, 228
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 232, 232
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 236, 236
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 240, 240
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 244, 244
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  248, 248
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  252, 252

    /* Add state[i] += A..H */
    l32i    a4, a1, 256                 /* state ptr */
    l32i.n  a5, a4, 0
    add.n   a5, a5, a8
    s32i.n  a5, a4, 0
    l32i.n  a5, a4, 4
    add.n   a5, a5, a9
    s32i.n  a5, a4, 4
    l32i.n  a5, a4, 8
    add.n   a5, a5, a10
    s32i.n  a5, a4, 8
    l32i.n  a5, a4, 12
    add.n   a5, a5, a11
    s32i.n  a5, a4, 12
    l32i.n  a5, a4, 16
    add.n   a5, a5, a12
    s32i.n  a5, a4, 16
    l32i.n  a5, a4, 20
    add.n   a5, a5, a13
    s32i.n  a5, a4, 20
    l32i.n  a5, a4, 24
    add.n   a5, a5, a14
    s32i.n  a5, a4, 24
    l32i.n  a5, a4, 28
    add.n   a5, a5, a15
    s32i.n  a5, a4, 28

    retw.n

    .size axehub_sha_sw_asm_compress_block, . - axehub_sha_sw_asm_compress_block

/* ===========================================================================
 * axehub_sha_sw_asm_compress_block2_reject — SHA-256 compression with
 * round-60 early-reject (returns 0 if rejected, 1 if completed).
 *
 *   int axehub_sha_sw_asm_compress_block2_reject(
 *       uint32_t       state[8],     // a2 — in/out (untouched on reject)
 *       const uint32_t msg[16]);     // a3 — 16 BE message words
 *
 * Identical to axehub_sha_sw_asm_compress_block except round 60 inserts the
 * (A[7] & 0xFFFF) == 0x32E7 filter check used by nerd_sha256d_baked. On
 * miss, branches out without completing rounds 60-63 or writing state.
 *
 * Caller MUST only use this for the SECOND hash of a Bitcoin double-SHA
 * (state initialised to SHA-256 IV). For the first hash use the unconditional
 * compress_block — the magic constant 0x32E7 is derived from the IV.
 * ===========================================================================
 */
    .align 4
    .global axehub_sha_sw_asm_compress_block2_reject
    .type   axehub_sha_sw_asm_compress_block2_reject, @function
axehub_sha_sw_asm_compress_block2_reject:
    entry   a1, 320                     /* 320B: W[64]+state ptr+8-word state snapshot */

    s32i    a2, a1, 256                 /* save state ptr */
    mov     a4, a3                      /* a4 = msg ptr */
    l32r    a3, .LK_TABLE

    /* Copy msg[0..15] into W[0..15] */
    l32i.n  a6, a4, 0
    s32i    a6, a1, 0
    l32i.n  a6, a4, 4
    s32i    a6, a1, 4
    l32i.n  a6, a4, 8
    s32i    a6, a1, 8
    l32i.n  a6, a4, 12
    s32i    a6, a1, 12
    l32i.n  a6, a4, 16
    s32i    a6, a1, 16
    l32i.n  a6, a4, 20
    s32i    a6, a1, 20
    l32i.n  a6, a4, 24
    s32i    a6, a1, 24
    l32i.n  a6, a4, 28
    s32i    a6, a1, 28
    l32i.n  a6, a4, 32
    s32i    a6, a1, 32
    l32i.n  a6, a4, 36
    s32i    a6, a1, 36
    l32i.n  a6, a4, 40
    s32i    a6, a1, 40
    l32i.n  a6, a4, 44
    s32i    a6, a1, 44
    l32i.n  a6, a4, 48
    s32i    a6, a1, 48
    l32i.n  a6, a4, 52
    s32i    a6, a1, 52
    l32i.n  a6, a4, 56
    s32i    a6, a1, 56
    l32i.n  a6, a4, 60
    s32i    a6, a1, 60

    /* Expand W[16..63] — fully unrolled (matches compress_block).
     * For i in 16..63: W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16]. */
    .set _i_, 16
    .rept 48
        l32i    a8,  a1, (_i_-2)*4
        SMALL_SIG1 a6, a8, a9, a10
        l32i    a8,  a1, (_i_-7)*4
        add.n   a6, a6, a8
        l32i    a8,  a1, (_i_-15)*4
        SMALL_SIG0 a9, a8, a10, a12
        add.n   a6, a6, a9
        l32i    a8,  a1, (_i_-16)*4
        add.n   a6, a6, a8
        s32i    a6, a1, _i_*4
        .set _i_, _i_+1
    .endr

    /* Load state[0..7] into a8..a15 (A..H = SHA-256 IV) */
    l32i    a4, a1, 256
    l32i.n  a8,  a4, 0
    l32i.n  a9,  a4, 4
    l32i.n  a10, a4, 8
    l32i.n  a11, a4, 12
    l32i.n  a12, a4, 16
    l32i.n  a13, a4, 20
    l32i.n  a14, a4, 24
    l32i.n  a15, a4, 28

    /* Rounds 0..59 — standard */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15,  0,  0
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14,  4,  4
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13,  8,  8
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 12, 12
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 16, 16
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 20, 20
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  24, 24
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  28, 28

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 32, 32
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 36, 36
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 40, 40
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 44, 44
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 48, 48
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 52, 52
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  56, 56
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  60, 60

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 64, 64
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 68, 68
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 72, 72
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 76, 76
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 80, 80
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 84, 84
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  88, 88
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  92, 92

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15,  96,  96
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 100, 100
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 104, 104
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 108, 108
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 112, 112
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 116, 116
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  120, 120
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  124, 124

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 128, 128
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 132, 132
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 136, 136
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 140, 140
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 144, 144
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 148, 148
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  152, 152
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  156, 156

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 160, 160
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 164, 164
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 168, 168
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 172, 172
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 176, 176
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 180, 180
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  184, 184
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  188, 188

    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 192, 192
    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 196, 196
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 200, 200
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 204, 204
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 208, 208
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 212, 212
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  216, 216
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  220, 220

    /* Round 56 — full standard */
    SHA_ROUND a8,  a9,  a10, a11, a12, a13, a14, a15, 224, 224

    /* Snapshot a8..a15 (= A[0..7] after round 56) BEFORE partial 57-60.
     * sp+264..sp+295 (32B). On PASS path: restore + rerun full rounds 57-63. */
    s32i    a8,  sp, 264
    s32i    a9,  sp, 268
    s32i    a10, sp, 272
    s32i    a11, sp, 276
    s32i    a12, sp, 280
    s32i    a13, sp, 284
    s32i    a14, sp, 288
    s32i    a15, sp, 292

    /* Partial rounds 57-59: T1 + d-update only. h-write skipped. */
    SHA_ROUND_T1ONLY a15, a8,  a9,  a10, a11, a12, a13, a14, 228, 228
    SHA_ROUND_T1ONLY a14, a15, a8,  a9,  a10, a11, a12, a13, 232, 232
    SHA_ROUND_T1ONLY a13, a14, a15, a8,  a9,  a10, a11, a12, 236, 236

    /* Round 60 partial + reject. h_check = a15 (= A[7], untouched since round 56). */
    SHA_ROUND_REJECT_T1 a15, a8, a9, a10, a11, 240, 240, a15, .Lreject_60

    /* PASS path (1/65536): restore snapshot from sp+264..sp+292 and rerun full
     * rounds 57-63. Simple and correct — no fast backfill risks divergence from baked C. */
    l32i    a8,  sp, 264
    l32i    a9,  sp, 268
    l32i    a10, sp, 272
    l32i    a11, sp, 276
    l32i    a12, sp, 280
    l32i    a13, sp, 284
    l32i    a14, sp, 288
    l32i    a15, sp, 292

    SHA_ROUND a15, a8,  a9,  a10, a11, a12, a13, a14, 228, 228   /* round 57 */
    SHA_ROUND a14, a15, a8,  a9,  a10, a11, a12, a13, 232, 232   /* round 58 */
    SHA_ROUND a13, a14, a15, a8,  a9,  a10, a11, a12, 236, 236   /* round 59 */
    SHA_ROUND a12, a13, a14, a15, a8,  a9,  a10, a11, 240, 240   /* round 60 (full, no reject) */
    SHA_ROUND a11, a12, a13, a14, a15, a8,  a9,  a10, 244, 244   /* round 61 */
    SHA_ROUND a10, a11, a12, a13, a14, a15, a8,  a9,  248, 248   /* round 62 */
    SHA_ROUND a9,  a10, a11, a12, a13, a14, a15, a8,  252, 252   /* round 63 */

    /* Add state[i] += A..H */
    l32i    a4, a1, 256
    l32i.n  a5, a4, 0
    add.n   a5, a5, a8
    s32i.n  a5, a4, 0
    l32i.n  a5, a4, 4
    add.n   a5, a5, a9
    s32i.n  a5, a4, 4
    l32i.n  a5, a4, 8
    add.n   a5, a5, a10
    s32i.n  a5, a4, 8
    l32i.n  a5, a4, 12
    add.n   a5, a5, a11
    s32i.n  a5, a4, 12
    l32i.n  a5, a4, 16
    add.n   a5, a5, a12
    s32i.n  a5, a4, 16
    l32i.n  a5, a4, 20
    add.n   a5, a5, a13
    s32i.n  a5, a4, 20
    l32i.n  a5, a4, 24
    add.n   a5, a5, a14
    s32i.n  a5, a4, 24
    l32i.n  a5, a4, 28
    add.n   a5, a5, a15
    s32i.n  a5, a4, 28

    movi    a2, 1                       /* return 1 (filter passed) */
    retw.n

.Lreject_60:
    movi    a2, 0                       /* return 0 (filter rejected — state untouched) */
    retw.n

    .size axehub_sha_sw_asm_compress_block2_reject, . - axehub_sha_sw_asm_compress_block2_reject

    /* K[] table (64 SHA-256 round constants). */
    .align 4
.LK_TABLE_DATA:
    .word 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5
    .word 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5
    .word 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3
    .word 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174
    .word 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC
    .word 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA
    .word 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7
    .word 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967
    .word 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13
    .word 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85
    .word 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3
    .word 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070
    .word 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5
    .word 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3
    .word 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208
    .word 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2

    .literal_position
    .literal .LK_TABLE,    .LK_TABLE_DATA
    .literal .L_magic_32E7, 0x000032E7
    .literal .L_magic_a41f32e7, 0xA41F32E7

#endif /* AXEHUB_HW_ASM_PURE || AXEHUB_SW_ASM_PURE */
