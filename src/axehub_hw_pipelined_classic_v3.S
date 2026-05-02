/*
 * Pipelined HW SHA double-hash mining loop with a SHA-256 SW round body
 * in the Wait2 slack. C wrapper + helpers in axehub_hw_pipelined_classic_v2.cpp;
 * signature in axehub_hw_pipelined_classic_v2.h.
 */

#ifdef AXEHUB_HW_PIPELINED_FRONT_C

    .section .iram1.axehub_hw_pipelined_classic_v3, "ax"
    .align 4
    .global axehub_hw_pipelined_mine_classic_frontc
    .type   axehub_hw_pipelined_mine_classic_frontc, @function

axehub_hw_pipelined_mine_classic_frontc:
    /* Windowed entry: rotate window by 8, reserve 32-byte frame. After
     * entry, args are in a2..a7. */
    entry   a1, 32

    /* Save all five pointer args we'll need later to stack scratch.
     * header_ptr (a3) goes onto the stack instead of being pinned in
     * a register — it's reloaded into a4 at the top of every inner
     * iteration during the block-1 fill phase, then a4 is freed for
     * HW scratch use after the block-2 first-3 loads. This frees a15
     * for sw-ptr pinning. */
    s32i    a3, sp, 16          /* header_swapped ptr */
    s32i    a4, sp, 0           /* nonce_swapped_inout ptr */
    s32i    a5, sp, 4           /* hash_count_low ptr */
    s32i    a6, sp, 8           /* mining_flag ptr */
    s32i    a7, sp, 12          /* sw ptr */

    /* Promote sha_base (a2) into a8 — the pinned TEXT_BASE used for all
     * fill stores. Pin sw-ptr (a7) into a15 — used for ONE direct KW[0]
     * load per round body (l32i.n a4, a15, 32), then a15 is clobbered
     * as the round body's third scratch register inside Maj. sw-ptr is
     * recovered from the stack copy at ml_end_v3 for state writeback. */
    mov.n   a8,  a2             /* a8  = sha_base (TEXT_BASE) */
    mov.n   a15, a7             /* a15 = sw_ptr */

    /* Pin sha_base + 0x90 in a5 (overrides arg-position; the saved ptr to
     * hash_count_low is in sp+4 for later reload). a5 stays pinned across
     * the full inner loop. */
    addi    a5, a8, 0x90        /* a5 = SHA_START_REG = sha_base + 0x90 */

    /* Load HW nonce_swapped into a2 from *nonce_inout. */
    l32i    a3, sp, 0           /* a3 = nonce_inout ptr (scratch) */
    l32i.n  a2, a3, 0           /* a2 = HW nonce_swapped */

    /* Load SW state[0..7] from sw->state[] into a6,a7,a9-a14, using a15
     * (= sw_ptr) directly to avoid a stack reload. */
    l32i.n  a6,  a15, 0         /* state[0] = a */
    l32i.n  a7,  a15, 4         /* state[1] = b */
    l32i.n  a9,  a15, 8         /* state[2] = c */
    l32i.n  a10, a15, 12        /* state[3] = d */
    l32i.n  a11, a15, 16        /* state[4] = e */
    l32i.n  a12, a15, 20        /* state[5] = f */
    l32i.n  a13, a15, 24        /* state[6] = g */
    l32i.n  a14, a15, 28        /* state[7] = h */

    /* Entry init: pre-fill TEXT[10..15] = header[40..63] (refreshed per iter
     * in Wait4 slack). Per-iter block-1 fill writes only TEXT[0..9].
     * TEXT[8..9] kept sequential — peripheral re-reads them in SHA-256
     * message expansion (writing them in slack causes ~9% reject). */
    l32i    a4, sp, 16          /* a4 = header_swapped ptr */
    l32i.n  a3, a4, 40          ;     s32i.n  a3, a8, 40   /* TEXT[10] */
    l32i.n  a3, a4, 44          ;     s32i.n  a3, a8, 44   /* TEXT[11] */
    l32i.n  a3, a4, 48          ;     s32i.n  a3, a8, 48   /* TEXT[12] */
    l32i.n  a3, a4, 52          ;     s32i.n  a3, a8, 52   /* TEXT[13] */
    l32i.n  a3, a4, 56          ;     s32i.n  a3, a8, 56   /* TEXT[14] */
    l32i.n  a3, a4, 60          ;     s32i.n  a3, a8, 60   /* TEXT[15] */

ml_start_v3:
    /* Reload header_swapped ptr into a4 and sw_ptr into a15 from the
     * stack scratch slots. Both loads run while the peripheral is idle
     * (block-1 hasn't started yet in this iteration), so they cannot
     * contend with the SHA peripheral for memory bus cycles — Wait2
     * stays at zero stack ops.
     *
     * Why a15 must be reloaded every iteration: the round body uses
     * a15 as the third scratch register inside Maj (final `xor a15,
     * a15, a14` writes Maj into a15), and then the state shift moves
     * `new_a` through a15 again; by the end of the round body, a15
     * holds the freshly-computed `a` state, NOT the sw_ptr. Without
     * the reload, the next iteration's `l32i.n a4, a15, 32` would
     * dereference a SHA state word as a pointer and trap with
     * LoadProhibited. (Empirically observed once: A15=0xb97e58b5,
     * EXCVADDR=A15+0x20=0xb97e58d5, EXCCAUSE=0x1c.)
     *
     * a4 (header_ptr) stays valid through block-1 fill + block-2
     * first-3 header loads, then is freed back to HW scratch at
     * ml_w1_v3. */
    l32i    a4,  sp, 16         /* a4 = header_swapped ptr */
    l32i    a15, sp, 12         /* a15 = sw_ptr (clobbered by Maj last iter) */

    /* round_idx state machine.
     * sw->round_idx (offset 544) tracks SHA-256 SW rounds done (0..128).
     * Per HW iter: read round_idx; if 128 exit (boundary handled in C);
     * otherwise advance and shift a15 by current*4 so the in-Wait2
     * `l32i.n a4, a15, 32` reads sw->KW[current]. ~7 cyc outside Wait2.
     * KW[127] at offset 32+127*4=540; l32i.n imm range 0..60 covers it. */
    l32i    a3, a15, 544        /* a3 = round_idx (current N done) */
    bnei    a3, 128, ml_skip_sw_exit
    j       ml_end_v3           /* SW boundary → exit via common save */
ml_skip_sw_exit:
    addi.n  a3, a3, 1           /* a3 = round_idx_new = current + 1 */
    s32i    a3, a15, 544        /* persist new round_idx (a15 still raw) */
    addi.n  a3, a3, -1          /* a3 = current (revert for KW shift) */
    slli    a3, a3, 2           /* a3 = current * 4 (byte offset) */
    add     a15, a15, a3        /* a15 = sw_ptr + current*4 → KW[current] base */

    /* ===== BLOCK-1 fill (10 stores TEXT[0..9] = header_swapped[0..9]).
     * TEXT[10..15] pre-written via Wait4 slack. */
    l32i.n  a3, a4, 0           ;     s32i.n  a3, a8, 0
    l32i.n  a3, a4, 4           ;     s32i.n  a3, a8, 4
    l32i.n  a3, a4, 8           ;     s32i.n  a3, a8, 8
    l32i.n  a3, a4, 12          ;     s32i.n  a3, a8, 12
    l32i.n  a3, a4, 16          ;     s32i.n  a3, a8, 16
    l32i.n  a3, a4, 20          ;     s32i.n  a3, a8, 20
    l32i.n  a3, a4, 24          ;     s32i.n  a3, a8, 24
    l32i.n  a3, a4, 28          ;     s32i.n  a3, a8, 28
    l32i.n  a3, a4, 32          ;     s32i.n  a3, a8, 32
    l32i.n  a3, a4, 36          ;     s32i.n  a3, a8, 36

    /* ===== START block-1 (write 1 to SHA_256_START_REG = a5+0) ===== */
    movi.n  a3, 1
    s32i.n  a3, a5, 0
    memw

    /* ===== BLOCK-2 fill OVERLAPPED with block-1 compute (~87 cyc) ===== */
    /* Header[16..18] → TEXT[0..2], nonce → TEXT[3], pad → TEXT[4],
     * 10× zero → TEXT[5..14], len_blk2 → TEXT[15]. Source is a4
     * (header_ptr), still valid from block-1 fill phase; freed for HW
     * scratch use after the third load below. */
    l32i    a3, a4, 64          ;     s32i.n  a3, a8, 0
    l32i    a3, a4, 68          ;     s32i.n  a3, a8, 4
    l32i    a3, a4, 72          ;     s32i.n  a3, a8, 8
    s32i.n  a2,  a8, 12         /* TEXT[3] = nonce */
    movi.n  a3, 1
    slli    a3, a3, 31          /* a3 = 0x80000000 (pad word) */
    s32i.n  a3, a8, 16          /* TEXT[4] = pad */
    movi.n  a3, 0               /* a3 = 0 const for the 10 zero stores */
    s32i.n  a3, a8, 20
    s32i.n  a3, a8, 24
    s32i.n  a3, a8, 28
    s32i.n  a3, a8, 32
    s32i.n  a3, a8, 36
    s32i.n  a3, a8, 40
    s32i.n  a3, a8, 44
    s32i.n  a3, a8, 48
    s32i.n  a3, a8, 52
    s32i.n  a3, a8, 56
    movi    a3, 0x280           /* len_blk2 = 640 (block1 + block2 input bytes) */
    s32i.n  a3, a8, 60

    /* ===== WAIT block-1 done ===== */
ml_w1_v3:
    l32i.n  a3, a5, 12          /* SHA_256_BUSY_REG = a5+12 */
    bnez.n  a3, ml_w1_v3

    /* ===== CONTINUE block-2 (write 1 to SHA_256_CONTINUE_REG = a5+4) ===== */
    movi.n  a3, 1
    s32i.n  a3, a5, 4
    memw

    /* SW SHA-256 round body — ZERO stack ops inside Wait2.
     * State: a6=a, a7=b, a9=c, a10=d, a11=e, a12=f, a13=g, a14=h.
     * Scratch: a3, a4 (HW + round body), a14 (after T1 consumes h),
     * a15 (sw_ptr on entry, then 3rd scratch for Maj; reloaded from
     * sp+12 in ml_end_v3). Only memory access here is one l32i.n
     * reading sw->KW[round_idx]. (Earlier revisions with stack ops in
     * Wait2 measured -10..-18% vs no-op variant.) */

    /* --- Σ1(e) into a3 (a4 is inner scratch) --- */
    ssai    6
    src     a3,  a11, a11       /* a3 = ROTR(e, 6) */
    ssai    11
    src     a4,  a11, a11       /* a4 = ROTR(e, 11) */
    xor     a3,  a3,  a4
    ssai    25
    src     a4,  a11, a11       /* a4 = ROTR(e, 25) */
    xor     a3,  a3,  a4        /* a3 = Σ1(e) */

    /* --- Ch(e,f,g) = g ^ (e & (f ^ g)) into a4 --- */
    xor     a4,  a12, a13       /* a4 = f ^ g */
    and     a4,  a4,  a11       /* a4 = e & (f ^ g) */
    xor     a4,  a4,  a13       /* a4 = Ch */

    /* --- T1 = h + Σ1 + Ch + KW[0]; a3 accumulates --- */
    add     a3,  a3,  a4        /* a3 = Σ1 + Ch */
    add     a3,  a3,  a14       /* a3 += h. h consumed; a14 reusable. */
    l32i.n  a4,  a15, 32        /* a4 = KW[0] = K[0]+W[0] (DIRECT, sw_ptr in a15) */
    add     a3,  a3,  a4        /* a3 = T1 */

    /* --- Σ0(a) into a4 (use a14, the freed h-slot, as inner scratch) --- */
    ssai    2
    src     a4,  a6,  a6        /* a4 = ROTR(a, 2) */
    ssai    13
    src     a14, a6,  a6        /* a14 = ROTR(a, 13) */
    xor     a4,  a4,  a14
    ssai    22
    src     a14, a6,  a6        /* a14 = ROTR(a, 22) */
    xor     a4,  a4,  a14       /* a4 = Σ0(a) */

    /* --- Maj(a,b,c) = (c & (a ^ b)) ^ (a & b) into a15 (uses a14
     *     scratch). This is the point where a15 (sw_ptr) is sacrificed
     *     for the third round-body scratch — sw_ptr is recovered from
     *     sp+12 at ml_end_v3 when the inner loop finally exits. --- */
    xor     a15, a6,  a7        /* a15 = a ^ b */
    and     a15, a15, a9        /* a15 = c & (a ^ b) */
    and     a14, a6,  a7        /* a14 = a & b */
    xor     a15, a15, a14       /* a15 = Maj */

    /* --- T2 = Σ0 + Maj into a4 --- */
    add     a4,  a4,  a15       /* a4 = T2 */

    /* --- new_e = d + T1 (into a14, the freed h-slot, awaiting state shift) ---
     * --- new_a = T1 + T2 (into a15) --- */
    add     a14, a10, a3        /* a14 = new_e */
    add     a15, a3,  a4        /* a15 = new_a */

    /* --- State shift, 9 mov.n. Order: top-half (d=c,c=b,b=a,a=new_a)
     *     then bottom-half (uses a3 as bottom-half temp since a3 (T1)
     *     is no longer live). --- */
    mov.n   a10, a9             /* d = c (old) */
    mov.n   a9,  a7             /* c = b (old) */
    mov.n   a7,  a6             /* b = a (old) */
    mov.n   a6,  a15            /* a = new_a */
    mov.n   a3,  a14            /* a3 = new_e (temp before clobbering h) */
    mov.n   a14, a13            /* h = g (old) */
    mov.n   a13, a12            /* g = f (old) */
    mov.n   a12, a11            /* f = e (old) */
    mov.n   a11, a3             /* e = new_e */

    /* ===== WAIT block-2 done ===== */
ml_w2_v3:
    l32i.n  a4, a5, 12
    bnez.n  a4, ml_w2_v3

    /* ===== LOAD1 (digest1 → TEXT[0..7]; a5+8 = LOAD_REG) ===== */
    movi.n  a4, 1
    s32i.n  a4, a5, 8
    memw

    /* OVERLAP: increment HW nonce while peripheral does LOAD1 (~22 cyc). */
    addi.n  a2, a2, 1

ml_w3_v3:
    l32i.n  a4, a5, 12
    bnez.n  a4, ml_w3_v3

    /* ===== BLOCK-3 fill (B.1 persistent zeros: only TEXT[8]=pad, TEXT[15]=len) ===== */
    movi.n  a3, 1
    slli    a3, a3, 31          /* a3 = 0x80000000 (pad) */
    s32i.n  a3, a8, 32          /* TEXT[8] = pad */
    movi    a3, 0x100           /* len_blk3 = 256 (digest1 input length) */
    s32i.n  a3, a8, 60          /* TEXT[15] = len */

    /* ===== START block-3 ===== */
    movi.n  a4, 1
    s32i.n  a4, a5, 0
    memw

    /* Bump hash counter during block-3 compute (Wait4 has bus slack;
     * moving hcnt out of this window measured -19% pool-eff). */
    l32i    a3, sp, 4           /* a3 = hash_count_low ptr */
    l32i.n  a4, a3, 0           /* a4 = current hash count */
    addi.n  a4, a4, 1
    s32i.n  a4, a3, 0

    /* Refresh TEXT[10..15] for NEXT iter's block-1 (header[40..63]).
     * 6-pair fill ~46 cyc + hash counter ~10 cyc fits ~88 cyc Wait4 budget. */
    l32i    a4, sp, 16          /* a4 = header_ptr */
    l32i.n  a3, a4, 40          ;     s32i.n  a3, a8, 40   /* TEXT[10] */
    l32i.n  a3, a4, 44          ;     s32i.n  a3, a8, 44   /* TEXT[11] */
    l32i.n  a3, a4, 48          ;     s32i.n  a3, a8, 48   /* TEXT[12] */
    l32i.n  a3, a4, 52          ;     s32i.n  a3, a8, 52   /* TEXT[13] */
    l32i.n  a3, a4, 56          ;     s32i.n  a3, a8, 56   /* TEXT[14] */
    l32i.n  a3, a4, 60          ;     s32i.n  a3, a8, 60   /* TEXT[15] */

ml_w4_v3:
    l32i.n  a4, a5, 12
    bnez.n  a4, ml_w4_v3

    /* ===== LOAD2 (final digest → TEXT[0..7]) ===== */
    movi.n  a3, 1
    s32i.n  a3, a5, 8
    memw

ml_w5_v3:
    l32i.n  a4, a5, 12
    bnez.n  a4, ml_w5_v3

    /* ===== Mining flag check ===== */
    l32i    a4, sp, 8           /* a4 = mining_flag ptr */
    l8ui    a3, a4, 0
    beqz.n  a3, ml_end_v3       /* flag dropped → exit */

    /* ===== EARLY REJECT: TEXT[7] low 16 bits == 0 means hit ===== */
    l16ui   a3, a8, 28          /* TEXT[7] low 16 bits */
    beqz.n  a3, ml_end_v3       /* candidate hit → exit (caller verifies) */

    /* MISS: continue inner loop. */
    j       ml_start_v3

ml_end_v3:
    /* Save HW nonce back to *nonce_inout. */
    l32i    a3, sp, 0           /* a3 = nonce_inout ptr */
    s32i.n  a2, a3, 0

    /* Save SW state[0..7] back to sw->state[]. */
    l32i    a3, sp, 12          /* a3 = sw ptr */
    s32i.n  a6,  a3, 0
    s32i.n  a7,  a3, 4
    s32i.n  a9,  a3, 8
    s32i.n  a10, a3, 12
    s32i.n  a11, a3, 16
    s32i.n  a12, a3, 20
    s32i.n  a13, a3, 24
    s32i.n  a14, a3, 28

    /* Return *mining_flag in a2. */
    l32i    a3, sp, 8           /* a3 = mining_flag ptr */
    l8ui    a2, a3, 0           /* a2 = *mining_flag (return value) */

    retw.n

    .size axehub_hw_pipelined_mine_classic_frontc, . - axehub_hw_pipelined_mine_classic_frontc

#endif /* AXEHUB_HW_PIPELINED_FRONT_C */
