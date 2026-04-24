/*
 * Xtensa LX7 SHA-256 mining inner loop for ESP32-S3, with HW peripheral
 * compute/setup overlap.
 *
 *   int32_t axehub_sha_asm_s3_mine_batch(
 *       const uint32_t *midstate,    // a2
 *       const uint32_t *block2,      // a3
 *       uint32_t       *nonce_io,    // a4
 *       uint32_t        nonce_end,   // a5
 *       uint8_t        *out_hash);   // a6
 *
 * Returns 1 on candidate, 0 on nonce-range exhaustion.
 */

#ifdef AXEHUB_HW_ASM_PURE

    .section .iram1.axehub_sha_asm_s3, "ax"
    .align 4
    .global axehub_sha_asm_s3_mine_batch
    .type   axehub_sha_asm_s3_mine_batch, @function

axehub_sha_asm_s3_mine_batch:
    entry   a1, 48

    l32r    a8,  .Lsha_base
    l32r    a9,  .Ltext_base
    l32r    a10, .Lh_base
    l32r    a14, .Lt15_first             /* 0x80020000 = 80-byte length LE */
    l32r    a15, .Lt15_inter             /* 0x00010000 = 32-byte length LE */
    movi.n  a7, 1                        /* persistent `1` for triggers */

    l32i.n  a11, a4, 0
    beq     a11, a5, .Lexhausted

    /* Initial setup: midstate -> H[0..7], block 2 + nonce + padding -> TEXT */
    l32i.n  a12, a2, 0
    s32i.n  a12, a10, 0
    l32i.n  a12, a2, 4
    s32i.n  a12, a10, 4
    l32i.n  a12, a2, 8
    s32i.n  a12, a10, 8
    l32i.n  a12, a2, 12
    s32i.n  a12, a10, 12
    l32i.n  a12, a2, 16
    s32i.n  a12, a10, 16
    l32i.n  a12, a2, 20
    s32i.n  a12, a10, 20
    l32i.n  a12, a2, 24
    s32i.n  a12, a10, 24
    l32i.n  a12, a2, 28
    s32i.n  a12, a10, 28

    l32i.n  a12, a3, 0
    s32i.n  a12, a9, 0
    l32i.n  a12, a3, 4
    s32i.n  a12, a9, 4
    l32i.n  a12, a3, 8
    s32i.n  a12, a9, 8
    s32i.n  a11, a9, 12                  /* nonce */
    movi.n  a12, 0x80
    s32i.n  a12, a9, 16
    movi.n  a12, 0
    s32i.n  a12, a9, 20
    s32i.n  a12, a9, 24
    s32i.n  a12, a9, 28
    s32i.n  a12, a9, 32
    s32i.n  a12, a9, 36
    s32i.n  a12, a9, 40
    s32i.n  a12, a9, 44
    s32i.n  a12, a9, 48
    s32i.n  a12, a9, 52
    s32i.n  a12, a9, 56
    s32i.n  a14, a9, 60                  /* TEXT[15] = block-2 length */

    movi.n  a12, 2
    s32i.n  a12, a8, 0                   /* SHA_MODE = SHA2_256 */
    movi.n  a12, 1
    s32i.n  a12, a8, 20                  /* SHA_CONTINUE = 1 */

.Lloop:
    /* Overlap 1: pre-write inter pad start + length while block-2 computes */
    movi.n  a12, 0x80
    s32i.n  a12, a9, 32
    s32i.n  a15, a9, 60

.Lwait1:
    l32i.n  a12, a8, 24
    bnez.n  a12, .Lwait1

    /* Phase E: H -> TEXT[0..7] (2-stage pipeline) */
    l32i.n  a12, a10, 0
    l32i.n  a13, a10, 4
    s32i.n  a12, a9, 0
    s32i.n  a13, a9, 4
    l32i.n  a12, a10, 8
    l32i.n  a13, a10, 12
    s32i.n  a12, a9, 8
    s32i.n  a13, a9, 12
    l32i.n  a12, a10, 16
    l32i.n  a13, a10, 20
    s32i.n  a12, a9, 16
    s32i.n  a13, a9, 20
    l32i.n  a12, a10, 24
    l32i.n  a13, a10, 28
    s32i.n  a12, a9, 24
    s32i.n  a13, a9, 28

    s32i.n  a7, a8, 16                   /* SHA_START (inter hash) */

    /* Overlap 2: pre-write next nonce's block-2 input while inter computes */
    addi.n  a11, a11, 1                  /* nonce++ for next iter */

    l32i.n  a12, a3, 0
    l32i.n  a13, a3, 4
    s32i.n  a12, a9, 0
    s32i.n  a13, a9, 4
    l32i.n  a12, a3, 8
    s32i.n  a12, a9, 8
    s32i.n  a11, a9, 12
    movi.n  a12, 0x80
    s32i.n  a12, a9, 16
    movi.n  a12, 0
    s32i.n  a12, a9, 20
    s32i.n  a12, a9, 24
    s32i.n  a12, a9, 28
    s32i.n  a12, a9, 32
    s32i.n  a14, a9, 60

.Lwait2:
    l32i.n  a12, a8, 24
    bnez.n  a12, .Lwait2


    /* 32-bit-share filter: high 16 bits of h[7] must be zero */
    l32i.n  a12, a10, 28
    extui   a13, a12, 16, 16
    beqz    a13, .Lcandidate

    beq     a11, a5, .Lexhausted

    /* Restore midstate to H for next block-2 compute (CONTINUE) */
    l32i.n  a12, a2, 0
    s32i.n  a12, a10, 0
    l32i.n  a12, a2, 4
    s32i.n  a12, a10, 4
    l32i.n  a12, a2, 8
    s32i.n  a12, a10, 8
    l32i.n  a12, a2, 12
    s32i.n  a12, a10, 12
    l32i.n  a12, a2, 16
    s32i.n  a12, a10, 16
    l32i.n  a12, a2, 20
    s32i.n  a12, a10, 20
    l32i.n  a12, a2, 24
    s32i.n  a12, a10, 24
    l32i.n  a12, a2, 28
    s32i.n  a12, a10, 28

    s32i.n  a7, a8, 20                   /* SHA_CONTINUE */

    j       .Lloop

.Lcandidate:
    /* Copy H[0..7] -> out_hash; back off nonce to one currently in flight */
    l32i.n  a12, a10, 0
    s32i.n  a12, a6, 0
    l32i.n  a12, a10, 4
    s32i.n  a12, a6, 4
    l32i.n  a12, a10, 8
    s32i.n  a12, a6, 8
    l32i.n  a12, a10, 12
    s32i.n  a12, a6, 12
    l32i.n  a12, a10, 16
    s32i.n  a12, a6, 16
    l32i.n  a12, a10, 20
    s32i.n  a12, a6, 20
    l32i.n  a12, a10, 24
    s32i.n  a12, a6, 24
    l32i.n  a12, a10, 28
    s32i.n  a12, a6, 28

    addi.n  a11, a11, -1
    s32i.n  a11, a4, 0
    movi.n  a2, 1
    retw.n

.Lexhausted:
    s32i.n  a11, a4, 0
    movi.n  a2, 0
    retw.n

    .literal_position
    .literal .Lsha_base,    0x6003B000
    .literal .Ltext_base,   0x6003B080
    .literal .Lh_base,      0x6003B040
    .literal .Lt15_first,   0x80020000
    .literal .Lt15_inter,   0x00010000

    .size axehub_sha_asm_s3_mine_batch, . - axehub_sha_asm_s3_mine_batch

#endif /* AXEHUB_HW_ASM_PURE */
