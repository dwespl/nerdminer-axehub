// Optional asm compress-block SW worker for classic ESP32 (gated by
// AXEHUB_SW_ASM_PURE). S3 has equivalent wrappers in axehub_sha_fast.cpp.

#ifdef AXEHUB_SW_ASM_PURE

#include <Arduino.h>
#include <stdint.h>

extern "C" {
    void axehub_sha_sw_asm_compress_block(uint32_t state[8], const uint32_t msg[16]);
    int  axehub_sha_sw_asm_compress_block2_reject(uint32_t state[8], const uint32_t msg[16]);
}

#pragma GCC push_options
#pragma GCC optimize("O3")

extern "C" {

// Two-block double-SHA256 with round-60 early reject. midstate = SW state
// after first 64 header bytes; tail = bytes 64..79. Returns true on
// candidate (h7 high-16 == 0).
bool IRAM_ATTR axehub_sha_sw_asm_classic_mine(const uint32_t midstate[8],
                                              const uint8_t  tail[16],
                                              uint8_t        out_hash[32])
{
    uint32_t state[8];
    uint32_t msg[16];

    // First (continuation) compress: state := SHA(midstate || tail || padding)
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

    // Second compress: SHA(state || padding) with init H constants and
    // round-60 early reject (returns 0 if hash[7] != 0 at the partial check).
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

// Plain double-SHA, no early reject — for one-shot selftests at boot.
void IRAM_ATTR axehub_sha_sw_asm_classic_double(const uint32_t midstate[8],
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

} // extern "C"

#pragma GCC pop_options

#endif // AXEHUB_SW_ASM_PURE
