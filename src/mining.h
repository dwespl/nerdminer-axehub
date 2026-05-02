
#ifndef MINING_API_H
#define MINING_API_H

// Mining
#define MAX_NONCE_STEP  5000000U
#define MAX_NONCE       25000000U
#define TARGET_NONCE    471136297U
// Most pools clamp suggested diff to their floor (~1); below that we get
// starved of shares.
#define DEFAULT_DIFFICULTY  1.0
// Short keepalive — some pools drop the socket after 10–15 s of silence.
#define KEEPALIVE_TIME_ms        5000
#define POOLINACTIVITY_TIME_ms  60000

//#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)
#define HARDWARE_SHA265
//#endif

#define TARGET_BUFFER_SIZE 64

void runMonitor(void *name);

void runStratumWorker(void *name);
void runMiner(void *name);

void minerWorkerSw(void * task_id);
void minerWorkerHw(void * task_id);

#if defined(CONFIG_IDF_TARGET_ESP32)
// Boot canary: TEXT-overlap safety probe (logs SAFE/UNSAFE to Serial).
void axehub_classic_overlap_canary(void);

// Empirical probe: does peripheral H register survive across block-3 START?
void axehub_classic_h_state_probe(void);
#endif

String printLocalTime(void);

void resetStat();

// Drop current pool socket and reconnect with current Settings. Safe from
// any task — flips flags; stratum loop picks up on next iteration.
void mining_invalidate_pool_connection();
bool mining_is_using_fallback();

typedef struct{
  uint8_t bytearray_target[32];
  uint8_t bytearray_pooltarget[32];
  uint8_t merkle_result[32];
  uint8_t bytearray_blockheader[128];
} miner_data;


#endif // UTILS_API_H