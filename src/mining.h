
#ifndef MINING_API_H
#define MINING_API_H

// Mining
#define MAX_NONCE_STEP  5000000U
#define MAX_NONCE       25000000U
#define TARGET_NONCE    471136297U
// Pool's vardiff floor on most public/private pools is ~1. Suggesting below
// the floor (e.g. 0.00015) gets ignored and pool clamps to its own default
// (often a high value like 42), starving us of accepted shares. Suggest 1
// so vardiff has a sane baseline and can scale us further down if it wants.
#define DEFAULT_DIFFICULTY  1.0
// Some pools (e.g. ckpool with short idle-timeout) drop the socket after
// 10–15 s of silence. With low hashrate we may go hours between shares,
// so a short keepalive is the only thing keeping the session alive.
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

String printLocalTime(void);

void resetStat();

// Signals the stratum worker to drop the current pool socket and reconnect
// with whatever is currently in Settings (primary or fallback, whichever is
// active). Safe to call from any task — just flips flags, the stratum loop
// notices on its next iteration.
void mining_invalidate_pool_connection();
bool mining_is_using_fallback();

typedef struct{
  uint8_t bytearray_target[32];
  uint8_t bytearray_pooltarget[32];
  uint8_t merkle_result[32];
  uint8_t bytearray_blockheader[128];
} miner_data;


#endif // UTILS_API_H