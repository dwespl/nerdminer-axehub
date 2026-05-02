#ifndef AXEHUB_METRICS_H
#define AXEHUB_METRICS_H

#ifdef AXEHUB_API_ENABLED

#include <Arduino.h>

#define AXEHUB_REJECT_REASONS_MAX 8

struct AxehubRejectReason {
    String   msg;
    uint32_t count;
};

void axehub_metrics_init();

void axehub_metrics_sample_rssi();
void axehub_metrics_sample_khs(uint32_t khs_this_second);        // feed 1 Hz from monitor loop
void axehub_metrics_sample_per_worker_khs();                     // 1 Hz from monitor; computes deltas
void axehub_metrics_record_hw_hashes(uint32_t n);                // miner workers bump on each batch
void axehub_metrics_record_sw_hashes(uint32_t n);
void axehub_metrics_record_reject(int code, const char* reason);
void axehub_metrics_record_accept();                             // called on every STRATUM_SUCCESS — full pool-accepted count for the API (complements the `shares` counter which tracks the 32-bit-prefix subset)
void axehub_metrics_record_session_diff(double diff);            // called when a share is accepted
void axehub_metrics_set_pool_diff(double diff);
void axehub_metrics_set_network_difficulty(double net_diff);     // from mempool.space poll
void axehub_metrics_set_pool_connected(bool connected);
void axehub_metrics_pool_send_marker();
void axehub_metrics_pool_recv_marker();

int      axehub_metrics_get_rssi();
float    axehub_metrics_get_ema_1m_khs();
float    axehub_metrics_get_ema_5m_khs();
uint32_t axehub_metrics_get_hw_khs();           // last 1-sec sample, 0 if no HW worker
uint32_t axehub_metrics_get_sw_khs();           // last 1-sec sample, 0 if no SW worker
double   axehub_metrics_get_session_best_diff();
double   axehub_metrics_get_pool_diff();
double   axehub_metrics_get_network_difficulty();
uint32_t axehub_metrics_get_pool_recv_age_ms();   // 0 if pool never seen
uint32_t axehub_metrics_get_pool_last_rtt_ms();   // 0 if no valid send/recv pair yet
size_t   axehub_metrics_get_reject_reasons(AxehubRejectReason* out, size_t max);
uint32_t axehub_metrics_get_reject_total();       // cumulative across all reasons
uint32_t axehub_metrics_get_accept_total();       // cumulative pool-accepted shares
bool     axehub_metrics_get_pool_connected();

// Pool-effective hashrate (kH/s) = accept_total * pool_diff * 2^32 / uptime_s.
// Independent of device counters. Returns 0 when uptime_s == 0 or pool_diff <= 0.
uint32_t axehub_metrics_get_pool_effective_khs(uint32_t uptime_s);

// True once >=5 accepted shares — pool_effective_khs has acceptable variance.
bool axehub_metrics_pool_effective_is_meaningful();

#else  // AXEHUB_API_ENABLED — provide no-op shims so callers don't need ifdefs.

inline void axehub_metrics_init() {}
inline void axehub_metrics_sample_rssi() {}
inline void axehub_metrics_sample_khs(uint32_t) {}
inline void axehub_metrics_sample_per_worker_khs() {}
inline void axehub_metrics_record_hw_hashes(uint32_t) {}
inline void axehub_metrics_record_sw_hashes(uint32_t) {}
inline void axehub_metrics_record_reject(int, const char*) {}
inline void axehub_metrics_record_accept() {}
inline void axehub_metrics_record_session_diff(double) {}
inline void axehub_metrics_set_pool_diff(double) {}
inline void axehub_metrics_set_network_difficulty(double) {}
inline void axehub_metrics_set_pool_connected(bool) {}
inline void axehub_metrics_pool_send_marker() {}
inline void axehub_metrics_pool_recv_marker() {}
inline uint32_t axehub_metrics_get_pool_effective_khs(uint32_t) { return 0; }
inline bool     axehub_metrics_pool_effective_is_meaningful() { return false; }

#endif

#endif
