#ifdef AXEHUB_API_ENABLED

#include "axehub_metrics.h"
#include "axehub_webhook.h"

#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

static SemaphoreHandle_t s_mutex = nullptr;

static int      s_rssi             = 0;
static double   s_pool_diff        = 0.0;
static double   s_network_diff     = 0.0;
static double   s_session_best_diff= 0.0;
static uint32_t s_pool_send_ts     = 0;
static uint32_t s_pool_recv_ts     = 0;
static uint32_t s_pool_last_rtt_ms = 0;
static uint32_t s_reject_total     = 0;
static uint32_t s_accept_total     = 0;
static bool     s_pool_connected   = false;

static float    s_ema_1m_khs       = 0.0f;
static float    s_ema_5m_khs       = 0.0f;
static bool     s_ema_seeded       = false;

static volatile uint64_t s_hw_hashes_total = 0;
static volatile uint64_t s_sw_hashes_total = 0;
static uint64_t s_hw_hashes_prev_sample = 0;
static uint64_t s_sw_hashes_prev_sample = 0;
static uint32_t s_hw_khs_last           = 0;
static uint32_t s_sw_khs_last           = 0;
static uint32_t s_per_worker_prev_ms    = 0;

static AxehubRejectReason s_rejects[AXEHUB_REJECT_REASONS_MAX];
static size_t s_rejects_count = 0;

static inline void lock()   { if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY); }
static inline void unlock() { if (s_mutex) xSemaphoreGive(s_mutex); }

void axehub_metrics_init() {
    if (s_mutex == nullptr) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

void axehub_metrics_sample_rssi() {
    int v = WiFi.RSSI();
    lock();
    s_rssi = v;
    unlock();
}

void axehub_metrics_record_hw_hashes(uint32_t n) {
    s_hw_hashes_total += n;
}

void axehub_metrics_record_sw_hashes(uint32_t n) {
    s_sw_hashes_total += n;
}

void axehub_metrics_sample_per_worker_khs() {
    uint32_t now = millis();
    uint64_t hw  = s_hw_hashes_total;
    uint64_t sw  = s_sw_hashes_total;
    if (s_per_worker_prev_ms == 0) {
        s_hw_hashes_prev_sample = hw;
        s_sw_hashes_prev_sample = sw;
        s_per_worker_prev_ms    = now;
        return;
    }
    uint32_t dt_ms = now - s_per_worker_prev_ms;
    if (dt_ms == 0) return;
    uint64_t hw_delta = hw - s_hw_hashes_prev_sample;
    uint64_t sw_delta = sw - s_sw_hashes_prev_sample;
    lock();
    s_hw_khs_last = (uint32_t)(hw_delta / dt_ms);
    s_sw_khs_last = (uint32_t)(sw_delta / dt_ms);
    unlock();
    s_hw_hashes_prev_sample = hw;
    s_sw_hashes_prev_sample = sw;
    s_per_worker_prev_ms    = now;
}

uint32_t axehub_metrics_get_hw_khs() {
    lock();
    uint32_t v = s_hw_khs_last;
    unlock();
    return v;
}

uint32_t axehub_metrics_get_sw_khs() {
    lock();
    uint32_t v = s_sw_khs_last;
    unlock();
    return v;
}

void axehub_metrics_sample_khs(uint32_t khs) {
    const float x = static_cast<float>(khs);
    const float a1 = 1.0f / 60.0f;
    const float a5 = 1.0f / 300.0f;
    lock();
    if (!s_ema_seeded) {
        s_ema_1m_khs = x;
        s_ema_5m_khs = x;
        s_ema_seeded = true;
    } else {
        s_ema_1m_khs += a1 * (x - s_ema_1m_khs);
        s_ema_5m_khs += a5 * (x - s_ema_5m_khs);
    }
    unlock();
}

void axehub_metrics_record_session_diff(double diff) {
    lock();
    if (diff > s_session_best_diff) s_session_best_diff = diff;
    unlock();
}

void axehub_metrics_set_network_difficulty(double d) {
    lock();
    s_network_diff = d;
    unlock();
}

void axehub_metrics_record_reject(int /*code*/, const char* reason) {
    if (reason == nullptr || *reason == '\0') return;
    String r(reason);
    lock();
    s_reject_total++;
    for (size_t i = 0; i < s_rejects_count; ++i) {
        if (s_rejects[i].msg == r) {
            s_rejects[i].count++;
            unlock();
            return;
        }
    }
    if (s_rejects_count < AXEHUB_REJECT_REASONS_MAX) {
        s_rejects[s_rejects_count].msg   = r;
        s_rejects[s_rejects_count].count = 1;
        s_rejects_count++;
    } else {
        size_t victim = 0;
        for (size_t i = 1; i < AXEHUB_REJECT_REASONS_MAX; ++i) {
            if (s_rejects[i].count < s_rejects[victim].count) victim = i;
        }
        s_rejects[victim].msg   = r;
        s_rejects[victim].count = 1;
    }
    unlock();
}

void axehub_metrics_record_accept() {
    lock();
    s_accept_total++;
    unlock();
}

void axehub_metrics_set_pool_diff(double diff) {
    lock();
    s_pool_diff = diff;
    unlock();
}

void axehub_metrics_pool_send_marker() {
    uint32_t t = millis();
    lock();
    s_pool_send_ts = t;
    unlock();
}

void axehub_metrics_pool_recv_marker() {
    uint32_t t = millis();
    lock();
    s_pool_recv_ts = t;
    if (s_pool_send_ts != 0 && t >= s_pool_send_ts) {
        s_pool_last_rtt_ms = t - s_pool_send_ts;
    }
    unlock();
}

int axehub_metrics_get_rssi() {
    lock();
    int v = s_rssi;
    unlock();
    return v;
}

float axehub_metrics_get_ema_1m_khs() {
    lock();
    float v = s_ema_seeded ? s_ema_1m_khs : 0.0f;
    unlock();
    return v;
}

float axehub_metrics_get_ema_5m_khs() {
    lock();
    float v = s_ema_seeded ? s_ema_5m_khs : 0.0f;
    unlock();
    return v;
}

double axehub_metrics_get_session_best_diff() {
    lock();
    double v = s_session_best_diff;
    unlock();
    return v;
}

double axehub_metrics_get_network_difficulty() {
    lock();
    double v = s_network_diff;
    unlock();
    return v;
}

double axehub_metrics_get_pool_diff() {
    lock();
    double v = s_pool_diff;
    unlock();
    return v;
}

uint32_t axehub_metrics_get_pool_recv_age_ms() {
    lock();
    uint32_t r = (s_pool_recv_ts == 0) ? 0 : (millis() - s_pool_recv_ts);
    unlock();
    return r;
}

uint32_t axehub_metrics_get_pool_last_rtt_ms() {
    lock();
    uint32_t v = s_pool_last_rtt_ms;
    unlock();
    return v;
}

size_t axehub_metrics_get_reject_reasons(AxehubRejectReason* out, size_t max) {
    lock();
    size_t n = s_rejects_count < max ? s_rejects_count : max;
    for (size_t i = 0; i < n; ++i) out[i] = s_rejects[i];
    unlock();
    return n;
}

uint32_t axehub_metrics_get_reject_total() {
    lock();
    uint32_t v = s_reject_total;
    unlock();
    return v;
}

uint32_t axehub_metrics_get_accept_total() {
    lock();
    uint32_t v = s_accept_total;
    unlock();
    return v;
}

void axehub_metrics_set_pool_connected(bool c) {
    lock();
    bool was = s_pool_connected;
    s_pool_connected = c;
    unlock();
    if (was && !c) {
        axehub_webhook_emit("pool_disconnected", "{}");
    }
}

bool axehub_metrics_get_pool_connected() {
    lock();
    bool v = s_pool_connected;
    unlock();
    return v;
}

#endif
