#ifdef AXEHUB_API_ENABLED

#include "axehub_api.h"
#include "axehub_metrics.h"
#include "axehub_webhook.h"
#include "axehub_price_history.h"

#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <AsyncJson.h>
#include <ArduinoJson.h>
#include <esp_chip_info.h>
#include <esp_system.h>

#include "version.h"
#include "mining.h"
#include "monitor.h"
#include "wManager.h"
#include "drivers/storage/storage.h"
#include "drivers/storage/nvMemory.h"
#include "drivers/displays/displayDriver.h"

#ifdef AXEHUB_HW_FAST
#include "axehub_sha_fast.h"
#endif

#define AXEHUB_COMPAT_VERSION "v1"
#define AXEHUB_COMPAT_HEADER  "X-AxeHub-Compat"
#define AXEHUB_PORT           80

// Per-build identity; override via -D AXEHUB_BOARD_NAME=\"Foo\" in platformio.ini.
#ifndef AXEHUB_BOARD_NAME
#  define AXEHUB_BOARD_NAME "NerdMiner"
#endif

// Externs from the rest of the firmware — these are the live mining/hashing
// globals that the spec expects the /info endpoint to surface.
extern uint32_t  templates;
extern uint32_t  hashes;
extern uint32_t  Mhashes;
extern uint32_t  totalKHashes;
extern uint32_t  elapsedKHs;
extern uint64_t  upTime;
extern uint32_t  shares;
extern uint32_t  valids;
extern double    best_diff;
extern TSettings Settings;

static AsyncWebServer* s_server = nullptr;

// Sleep-window state: minutes-of-day in [0, 1440). -1 = disabled.
// Allows wrap-around (start > end) for nighttime windows like 22:00-06:00.
static int s_sleep_start_min = -1;
static int s_sleep_end_min   = -1;
static bool s_sleep_in_window_last = false;

static String minutesToHhmm(int mins) {
    char buf[8];
    snprintf(buf, sizeof(buf), "%02d:%02d", mins / 60, mins % 60);
    return String(buf);
}

static bool checkCompatHeader(AsyncWebServerRequest* request) {
    if (!request->hasHeader(AXEHUB_COMPAT_HEADER)) return false;
    const AsyncWebHeader* h = request->getHeader(AXEHUB_COMPAT_HEADER);
    return h != nullptr && h->value() == "1";
}

static void send404(AsyncWebServerRequest* request) {
    request->send(404, "text/plain", "");
}

static void sendJsonStatus(AsyncWebServerRequest* request, int code, const char* status, const char* msg = nullptr) {
    StaticJsonDocument<128> doc;
    doc["status"] = status;
    if (msg && *msg) doc["msg"] = msg;
    String out;
    serializeJson(doc, out);
    request->send(code, "application/json", out);
}

static void handlePing(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) {
        send404(request);
        return;
    }
    StaticJsonDocument<192> doc;
    doc["ok"]            = true;
    doc["axehub_compat"] = AXEHUB_COMPAT_VERSION;
    doc["firmware"]      = String("NerdMiner ") + CURRENT_VERSION;

    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static const char* chipModelName() {
    esp_chip_info_t info;
    esp_chip_info(&info);
    switch (info.model) {
        case CHIP_ESP32:   return "ESP32";
        case CHIP_ESP32S2: return "ESP32-S2";
        case CHIP_ESP32S3: return "ESP32-S3";
        case CHIP_ESP32C3: return "ESP32-C3";
#ifdef CHIP_ESP32H2
        case CHIP_ESP32H2: return "ESP32-H2";
#endif
#ifdef CHIP_ESP32C6
        case CHIP_ESP32C6: return "ESP32-C6";
#endif
        default:           return "unknown";
    }
}

static String hostnameFromMac(const String& mac) {
    String suffix = mac;
    suffix.replace(":", "");
    if (suffix.length() >= 6) suffix = suffix.substring(suffix.length() - 6);
    suffix.toLowerCase();
    return String("nerdminer-") + suffix;
}

static void fillPoolEntry(JsonObject& out, const String& url, int port, const char* user, bool isActive) {
    out["url"]    = url;
    out["port"]   = port;
    out["user"]   = user;
    out["active"] = isActive;
    uint32_t rtt = axehub_metrics_get_pool_last_rtt_ms();
    if (isActive && rtt > 0) out["last_ping_ms"] = rtt; else out["last_ping_ms"] = nullptr;
    double pdiff = axehub_metrics_get_pool_diff();
    out["difficulty"] = isActive ? pdiff : 0;
}

static void handleInfo(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) {
        send404(request);
        return;
    }

    DynamicJsonDocument doc(3072);

    // ---- firmware ----
    JsonObject fw = doc.createNestedObject("firmware");
    fw["name"]          = "NerdMiner";
    fw["version"]       = CURRENT_VERSION;
    fw["axehub_compat"] = AXEHUB_COMPAT_VERSION;
    JsonArray features  = fw.createNestedArray("features");
    features.add("wifi_provision");
    features.add("solo_mining");
    features.add("block_winner_lottery");
    features.add("pool_fallback");
    fw["sw_worker_path"] = "nerd_sha256d_baked";
#ifdef AXEHUB_HW_FAST
    features.add("hw_fast");
    fw["sha_fast_selftest_ran"]    = axehub_sha_fast_get_selftest_ran();
    fw["sha_fast_selftest_passed"] = axehub_sha_fast_get_selftest_status();
    if (axehub_sha_fast_get_selftest_ran()) {
        char hex[65];
        const uint8_t* exp  = axehub_sha_fast_get_selftest_expected();
        const uint8_t* got  = axehub_sha_fast_get_selftest_got();
        const uint8_t* base = axehub_sha_fast_get_selftest_baseline();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", exp[i]);
        hex[64] = 0; fw["sha_fast_selftest_expected"] = String(hex);
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", got[i]);
        hex[64] = 0; fw["sha_fast_selftest_got"] = String(hex);
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", base[i]);
        hex[64] = 0; fw["sha_fast_selftest_baseline"] = String(hex);
    }
    fw["sha_overlap_canary_ran"]  = axehub_sha_fast_get_overlap_ran();
    fw["sha_overlap_canary_safe"] = axehub_sha_fast_get_overlap_safe();
#ifdef AXEHUB_HW_ASM
    {
        char hex[65];
        fw["sha_asm_selftest_passed"] = axehub_sha_fast_get_asm_selftest_passed();
        const uint8_t* g = axehub_sha_fast_get_asm_selftest_got();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", g[i]);
        hex[64] = 0;
        fw["sha_asm_selftest_got"] = String(hex);
    }
#endif
#ifdef AXEHUB_HW_ASM_PURE
    {
        char hex[65];
        fw["sha_pure_selftest_passed"] = axehub_sha_fast_get_pure_selftest_passed();
        const uint8_t* g = axehub_sha_fast_get_pure_selftest_got();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", g[i]);
        hex[64] = 0;
        fw["sha_pure_selftest_got"] = String(hex);

        fw["sha_sw_asm_selftest_ran"]    = axehub_sha_sw_asm_get_selftest_ran();
        fw["sha_sw_asm_selftest_passed"] = axehub_sha_sw_asm_get_selftest_passed();
        const uint8_t* s = axehub_sha_sw_asm_get_selftest_got();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", s[i]);
        hex[64] = 0;
        fw["sha_sw_asm_selftest_got"] = String(hex);

        fw["sha_sw_asm_double_ran"]    = axehub_sha_sw_asm_get_double_selftest_ran();
        fw["sha_sw_asm_double_passed"] = axehub_sha_sw_asm_get_double_selftest_passed();
        const uint8_t* d = axehub_sha_sw_asm_get_double_selftest_got();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", d[i]);
        hex[64] = 0;
        fw["sha_sw_asm_double_got"] = String(hex);
        const uint8_t* e = axehub_sha_sw_asm_get_double_selftest_expected();
        for (int i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", e[i]);
        hex[64] = 0;
        fw["sha_sw_asm_double_expected"] = String(hex);
    }
#endif
#endif
#ifdef AXEHUB_FEATURE_TFT
    features.add("tft");
#endif
#ifdef AXEHUB_FEATURE_BUZZER
    features.add("buzzer");
#endif

    // ---- device ----
    JsonObject dev = doc.createNestedObject("device");
    String mac = WiFi.macAddress();
    dev["mac"] = mac;
    const char* hn = WiFi.getHostname();
    dev["hostname"] = (hn && *hn) ? String(hn) : hostnameFromMac(mac);
    dev["board"]    = AXEHUB_BOARD_NAME;
    dev["chip"]     = chipModelName();

    // current_khs from per-worker counters (upstream elapsedKHs inflates
    // when monitor loop stalls >1s).
    JsonObject hash = doc.createNestedObject("hashing");
    uint32_t hw_khs_now = axehub_metrics_get_hw_khs();
    uint32_t sw_khs_now = axehub_metrics_get_sw_khs();
    uint32_t accept_total = axehub_metrics_get_accept_total();
    uint32_t uptime_now   = (uint32_t)upTime;
    // pool_effective_khs = accepted_shares * pool_diff * 2^32 / uptime —
    // independent of device counters. Same helper backs the LCD source.
    uint32_t pool_eff_khs = axehub_metrics_get_pool_effective_khs(uptime_now);
    hash["current_khs"]        = hw_khs_now + sw_khs_now;
    hash["average_1m_khs"]     = axehub_metrics_get_ema_1m_khs();
    hash["average_5m_khs"]     = axehub_metrics_get_ema_5m_khs();
    hash["pool_effective_khs"] = pool_eff_khs;
    hash["expected_khs"]       = nullptr;
    hash["shares_accepted"]    = accept_total;
    hash["shares_rejected"]    = axehub_metrics_get_reject_total();
    JsonArray rr = hash.createNestedArray("reject_reasons");
    {
        AxehubRejectReason rs[AXEHUB_REJECT_REASONS_MAX];
        size_t n = axehub_metrics_get_reject_reasons(rs, AXEHUB_REJECT_REASONS_MAX);
        for (size_t i = 0; i < n; ++i) {
            JsonObject e = rr.createNestedObject();
            e["msg"]   = rs[i].msg;
            e["count"] = rs[i].count;
        }
    }
    hash["best_diff"]          = best_diff;
    hash["best_session_diff"]  = axehub_metrics_get_session_best_diff();
    hash["valid_blocks"]       = valids;
    hash["hw_khs"]             = axehub_metrics_get_hw_khs();
    hash["sw_khs"]             = axehub_metrics_get_sw_khs();

    // ---- pool ----
    JsonObject pool = doc.createNestedObject("pool");
    bool connected = axehub_metrics_get_pool_connected();
    bool usingFB   = mining_is_using_fallback();

    JsonObject primary = pool.createNestedObject("primary");
    fillPoolEntry(primary, Settings.PoolAddress, Settings.PoolPort,
                  Settings.BtcWallet, connected && !usingFB);

    JsonObject fallback = pool.createNestedObject("fallback");
    fillPoolEntry(fallback, Settings.FallbackPoolAddress, Settings.FallbackPoolPort,
                  Settings.FallbackBtcWallet, connected && usingFB);

    // ---- hardware ----
    JsonObject hw = doc.createNestedObject("hardware");
    hw["temp_asic_c"]         = nullptr;
    hw["temp_board_c"]        = (float)temperatureRead();
    hw["heap_free_bytes"]     = ESP.getFreeHeap();
    hw["heap_min_free_bytes"] = ESP.getMinFreeHeap();
    hw["last_reset_reason"]   = (int)esp_reset_reason();
    hw["uptime_s"]            = (uint32_t)upTime;
    hw["wifi_rssi_dbm"]       = axehub_metrics_get_rssi();
    hw["power_consumption_w"] = nullptr;
    hw["cpu_freq_mhz"]        = ESP.getCpuFreqMHz();

    // ---- display ----
    JsonObject disp = doc.createNestedObject("display");
#ifdef AXEHUB_FEATURE_TFT
    disp["tft_present"] = true;
#else
    disp["tft_present"] = false;
#endif
    disp["current_mode"]          = nullptr;
    disp.createNestedArray("available_modes");
    disp["brightness_pct"]        = nullptr;
    disp["auto_sleep_enabled"]    = false;
    disp["auto_sleep_start_hour"] = nullptr;
    disp["auto_sleep_end_hour"]   = nullptr;
    disp["invert_colors"]         = Settings.invertColors;

    // ---- lottery ----
    JsonObject lot = doc.createNestedObject("lottery");
    double netDiff = axehub_metrics_get_network_difficulty();
    float  ema5    = axehub_metrics_get_ema_5m_khs();
    double hps     = (double)ema5 * 1000.0;
    const double TWO_POW_32 = 4294967296.0;
    if (netDiff > 0.0 && hps > 0.0) {
        double prob_per_block  = hps * 600.0 / (netDiff * TWO_POW_32);
        double prob_per_second = hps / (netDiff * TWO_POW_32);
        double sec_per_year    = 365.25 * 86400.0;
        double expected_years  = 1.0 / (prob_per_second * sec_per_year);
        lot["probability_per_block"]   = prob_per_block;
        lot["expected_years_to_block"] = expected_years;
    } else {
        lot["probability_per_block"]   = nullptr;
        lot["expected_years_to_block"] = nullptr;
    }
    lot["blocks_found"]              = valids;
    lot["closest_diff_this_session"] = axehub_metrics_get_session_best_diff();

    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static bool readString(JsonObject& o, const char* key, String& dst) {
    if (!o.containsKey(key)) return false;
    if (!o[key].is<const char*>()) return false;
    dst = o[key].as<const char*>();
    return true;
}

static bool readInt(JsonObject& o, const char* key, int& dst) {
    if (!o.containsKey(key)) return false;
    if (!o[key].is<int>()) return false;
    dst = o[key].as<int>();
    return true;
}

static void handlePoolSet(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) {
        send404(request);
        return;
    }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();

    String url;
    int    port = 0;
    String user;
    String pass;
    bool haveUrl  = readString(o, "url",  url);
    bool havePort = readInt(o, "port", port);
    bool haveUser = readString(o, "user", user);
    /*bool havePass =*/ readString(o, "pass", pass);
    if (!haveUrl || !havePort || !haveUser || url.length() == 0 || port <= 0 || user.length() == 0) {
        sendJsonStatus(request, 400, "error", "url, port and user are required");
        return;
    }

    Settings.PoolAddress = url;
    Settings.PoolPort    = port;
    strlcpy(Settings.BtcWallet, user.c_str(), sizeof(Settings.BtcWallet));
    if (pass.length() > 0) {
        strlcpy(Settings.PoolPassword, pass.c_str(), sizeof(Settings.PoolPassword));
    }

    nvMemory nv;
    nv.saveConfig(&Settings);

    mining_invalidate_pool_connection();

    sendJsonStatus(request, 200, "ok");
}

static void handlePoolSetFallback(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) {
        send404(request);
        return;
    }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();

    // Sending an empty body with just {} is interpreted as "clear fallback".
    bool hasAny = o.containsKey("url") || o.containsKey("port") ||
                  o.containsKey("user") || o.containsKey("pass");

    if (!hasAny) {
        Settings.FallbackPoolAddress = "";
        Settings.FallbackPoolPort    = 0;
        Settings.FallbackBtcWallet[0] = '\0';
        strlcpy(Settings.FallbackPoolPassword, "x", sizeof(Settings.FallbackPoolPassword));
    } else {
        String url;
        int    port = 0;
        String user;
        String pass;
        bool haveUrl  = readString(o, "url",  url);
        bool havePort = readInt(o, "port", port);
        bool haveUser = readString(o, "user", user);
        /*bool havePass =*/ readString(o, "pass", pass);
        if (!haveUrl || !havePort || !haveUser ||
            url.length() == 0 || port <= 0 || user.length() == 0) {
            sendJsonStatus(request, 400, "error",
                           "url, port and user are required (send {} with empty body to clear fallback)");
            return;
        }
        Settings.FallbackPoolAddress = url;
        Settings.FallbackPoolPort    = port;
        strlcpy(Settings.FallbackBtcWallet, user.c_str(), sizeof(Settings.FallbackBtcWallet));
        strlcpy(Settings.FallbackPoolPassword, pass.length() > 0 ? pass.c_str() : "x",
                sizeof(Settings.FallbackPoolPassword));
    }

    nvMemory nv;
    nv.saveConfig(&Settings);

    sendJsonStatus(request, 200, "ok");
}

// Run a side-effecting action (typically ESP.restart) on a separate one-shot
// task after a delay, so the HTTP response we just queued has time to flush
// before the chip reboots and tears down the socket.
struct DeferredAction {
    void (*fn)();
    uint32_t delay_ms;
};
static void deferredActionTask(void* arg) {
    auto* d = static_cast<DeferredAction*>(arg);
    vTaskDelay(d->delay_ms / portTICK_PERIOD_MS);
    d->fn();
    delete d;
    vTaskDelete(NULL);
}
static void scheduleDeferred(void (*fn)(), uint32_t delay_ms) {
    auto* d = new DeferredAction{ fn, delay_ms };
    xTaskCreate(deferredActionTask, "AxehubDefer", 2048, d, 1, nullptr);
}

static void handleWebhookSet(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();

    // Both fields are independently optional. Caller can update just the URL,
    // just the threshold, or both. Empty url disables push entirely; threshold
    // <= 0 disables share_above_diff events but still permits the others.
    if (o.containsKey("url")) {
        if (!o["url"].is<const char*>()) {
            sendJsonStatus(request, 400, "error", "url must be a string");
            return;
        }
        Settings.WebhookUrl = o["url"].as<const char*>();
    }
    if (o.containsKey("share_above_diff")) {
        if (!o["share_above_diff"].is<double>() && !o["share_above_diff"].is<int>()) {
            sendJsonStatus(request, 400, "error", "share_above_diff must be a number");
            return;
        }
        Settings.WebhookShareAboveDiffThreshold = o["share_above_diff"].as<double>();
    }

    nvMemory nv;
    nv.saveConfig(&Settings);

    sendJsonStatus(request, 200, "ok");
}

static void handleSystemRestart(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    sendJsonStatus(request, 200, "ok");
    scheduleDeferred(+[]() { ESP.restart(); }, 800);
}

extern void resetStat();   // mining.cpp — wipes uptime/Mhashes/shares/etc in NVS

static void handleSystemResetStats(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    resetStat();
    sendJsonStatus(request, 200, "ok");
    // Restart so the mining task starts clean — without restart, in-flight
    // hashes counters or periodic saveStat() can re-populate NVS with stale
    // (large) values right after the reset.
    scheduleDeferred(+[]() { ESP.restart(); }, 800);
}

static void handleWifiReset(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    sendJsonStatus(request, 200, "ok");
    scheduleDeferred(+[]() { reset_configuration(); }, 800);
}

#ifdef AXEHUB_HW_FAST
// Runtime trigger for SHA TEXT-overlap and H-write canaries (boot-time runs
// disabled on S3 due to lwIP routing regression). Acquires SHA peripheral,
// returns verdicts as JSON.
static void handleShaCanary(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    bool overlap = axehub_sha_fast_overlap_canary();
    bool hwrite  = axehub_sha_fast_hwrite_canary();
    StaticJsonDocument<128> doc;
    doc["overlap_safe"] = overlap;
    doc["hwrite_safe"]  = hwrite;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

#include <sha/sha_dma.h>     // esp_sha_acquire/release_hardware

// Inline microbench: peripheral cycles for CONTINUE+wait, wait-only, START+wait.
// Acquires SHA hardware (blocks miner briefly), runs N iters, returns
// avg/min cyc/iter as JSON.
static void handleShaMicrobench(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }

    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    volatile uint32_t * const sha_base = (uint32_t *)0x6003B000;
    volatile uint32_t * const sha_text = (uint32_t *)0x6003B080;
    volatile uint32_t * const sha_h    = (uint32_t *)0x6003B040;

    esp_sha_acquire_hardware();

    // Prime: one full block to leave H in a known midstate.
    sha_base[0] = 2;
    for (int i = 0; i < 16; ++i) sha_text[i] = 0xDEADBEEF + i;
    for (int i = 0; i < 8; ++i) sha_h[i] = 0x12345678 + i;
    sha_base[16/4] = 1;
    while (sha_base[24/4]) ;

    const uint32_t N = 500;

    uint32_t min_full = 0xFFFFFFFF, sum_full = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        uint32_t t0 = rdcc();
        sha_base[20/4] = 1;       // CONTINUE @ 0x14
        while (sha_base[24/4]) ;  // wait BUSY @ 0x18
        uint32_t dt = rdcc() - t0;
        sum_full += dt;
        if (dt < min_full) min_full = dt;
    }

    uint32_t min_wait = 0xFFFFFFFF, sum_wait = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        sha_base[20/4] = 1;
        uint32_t t0 = rdcc();
        while (sha_base[24/4]) ;
        uint32_t dt = rdcc() - t0;
        sum_wait += dt;
        if (dt < min_wait) min_wait = dt;
    }

    uint32_t min_start = 0xFFFFFFFF, sum_start = 0;
    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        uint32_t t0 = rdcc();
        sha_base[16/4] = 1;       // START @ 0x10
        while (sha_base[24/4]) ;
        uint32_t dt = rdcc() - t0;
        sum_start += dt;
        if (dt < min_start) min_start = dt;
    }

    esp_sha_release_hardware();

    StaticJsonDocument<384> doc;
    doc["cpu_freq_mhz"] = getCpuFrequencyMhz();
    JsonObject cw = doc.createNestedObject("continue_wait");
    cw["avg"] = sum_full/N;
    cw["min"] = min_full;
    JsonObject wo = doc.createNestedObject("wait_only");
    wo["avg"] = sum_wait/N;
    wo["min"] = min_wait;
    JsonObject sw = doc.createNestedObject("start_wait");
    sw["avg"] = sum_start/N;
    sw["min"] = min_start;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

// Phase microbench: replicates the production hot loop section by section,
// measuring each phase's CPU cost. Returns per-section avg cycles as JSON.
static void handleShaMicrobenchPhase(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }

    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    volatile uint32_t * const sha_base = (uint32_t *)0x6003B000;
    volatile uint32_t * const sha_text = (uint32_t *)0x6003B080;
    volatile uint32_t * const sha_h    = (uint32_t *)0x6003B040;

    esp_sha_acquire_hardware();

    sha_base[0] = 2;
    for (int i = 0; i < 8; ++i) sha_h[i] = 0x6A09E667 + i*0x11111111;
    for (int i = 0; i < 16; ++i) sha_text[i] = 0xDEADBEEF + i;
    sha_base[16/4] = 1;
    while (sha_base[24/4]) ;

    const uint32_t N = 500;
    uint64_t s_overlap1=0, s_wait1=0, s_phaseE=0, s_trig=0;
    uint64_t s_overlap2=0, s_wait2=0, s_filter=0, s_phaseA=0, s_trigC=0;

    for (uint32_t i = 0; i < N; ++i) {
        sha_text[3] = i;
        sha_base[20/4] = 1;

        uint32_t t0 = rdcc();
        sha_text[8]=0x80; sha_text[9]=0; sha_text[10]=0; sha_text[11]=0;
        sha_text[12]=0; sha_text[13]=0; sha_text[14]=0; sha_text[15]=0x10000;
        uint32_t t1 = rdcc();
        s_overlap1 += t1-t0;

        t0 = rdcc();
        while (sha_base[24/4]) ;
        t1 = rdcc();
        s_wait1 += t1-t0;

        t0 = rdcc();
        sha_text[0]=sha_h[0]; sha_text[1]=sha_h[1]; sha_text[2]=sha_h[2]; sha_text[3]=sha_h[3];
        sha_text[4]=sha_h[4]; sha_text[5]=sha_h[5]; sha_text[6]=sha_h[6]; sha_text[7]=sha_h[7];
        t1 = rdcc();
        s_phaseE += t1-t0;

        t0 = rdcc();
        __asm__ __volatile__("memw" ::: "memory");
        sha_base[0] = 2;
        sha_base[16/4] = 1;
        t1 = rdcc();
        s_trig += t1-t0;

        t0 = rdcc();
        sha_text[0]=0xAAA0; sha_text[1]=0xAAA1; sha_text[2]=0xAAA2; sha_text[3]=i;
        sha_text[4]=0x80; sha_text[5]=0; sha_text[6]=0; sha_text[7]=0;
        sha_text[8]=0; sha_text[9]=0; sha_text[10]=0; sha_text[11]=0;
        sha_text[12]=0; sha_text[13]=0; sha_text[14]=0; sha_text[15]=0x20000;
        t1 = rdcc();
        s_overlap2 += t1-t0;

        t0 = rdcc();
        while (sha_base[24/4]) ;
        t1 = rdcc();
        s_wait2 += t1-t0;

        t0 = rdcc();
        uint32_t h7 = sha_h[7];
        bool reject = ((h7 >> 16) != 0);
        (void)reject;
        t1 = rdcc();
        s_filter += t1-t0;

        t0 = rdcc();
        sha_h[0]=0x6A09E667; sha_h[1]=0xBB67AE85; sha_h[2]=0x3C6EF372; sha_h[3]=0xA54FF53A;
        sha_h[4]=0x510E527F; sha_h[5]=0x9B05688C; sha_h[6]=0x1F83D9AB; sha_h[7]=0x5BE0CD19;
        t1 = rdcc();
        s_phaseA += t1-t0;

        t0 = rdcc();
        __asm__ __volatile__("memw" ::: "memory");
        sha_base[0] = 2;
        sha_base[20/4] = 1;
        t1 = rdcc();
        s_trigC += t1-t0;

        while (sha_base[24/4]) ;
    }

    esp_sha_release_hardware();

    uint64_t total = s_overlap1+s_wait1+s_phaseE+s_trig+s_overlap2+s_wait2+s_filter+s_phaseA+s_trigC;

    StaticJsonDocument<512> doc;
    doc["cpu_freq_mhz"] = getCpuFrequencyMhz();
    doc["iters"] = N;
    doc["overlap1_8stores"] = (uint32_t)(s_overlap1/N);
    doc["wait1_block2"] = (uint32_t)(s_wait1/N);
    doc["phase_e_h_to_text"] = (uint32_t)(s_phaseE/N);
    doc["trig_inter_memw_mode_start"] = (uint32_t)(s_trig/N);
    doc["overlap2_16stores"] = (uint32_t)(s_overlap2/N);
    doc["wait2_inter"] = (uint32_t)(s_wait2/N);
    doc["filter_check"] = (uint32_t)(s_filter/N);
    doc["phase_a_midstate_to_h"] = (uint32_t)(s_phaseA/N);
    doc["trig_continue_memw_mode_continue"] = (uint32_t)(s_trigC/N);
    doc["total_per_nonce"] = (uint32_t)(total/N);
    doc["khs_implied"] = (uint32_t)(240000000ull/(total/N)/1000);
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

#endif  // AXEHUB_HW_FAST

#if defined(CONFIG_IDF_TARGET_ESP32) && defined(HARDWARE_SHA265)
extern "C" {
#include "soc/hwcrypto_reg.h"
#include "esp32/sha.h"
}

// Classic ESP32 phase microbench — replicates the production hot-loop section
// by section, mirroring axehub_hw_pipelined_classic_v3.S. Returns per-section
// avg cycles as JSON for locating where per-nonce CPU budget is spent.
static void handleShaMicrobenchPhaseClassic(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }

    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    volatile uint32_t * const text  = (volatile uint32_t *)SHA_TEXT_BASE;
    volatile uint32_t * const start = (volatile uint32_t *)SHA_256_START_REG;
    volatile uint32_t * const cont  = (volatile uint32_t *)SHA_256_CONTINUE_REG;
    volatile uint32_t * const load  = (volatile uint32_t *)SHA_256_LOAD_REG;
    volatile uint32_t * const busy  = (volatile uint32_t *)SHA_256_BUSY_REG;

    static const uint32_t test_blk1[16] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444,
        0x55555555, 0x66666666, 0x77777777, 0x88888888,
        0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC,
        0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x12345678,
    };

    esp_sha_lock_engine(SHA2_256);

    const uint32_t N = 200;
    uint64_t s_b1fill=0, s_start=0, s_w1=0, s_b2fill=0, s_cont=0, s_w2=0;
    uint64_t s_load1=0, s_w3=0, s_b3fill=0, s_b3start=0, s_w4=0;
    uint64_t s_load2=0, s_w5=0, s_filter=0;

    // Prime: one full block-1 done so peripheral isn't in pristine state.
    for (int i = 0; i < 16; ++i) text[i] = test_blk1[i];
    *start = 1;
    while (*busy) {}
    *load = 1;
    while (*busy) {}

    for (uint32_t iter = 0; iter < N; ++iter) {
        // ===== BLOCK-1 fill (16 TEXT writes) =====
        uint32_t t0 = rdcc();
        for (int i = 0; i < 16; ++i) text[i] = test_blk1[i] ^ iter;
        s_b1fill += rdcc() - t0;

        // ===== START block-1 =====
        t0 = rdcc();
        *start = 1;
        __asm__ __volatile__("memw" ::: "memory");
        s_start += rdcc() - t0;

        // ===== BLOCK-2 fill (overlapped with block-1 compute in production) =====
        t0 = rdcc();
        text[0] = 0x10101010;
        text[1] = 0x20202020;
        text[2] = 0x30303030;
        text[3] = iter;            // nonce
        text[4] = 0x80000000;      // pad
        text[5] = 0; text[6] = 0; text[7] = 0;
        text[8] = 0; text[9] = 0; text[10] = 0; text[11] = 0;
        text[12] = 0; text[13] = 0; text[14] = 0;
        text[15] = 0x280;          // length
        s_b2fill += rdcc() - t0;

        // ===== Wait1 (block-1 done) =====
        t0 = rdcc();
        while (*busy) {}
        s_w1 += rdcc() - t0;

        // ===== CONTINUE block-2 =====
        t0 = rdcc();
        *cont = 1;
        __asm__ __volatile__("memw" ::: "memory");
        s_cont += rdcc() - t0;

        // ===== Wait2 (block-2 done) =====
        t0 = rdcc();
        while (*busy) {}
        s_w2 += rdcc() - t0;

        // ===== LOAD1 =====
        t0 = rdcc();
        *load = 1;
        __asm__ __volatile__("memw" ::: "memory");
        s_load1 += rdcc() - t0;

        // ===== Wait3 (LOAD1 done) =====
        t0 = rdcc();
        while (*busy) {}
        s_w3 += rdcc() - t0;

        // ===== BLOCK-3 fill (B.1 persistent zeros: only 2 stores) =====
        t0 = rdcc();
        text[8]  = 0x80000000;     // pad
        text[15] = 0x100;          // len_blk3
        s_b3fill += rdcc() - t0;

        // ===== START block-3 =====
        t0 = rdcc();
        *start = 1;
        __asm__ __volatile__("memw" ::: "memory");
        s_b3start += rdcc() - t0;

        // ===== Wait4 (block-3 done) =====
        t0 = rdcc();
        while (*busy) {}
        s_w4 += rdcc() - t0;

        // ===== LOAD2 =====
        t0 = rdcc();
        *load = 1;
        __asm__ __volatile__("memw" ::: "memory");
        s_load2 += rdcc() - t0;

        // ===== Wait5 (LOAD2 done) =====
        t0 = rdcc();
        while (*busy) {}
        s_w5 += rdcc() - t0;

        // ===== Filter check (l16ui TEXT[7] low 16) =====
        t0 = rdcc();
        uint32_t h7 = text[7];
        bool reject = ((h7 & 0xFFFF) != 0);
        (void)reject;
        s_filter += rdcc() - t0;
    }

    esp_sha_unlock_engine(SHA2_256);

    uint64_t total = s_b1fill + s_start + s_w1 + s_b2fill + s_cont + s_w2
                   + s_load1 + s_w3 + s_b3fill + s_b3start + s_w4
                   + s_load2 + s_w5 + s_filter;

    StaticJsonDocument<768> doc;
    doc["cpu_freq_mhz"] = getCpuFrequencyMhz();
    doc["iters"] = N;
    doc["block1_fill_16stores"] = (uint32_t)(s_b1fill/N);
    doc["start_block1"] = (uint32_t)(s_start/N);
    doc["block2_fill_16stores"] = (uint32_t)(s_b2fill/N);
    doc["wait1_block1_compute"] = (uint32_t)(s_w1/N);
    doc["continue_block2"] = (uint32_t)(s_cont/N);
    doc["wait2_block2_compute"] = (uint32_t)(s_w2/N);
    doc["load1"] = (uint32_t)(s_load1/N);
    doc["wait3_load1"] = (uint32_t)(s_w3/N);
    doc["block3_fill_2stores_B1"] = (uint32_t)(s_b3fill/N);
    doc["start_block3"] = (uint32_t)(s_b3start/N);
    doc["wait4_block3_compute"] = (uint32_t)(s_w4/N);
    doc["load2"] = (uint32_t)(s_load2/N);
    doc["wait5_load2"] = (uint32_t)(s_w5/N);
    doc["filter_check"] = (uint32_t)(s_filter/N);
    doc["total_per_nonce"] = (uint32_t)(total/N);
    doc["khs_implied"] = (uint32_t)(240000000ull/(total/N)/1000);
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}
#endif  // CONFIG_IDF_TARGET_ESP32

#ifdef AXEHUB_HW_FAST
// DMA microbench: compares esp_sha_dma() per-nonce cost against the manual
// DPort path. 2-block DMA = double-SHA-256-d in one call. Returns avg/min
// cyc/iter as JSON.
static void handleShaMicrobenchDma(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }

    auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

    static uint8_t input1[64]  __attribute__((aligned(16)));
    static uint8_t input2[128] __attribute__((aligned(16)));
    for (int i = 0; i < 64;  ++i) input1[i] = (uint8_t)(0xAA + i);
    for (int i = 0; i < 128; ++i) input2[i] = (uint8_t)(0xBB + i);

    esp_sha_acquire_hardware();

    const uint32_t N = 100;

    uint32_t min_first = 0xFFFFFFFF, sum_first = 0;
    for (uint32_t i = 0; i < N; ++i) {
        input1[60] = (uint8_t)i;
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input1, 64, NULL, 0, true);
        uint32_t dt = rdcc() - t0;
        sum_first += dt;
        if (dt < min_first) min_first = dt;
    }

    uint32_t min_cont = 0xFFFFFFFF, sum_cont = 0;
    for (uint32_t i = 0; i < N; ++i) {
        input1[60] = (uint8_t)i;
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input1, 64, NULL, 0, false);
        uint32_t dt = rdcc() - t0;
        sum_cont += dt;
        if (dt < min_cont) min_cont = dt;
    }

    uint32_t min_2blk = 0xFFFFFFFF, sum_2blk = 0;
    for (uint32_t i = 0; i < N; ++i) {
        input2[60] = (uint8_t)i;
        uint32_t t0 = rdcc();
        esp_sha_dma(SHA2_256, input2, 128, NULL, 0, true);
        uint32_t dt = rdcc() - t0;
        sum_2blk += dt;
        if (dt < min_2blk) min_2blk = dt;
    }

    esp_sha_release_hardware();

    StaticJsonDocument<384> doc;
    doc["cpu_freq_mhz"] = getCpuFrequencyMhz();
    doc["manual_dport_per_nonce_baseline"] = 681;
    JsonObject f = doc.createNestedObject("dma_1block_first");
    f["avg"] = sum_first/N;
    f["min"] = min_first;
    JsonObject c = doc.createNestedObject("dma_1block_continue");
    c["avg"] = sum_cont/N;
    c["min"] = min_cont;
    JsonObject b = doc.createNestedObject("dma_2blocks");
    b["avg"] = sum_2blk/N;
    b["min"] = min_2blk;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}
#endif

static void handleDisplayGet(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    StaticJsonDocument<256> doc;
    if (currentDisplayDriver) {
        doc["mode"] = currentDisplayDriver->current_cyclic_screen;
        doc["num_modes"] = currentDisplayDriver->num_cyclic_screens;
        doc["width"] = currentDisplayDriver->screenWidth;
        doc["height"] = currentDisplayDriver->screenHeight;
    } else {
        doc["mode"] = -1;
        doc["num_modes"] = 0;
    }
    doc["brightness"] = ledcRead(0);            // current LEDC duty (0-255)
    doc["brightness_persisted"] = Settings.Brightness;
    if (s_sleep_start_min >= 0) {
        doc["sleep_start"]      = minutesToHhmm(s_sleep_start_min);
        doc["sleep_end"]        = minutesToHhmm(s_sleep_end_min);
        doc["sleep_in_window"]  = s_sleep_in_window_last;
    } else {
        doc["sleep_window"]     = "disabled";
    }
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static int parseHhmmToMinutes(const String& s) {
    int colon = s.indexOf(':');
    if (colon < 0) return -1;
    int h = s.substring(0, colon).toInt();
    int m = s.substring(colon + 1).toInt();
    if (h < 0 || h > 23 || m < 0 || m > 59) return -1;
    return h * 60 + m;
}

static bool sleepWindowActive(int start, int end, int now_min) {
    if (start < 0 || end < 0) return false;
    if (start == end) return false;
    if (start < end) return (now_min >= start && now_min < end);
    // wrap-around (e.g. 22:00 .. 06:00)
    return (now_min >= start || now_min < end);
}

// monitor.cpp exports a getTime(h, m, s) that derives from the NTPClient —
// system's time(nullptr) isn't settimeofday()'d from NTP on this firmware.
void getTime(unsigned long* h, unsigned long* m, unsigned long* s);
// monitor.cpp's mTriggerUpdate == 0 before first NTP sync succeeds.
extern unsigned long mTriggerUpdate;

static void axehubSleepWindowTask(void*) {
    while (true) {
        if (mTriggerUpdate != 0 && s_sleep_start_min >= 0) {
            unsigned long h = 0, m = 0, s = 0;
            getTime(&h, &m, &s);
            int now_min = (int)h * 60 + (int)m;
            bool in_win = sleepWindowActive(s_sleep_start_min, s_sleep_end_min, now_min);
            if (in_win != s_sleep_in_window_last) {
                if (in_win) {
                    ledcWrite(0, 0);                    // backlight off
                    Serial.printf("[AxeHub] sleep window entered at %02lu:%02lu\n", h, m);
                } else {
                    ledcWrite(0, Settings.Brightness);  // restore
                    Serial.printf("[AxeHub] sleep window exited at %02lu:%02lu\n", h, m);
                }
                s_sleep_in_window_last = in_win;
            }
        }
        vTaskDelay(5000 / portTICK_PERIOD_MS);   // 5s poll
    }
}

// ---- Buzzer (CYD has 1W speaker on GPIO26 via amplifier). Uses LEDC channel 1
// with PWM at the target audio frequency, 50% duty. For a plain buzz, any
// frequency 100-8000 Hz works; a gentle ~2 kHz is the default test tone.
#ifndef AXEHUB_BUZZER_PIN
#  define AXEHUB_BUZZER_PIN 26
#endif
#define AXEHUB_BUZZER_LEDC_CH  1

static bool s_buzzer_initialized = false;
static bool s_buzzer_attached    = false;

static void buzzerInit() {
    if (s_buzzer_initialized) return;
    ledcSetup(AXEHUB_BUZZER_LEDC_CH, 2000, 8);   // freq reconfigured per tone
    s_buzzer_initialized = true;
}

static void buzzerOff() {
    if (!s_buzzer_attached) return;
    ledcWrite(AXEHUB_BUZZER_LEDC_CH, 0);
    ledcDetachPin(AXEHUB_BUZZER_PIN);
    s_buzzer_attached = false;
}

static void buzzerTone(uint32_t freq, uint32_t duration_ms) {
    buzzerInit();
    if (freq < 30 || freq > 20000) return;
    if (duration_ms > 10000) duration_ms = 10000;   // cap 10s safety
    ledcWriteTone(AXEHUB_BUZZER_LEDC_CH, freq);
    if (!s_buzzer_attached) {
        ledcAttachPin(AXEHUB_BUZZER_PIN, AXEHUB_BUZZER_LEDC_CH);
        s_buzzer_attached = true;
    }
    ledcWrite(AXEHUB_BUZZER_LEDC_CH, 128);   // 50% duty
    vTaskDelay(duration_ms / portTICK_PERIOD_MS);
    buzzerOff();
}

// Simple 3-note confirmation beep.
static void buzzerTestMelody() {
    buzzerTone(1200, 100);
    vTaskDelay(30 / portTICK_PERIOD_MS);
    buzzerTone(1800, 100);
    vTaskDelay(30 / portTICK_PERIOD_MS);
    buzzerTone(2400, 150);
}

static void handleBuzzerTest(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    sendJsonStatus(request, 200, "ok", "playing test melody");
    // Spawn one-shot task so the async server thread isn't blocked.
    xTaskCreate([](void*){ buzzerTestMelody(); vTaskDelete(NULL); },
                "AxhBuzzT", 2048, nullptr, 1, nullptr);
}

static void handleBuzzerTone(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) { sendJsonStatus(request, 400, "error", "expected JSON object"); return; }
    JsonObject o = json.as<JsonObject>();
    if (!o.containsKey("freq") || !o.containsKey("duration_ms")) {
        sendJsonStatus(request, 400, "error", "freq and duration_ms required");
        return;
    }
    int freq = o["freq"].as<int>();
    int dur  = o["duration_ms"].as<int>();
    if (freq < 30 || freq > 20000) { sendJsonStatus(request, 400, "error", "freq out of range (30-20000)"); return; }
    if (dur  < 1  || dur  > 10000) { sendJsonStatus(request, 400, "error", "duration_ms out of range (1-10000)"); return; }

    StaticJsonDocument<96> reply;
    reply["status"] = "ok";
    reply["freq"] = freq;
    reply["duration_ms"] = dur;
    String out;
    serializeJson(reply, out);
    request->send(200, "application/json", out);

    // Spawn async task so we don't block the web server.
    struct ToneArgs { uint32_t f, d; };
    ToneArgs* args = new ToneArgs{(uint32_t)freq, (uint32_t)dur};
    xTaskCreate([](void* a){
        ToneArgs* ta = (ToneArgs*)a;
        buzzerTone(ta->f, ta->d);
        delete ta;
        vTaskDelete(NULL);
    }, "AxhBuzzN", 2048, args, 1, nullptr);
}

static void handleDisplaySleepWindow(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();

    // {} disables the window
    if (!o.containsKey("start") && !o.containsKey("end")) {
        if (s_sleep_in_window_last) ledcWrite(0, Settings.Brightness);
        s_sleep_start_min = -1;
        s_sleep_end_min   = -1;
        s_sleep_in_window_last = false;
        sendJsonStatus(request, 200, "ok", "sleep window disabled");
        return;
    }

    if (!o.containsKey("start") || !o.containsKey("end")) {
        sendJsonStatus(request, 400, "error", "both start and end required");
        return;
    }
    String startS = o["start"].as<String>();
    String endS   = o["end"].as<String>();
    int start = parseHhmmToMinutes(startS);
    int end   = parseHhmmToMinutes(endS);
    if (start < 0 || end < 0) {
        sendJsonStatus(request, 400, "error", "start/end must be HH:MM (00-23:00-59)");
        return;
    }
    if (start == end) {
        sendJsonStatus(request, 400, "error", "start and end must differ");
        return;
    }
    s_sleep_start_min = start;
    s_sleep_end_min   = end;
    s_sleep_in_window_last = false;   // re-evaluate on next poll

    StaticJsonDocument<160> doc;
    doc["status"] = "ok";
    doc["start"] = minutesToHhmm(start);
    doc["end"]   = minutesToHhmm(end);
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static void handlePoolStatsApi(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) { sendJsonStatus(request, 400, "error", "expected JSON object"); return; }
    JsonObject o = json.as<JsonObject>();
    if (!o.containsKey("url")) {
        // Clear override.
        Settings.PoolStatsApiUrl = "";
    } else {
        String url = o["url"].as<String>();
        if (url.length() > 0 && !(url.startsWith("http://") || url.startsWith("https://"))) {
            sendJsonStatus(request, 400, "error", "url must start with http:// or https://");
            return;
        }
        Settings.PoolStatsApiUrl = url;
    }
    nvMemory nv; nv.saveConfig(&Settings);
#ifdef SCREEN_WORKERS_ENABLE
    getPoolAPIUrl();
#endif
    mining_invalidate_pool_connection();

    StaticJsonDocument<160> doc;
    doc["status"] = "ok";
    doc["url"] = Settings.PoolStatsApiUrl;
    String out; serializeJson(doc, out);
    request->send(200, "application/json", out);
}

// Exposed by monitor.cpp so coin-switch can force a fresh poll instead of
// waiting up to 2 min for the stale BTC values to age out.
extern unsigned long mHeightUpdate;
extern unsigned long mBTCUpdate;
extern unsigned long mGlobalUpdate;
extern double        bitcoin_price;
extern String        current_block;

static void handleCoinSet(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) { sendJsonStatus(request, 400, "error", "expected JSON object"); return; }
    JsonObject o = json.as<JsonObject>();
    if (!o.containsKey("ticker")) {
        sendJsonStatus(request, 400, "error", "ticker required");
        return;
    }
    String ticker = o["ticker"].as<String>();
    ticker.toUpperCase();
    if (ticker != "BTC" && ticker != "BC2" && ticker != "CUSTOM") {
        sendJsonStatus(request, 400, "error", "ticker must be BTC, BC2, or custom");
        return;
    }
    Settings.CoinTicker = (ticker == "CUSTOM") ? String("custom") : ticker;

    // Optional per-URL overrides (only meaningful when ticker="custom").
    auto setIfPresent = [&](const char* key, String& dst) {
        if (o.containsKey(key)) {
            String v = o[key].as<String>();
            if (v.length() > 0 && !(v.startsWith("http://") || v.startsWith("https://"))) return false;
            dst = v;
        }
        return true;
    };
    if (!setIfPresent("height_url",     Settings.CoinHeightApiUrl) ||
        !setIfPresent("difficulty_url", Settings.CoinDifficultyApiUrl) ||
        !setIfPresent("price_url",      Settings.CoinPriceApiUrl) ||
        !setIfPresent("global_hash_url",Settings.CoinGlobalHashApiUrl)) {
        sendJsonStatus(request, 400, "error", "override URLs must start with http(s)://");
        return;
    }
    nvMemory nv; nv.saveConfig(&Settings);

    // Force fresh polls and clear stale values so display reflects the new
    // coin immediately instead of waiting for the next scheduled poll.
    mHeightUpdate    = 0;
    mBTCUpdate       = 0;
    mGlobalUpdate    = 0;
    bitcoin_price    = 0.0;
    current_block    = "0";
    gData.globalHash = "";
    gData.difficulty = "";
    axehub_price_history_reset();

    StaticJsonDocument<384> doc;
    doc["status"] = "ok";
    doc["ticker"] = Settings.CoinTicker;
    doc["height_url"]      = Settings.CoinHeightApiUrl;
    doc["difficulty_url"]  = Settings.CoinDifficultyApiUrl;
    doc["price_url"]       = Settings.CoinPriceApiUrl;
    doc["global_hash_url"] = Settings.CoinGlobalHashApiUrl;
    String out; serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static void handleCoinGet(AsyncWebServerRequest* request) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    StaticJsonDocument<384> doc;
    doc["ticker"] = Settings.CoinTicker;
    doc["height_url"]      = Settings.CoinHeightApiUrl;
    doc["difficulty_url"]  = Settings.CoinDifficultyApiUrl;
    doc["price_url"]       = Settings.CoinPriceApiUrl;
    doc["global_hash_url"] = Settings.CoinGlobalHashApiUrl;
    doc["pool_stats_url"]  = Settings.PoolStatsApiUrl;
    String out; serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static void handleDisplayBrightness(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();
    if (!o.containsKey("value")) {
        sendJsonStatus(request, 400, "error", "value required (0-255)");
        return;
    }
    int v = o["value"].as<int>();
    if (v < 0 || v > 255) {
        sendJsonStatus(request, 400, "error", "value out of range (0-255)");
        return;
    }
    // LEDC channel 0 is the TFT backlight (esp32_2432S028R driver uses
    // ledcAttachPin(TFT_BL, 0) at init). Apply immediately.
    ledcWrite(0, v);

    bool persist = false;
    if (o.containsKey("persist")) persist = o["persist"].as<bool>();
    if (persist) {
        Settings.Brightness = v;
        nvMemory nv;
        nv.saveConfig(&Settings);
    }

    StaticJsonDocument<128> doc;
    doc["status"] = "ok";
    doc["value"] = v;
    doc["persisted"] = persist;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

#ifdef AXEHUB_DISPLAY
extern void axehubCyd_ApplyInvertColors();
#endif

static void handleDisplayInvert(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();
    if (!o.containsKey("on")) {
        sendJsonStatus(request, 400, "error", "'on' boolean required");
        return;
    }
    bool on = o["on"].as<bool>();
    Settings.invertColors = on;
    nvMemory nv;
    nv.saveConfig(&Settings);
#ifdef AXEHUB_DISPLAY
    axehubCyd_ApplyInvertColors();
#endif

    StaticJsonDocument<128> doc;
    doc["status"]        = "ok";
    doc["invert_colors"] = on;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static void handleDisplayMode(AsyncWebServerRequest* request, JsonVariant& json) {
    if (!checkCompatHeader(request)) { send404(request); return; }
    if (!currentDisplayDriver) {
        sendJsonStatus(request, 503, "error", "no display driver");
        return;
    }
    if (!json.is<JsonObject>()) {
        sendJsonStatus(request, 400, "error", "expected JSON object");
        return;
    }
    JsonObject o = json.as<JsonObject>();

    const int n = currentDisplayDriver->num_cyclic_screens;
    int current = currentDisplayDriver->current_cyclic_screen;

    if (o.containsKey("mode")) {
        int m = o["mode"].as<int>();
        if (m < 0 || m >= n) {
            sendJsonStatus(request, 400, "error", "mode out of range");
            return;
        }
        currentDisplayDriver->current_cyclic_screen = m;
    } else if (o.containsKey("action")) {
        String action = o["action"].as<String>();
        if (action == "next") {
            currentDisplayDriver->current_cyclic_screen = (current + 1) % n;
        } else if (action == "prev") {
            currentDisplayDriver->current_cyclic_screen = (current - 1 + n) % n;
        } else if (action == "backlight_toggle") {
            if (currentDisplayDriver->alternateScreenState) {
                currentDisplayDriver->alternateScreenState();
            } else {
                sendJsonStatus(request, 501, "error", "backlight control not supported");
                return;
            }
        } else {
            sendJsonStatus(request, 400, "error", "unknown action");
            return;
        }
    } else {
        sendJsonStatus(request, 400, "error", "mode or action required");
        return;
    }

    StaticJsonDocument<128> doc;
    doc["status"] = "ok";
    doc["mode"] = currentDisplayDriver->current_cyclic_screen;
    String out;
    serializeJson(doc, out);
    request->send(200, "application/json", out);
}

static void axehubServerTask(void*) {
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
    // Give WiFiManager's captive portal a beat to release port 80.
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    if (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) {
        WiFi.softAPdisconnect(true);
        WiFi.mode(WIFI_STA);
        vTaskDelay(200 / portTICK_PERIOD_MS);
    }

    s_server = new AsyncWebServer(AXEHUB_PORT);
    s_server->on("/api/axehub/v1/ping", HTTP_GET, handlePing);
    s_server->on("/api/axehub/v1/info", HTTP_GET, handleInfo);

    auto* poolSetHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/pool/set", handlePoolSet);
    poolSetHandler->setMethod(HTTP_POST);
    s_server->addHandler(poolSetHandler);

    auto* poolFbHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/pool/set_fallback", handlePoolSetFallback);
    poolFbHandler->setMethod(HTTP_POST);
    s_server->addHandler(poolFbHandler);

    s_server->on("/api/axehub/v1/system/restart", HTTP_POST, handleSystemRestart);
    s_server->on("/api/axehub/v1/system/reset_stats", HTTP_POST, handleSystemResetStats);
    s_server->on("/api/axehub/v1/wifi/reset",     HTTP_POST, handleWifiReset);
#ifdef AXEHUB_HW_FAST
    s_server->on("/api/axehub/v1/sha/canary",      HTTP_POST, handleShaCanary);
    s_server->on("/api/axehub/v1/sha/bench_hw",    HTTP_POST, handleShaMicrobench);
    s_server->on("/api/axehub/v1/sha/bench_dma",   HTTP_POST, handleShaMicrobenchDma);
    s_server->on("/api/axehub/v1/sha/bench_phase", HTTP_POST, handleShaMicrobenchPhase);
#endif
#if defined(CONFIG_IDF_TARGET_ESP32) && defined(HARDWARE_SHA265)
    s_server->on("/api/axehub/v1/sha/bench_phase_classic", HTTP_POST, handleShaMicrobenchPhaseClassic);
#endif

    s_server->on("/api/axehub/v1/display", HTTP_GET, handleDisplayGet);
    auto* displayModeHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/display/mode", handleDisplayMode);
    displayModeHandler->setMethod(HTTP_POST);
    s_server->addHandler(displayModeHandler);

    auto* displayBrightnessHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/display/brightness", handleDisplayBrightness);
    displayBrightnessHandler->setMethod(HTTP_POST);
    s_server->addHandler(displayBrightnessHandler);

    auto* displayInvertHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/display/invert", handleDisplayInvert);
    displayInvertHandler->setMethod(HTTP_POST);
    s_server->addHandler(displayInvertHandler);

    auto* displaySleepHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/display/sleep_window", handleDisplaySleepWindow);
    displaySleepHandler->setMethod(HTTP_POST);
    s_server->addHandler(displaySleepHandler);

    s_server->on("/api/axehub/v1/buzzer/test", HTTP_POST, handleBuzzerTest);
    auto* buzzerToneHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/buzzer/tone", handleBuzzerTone);
    buzzerToneHandler->setMethod(HTTP_POST);
    s_server->addHandler(buzzerToneHandler);

    s_server->on("/api/axehub/v1/coin", HTTP_GET, handleCoinGet);
    auto* coinSetHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/coin", handleCoinSet);
    coinSetHandler->setMethod(HTTP_POST);
    s_server->addHandler(coinSetHandler);

    auto* poolStatsHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/pool/stats_api", handlePoolStatsApi);
    poolStatsHandler->setMethod(HTTP_POST);
    s_server->addHandler(poolStatsHandler);

    xTaskCreatePinnedToCore(axehubSleepWindowTask, "AxhSleep", 2048, nullptr, 1, nullptr, 0);

    auto* webhookSetHandler = new AsyncCallbackJsonWebHandler("/api/axehub/v1/webhook/set", handleWebhookSet);
    webhookSetHandler->setMethod(HTTP_POST);
    s_server->addHandler(webhookSetHandler);

    s_server->onNotFound(send404);
    s_server->begin();

    Serial.printf("[AxeHub] API listening on :%d (compat %s)\n",
                  AXEHUB_PORT, AXEHUB_COMPAT_VERSION);

    vTaskDelete(NULL);
}

void axehub_api_start() {
    xTaskCreatePinnedToCore(axehubServerTask, "AxehubAPI", 8192, nullptr, 4, nullptr, 1);
}

#endif
