#include "axehub_price_history.h"

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

#include "drivers/storage/storage.h"

extern TSettings Settings;

#define AXEHUB_PRICE_HIST_PERIOD_MS  (10UL * 60UL * 1000UL)

#define AXEHUB_PRICE_HIST_MAX_BYTES  (12U * 1024U)

static float       s_hist[AXEHUB_PRICE_HIST_SIZE] = {0};
static uint8_t     s_count        = 0;
static uint32_t    s_last_attempt = 0;
static bool        s_first_done   = false;
static uint16_t    s_version      = 0;
static String      s_last_ticker  = "";
static const char* s_label        = "BC2";

static WiFiClientSecure s_secure;

static const char* coingeckoIdForActiveCoin() {
    if (Settings.CoinTicker == "BTC") return "bitcoin";
    return "bitcoinii";
}

static const char* labelForActiveCoin() {
    if (Settings.CoinTicker == "BTC") return "BTC";
    return "BC2";
}

static uint16_t parsePricesArray(const String& payload, float* tmp, uint16_t tmpCap) {
    int p = payload.indexOf("\"prices\"");
    if (p < 0) return 0;
    p = payload.indexOf('[', p);
    if (p < 0) return 0;
    p++;

    uint16_t n = 0;
    int len = (int)payload.length();
    while (n < tmpCap && p < len) {
        while (p < len && (payload[p] == ',' || payload[p] == ' ' ||
                           payload[p] == '\n' || payload[p] == '\r' ||
                           payload[p] == '\t')) p++;
        if (p >= len || payload[p] == ']') break;
        if (payload[p] != '[') break;

        int innerStart = p + 1;
        int innerEnd   = payload.indexOf(']', innerStart);
        if (innerEnd < 0) break;

        int comma = payload.indexOf(',', innerStart);
        if (comma < 0 || comma > innerEnd) break;

        String priceStr = payload.substring(comma + 1, innerEnd);
        priceStr.trim();
        float v = priceStr.toFloat();
        if (v > 0.0f) tmp[n++] = v;

        p = innerEnd + 1;
    }
    return n;
}

static void downsample(const float* src, uint16_t srcN, float* dst, uint8_t dstCap) {
    if (srcN == 0 || dstCap == 0) return;
    if (srcN <= dstCap) {
        for (uint16_t i = 0; i < srcN; i++) dst[i] = src[i];
        return;
    }
    for (uint8_t i = 0; i < dstCap; i++) {
        uint32_t idx = (uint32_t)i * (srcN - 1) / (dstCap - 1);
        if (idx >= srcN) idx = srcN - 1;
        dst[i] = src[idx];
    }
}

void axehub_price_history_reset() {
    s_count        = 0;
    s_first_done   = false;
    s_last_attempt = 0;
    s_label        = labelForActiveCoin();
    s_version++;
}

void axehub_price_history_tick() {
    if (Settings.CoinTicker != s_last_ticker) {
        s_last_ticker  = Settings.CoinTicker;
        axehub_price_history_reset();
    }

    if (WiFi.status() != WL_CONNECTED) return;

    uint32_t now = millis();
    if (s_last_attempt != 0 && (now - s_last_attempt) < AXEHUB_PRICE_HIST_PERIOD_MS) return;

    if (ESP.getFreeHeap() < (AXEHUB_PRICE_HIST_MAX_BYTES + 8192)) {
        Serial.println("[PriceHist] low heap; skipping fetch");
        s_last_attempt = now;
        return;
    }

    s_last_attempt = now;

    String url = String("https://api.coingecko.com/api/v3/coins/") +
                 coingeckoIdForActiveCoin() +
                 "/market_chart?vs_currency=usd&days=1";

    s_secure.setInsecure();
    s_secure.setHandshakeTimeout(3);

    HTTPClient http;
    http.setConnectTimeout(8000);
    http.setTimeout(8000);
    Serial.printf("[PriceHist] GET %s\n", url.c_str());

    try {
        http.begin(s_secure, url);
        int httpCode = http.GET();
        Serial.printf("[PriceHist] HTTP %d\n", httpCode);

        if (httpCode == HTTP_CODE_OK) {
            int contentLen = http.getSize();
            if (contentLen > 0 && (uint32_t)contentLen > AXEHUB_PRICE_HIST_MAX_BYTES) {
                Serial.printf("[PriceHist] payload %d B exceeds cap\n", contentLen);
            } else {
                String payload = http.getString();
                Serial.printf("[PriceHist] payload len=%d\n", (int)payload.length());

                static float tmp[320];
                uint16_t srcN = parsePricesArray(payload, tmp, sizeof(tmp) / sizeof(tmp[0]));
                if (srcN >= 2) {
                    uint8_t targetN = AXEHUB_PRICE_HIST_SIZE;
                    if (srcN < targetN) targetN = (uint8_t)srcN;
                    downsample(tmp, srcN, s_hist, targetN);
                    s_count      = targetN;
                    s_first_done = true;
                    s_label      = labelForActiveCoin();
                    s_version++;
                    Serial.printf("[PriceHist] parsed %u src -> %u points (%s)\n",
                                  (unsigned)srcN, (unsigned)targetN, s_label);
                } else {
                    Serial.printf("[PriceHist] parse yielded %u points\n", (unsigned)srcN);
                }
            }
        }
        http.end();
    } catch (...) {
        Serial.println("[PriceHist] HTTP error caught");
        http.end();
    }
}

uint8_t axehub_price_history_get(float* out, uint8_t cap,
                                 float* out_min, float* out_max) {
    uint8_t n = s_count;
    if (n > cap) n = cap;
    if (n == 0) return 0;

    float lo = s_hist[0], hi = s_hist[0];
    for (uint8_t i = 0; i < n; i++) {
        float v = s_hist[i];
        out[i] = v;
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    if (n >= 2) {
        if (out_min) *out_min = lo;
        if (out_max) *out_max = hi;
    }
    return n;
}

const char* axehub_price_history_label() {
    return s_label;
}

uint16_t axehub_price_history_version() {
    return s_version;
}
