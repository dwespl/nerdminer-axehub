#ifdef AXEHUB_API_ENABLED

#include "axehub_webhook.h"

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

#include "drivers/storage/storage.h"

extern TSettings Settings;

#define AXEHUB_WH_QUEUE_DEPTH    8
#define AXEHUB_WH_TYPE_MAX       32
#define AXEHUB_WH_PAYLOAD_MAX    256
#define AXEHUB_WH_HTTP_TIMEOUT   5000

struct AxehubWebhookEvent {
    char  type[AXEHUB_WH_TYPE_MAX];
    char  payload[AXEHUB_WH_PAYLOAD_MAX];
    uint32_t enqueued_ms;
};

static QueueHandle_t s_queue = nullptr;

void axehub_webhook_emit(const char* event_type, const String& payload_json) {
    if (s_queue == nullptr) return;
    AxehubWebhookEvent ev{};
    strlcpy(ev.type, event_type ? event_type : "", sizeof(ev.type));
    strlcpy(ev.payload,
            payload_json.length() > 0 ? payload_json.c_str() : "{}",
            sizeof(ev.payload));
    ev.enqueued_ms = millis();
    if (xQueueSend(s_queue, &ev, 0) != pdTRUE) {
        Serial.printf("[AxeHub] webhook queue full; dropping event '%s'\n", ev.type);
    }
}

static void postEvent(const AxehubWebhookEvent& ev) {
    if (Settings.WebhookUrl.length() == 0) return;
    if (WiFi.status() != WL_CONNECTED) return;

    DynamicJsonDocument doc(512);
    doc["event"]      = ev.type;
    doc["device_mac"] = WiFi.macAddress();
    doc["ts_ms"]      = ev.enqueued_ms;

    // Try to parse the payload back into a JSON object so it nests cleanly;
    // fall back to a raw string if it isn't valid JSON.
    DynamicJsonDocument payload(256);
    DeserializationError err = deserializeJson(payload, ev.payload);
    if (err) {
        doc["data"] = ev.payload;
    } else {
        doc["data"] = payload.as<JsonVariant>();
    }

    String body;
    serializeJson(doc, body);

    HTTPClient http;
    http.setConnectTimeout(AXEHUB_WH_HTTP_TIMEOUT);
    http.setTimeout(AXEHUB_WH_HTTP_TIMEOUT);
    if (!http.begin(Settings.WebhookUrl)) {
        Serial.printf("[AxeHub] webhook begin() failed for %s\n", Settings.WebhookUrl.c_str());
        return;
    }
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    if (code <= 0) {
        Serial.printf("[AxeHub] webhook POST failed: %s (event=%s)\n",
                      http.errorToString(code).c_str(), ev.type);
    } else if (code >= 400) {
        Serial.printf("[AxeHub] webhook %s rejected with HTTP %d\n", ev.type, code);
    } else {
        Serial.printf("[AxeHub] webhook %s -> HTTP %d\n", ev.type, code);
    }
    http.end();
}

static void axehubWebhookTask(void*) {
    AxehubWebhookEvent ev;
    while (true) {
        if (xQueueReceive(s_queue, &ev, portMAX_DELAY) == pdTRUE) {
            postEvent(ev);
        }
    }
}

void axehub_webhook_start() {
    if (s_queue != nullptr) return;
    s_queue = xQueueCreate(AXEHUB_WH_QUEUE_DEPTH, sizeof(AxehubWebhookEvent));
    if (s_queue == nullptr) {
        Serial.println("[AxeHub] webhook queue alloc failed");
        return;
    }
    xTaskCreatePinnedToCore(axehubWebhookTask, "AxehubWH", 6144, nullptr, 1, nullptr, 0);
}

#endif
