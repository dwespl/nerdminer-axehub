#ifndef AXEHUB_WEBHOOK_H
#define AXEHUB_WEBHOOK_H

#ifdef AXEHUB_API_ENABLED

#include <Arduino.h>

void axehub_webhook_start();

// Emit an event with a JSON-object string payload (no surrounding braces are
// added — pass `{"key":value}` as-is). Non-blocking — the call enqueues the
// event and returns. The webhook worker eventually POSTs:
//
//   { "event": "<type>", "device_mac": "...", "ts_ms": <millis>,
//     "data": <payload-as-parsed-json> }
//
// to Settings.WebhookUrl. Drops silently if the queue is full; safe to
// call before axehub_webhook_start() (no-op until queue is alive).
void axehub_webhook_emit(const char* event_type, const String& payload_json);

#else

inline void axehub_webhook_start() {}
inline void axehub_webhook_emit(const char*, const String&) {}

#endif

#endif
