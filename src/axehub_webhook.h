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
// to the URL configured in Settings.WebhookUrl. If the queue is full the
// event is silently dropped (logged to Serial) so callers in hot paths
// don't block. Safe to call before axehub_webhook_start() — the call will
// simply no-op until the queue is alive.
void axehub_webhook_emit(const char* event_type, const String& payload_json);

#else

inline void axehub_webhook_start() {}
inline void axehub_webhook_emit(const char*, const String&) {}

#endif

#endif
