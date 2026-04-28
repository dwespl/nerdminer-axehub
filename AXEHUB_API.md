# AxeHub API v1

REST API exposed by the NerdMiner firmware (with `AXEHUB_API_ENABLED=1` build flag).
All endpoints live under the device's HTTP server on port **80**.

## Authentication / handshake

Every request MUST include the compat header. Requests without it return **404**.

```
X-AxeHub-Compat: 1
```

`POST` endpoints that accept a JSON body MUST set `Content-Type: application/json`.

Base URL: `http://<device-ip>/api/axehub/v1`

Standard success response shape:

```json
{"status":"ok"}
```

Standard error response shape:

```json
{"status":"error","msg":"<reason>"}
```

HTTP codes used: `200` OK, `400` bad request, `404` missing/invalid header,
`501` feature not supported, `503` feature unavailable.

---

## Endpoints

### `GET /ping`

Liveness check. Returns uptime and firmware version.

Example:
```bash
curl -H "X-AxeHub-Compat: 1" http://DEV/api/axehub/v1/ping
```

### `GET /info`

Full telemetry snapshot. Returns a large JSON with device/pool/hashrate/firmware fields.

Top-level keys:
- `firmware` — name, version, axehub_compat, features, sw_worker_path
- `device` — mac, hostname, board, chip
- `hashing` — current/average 1m/5m kH/s, hw/sw split, shares_accepted/rejected, reject_reasons, best_diff, valid_blocks
- `pool` — `primary` + `fallback` (url, port, user, active, last_ping_ms, difficulty)
- `hardware` — temp_board_c, heap_free_bytes, uptime_s, wifi_rssi_dbm, cpu_freq_mhz, last_reset_reason
- `display` — tft_present, current_mode, available_modes, brightness_pct, auto_sleep_enabled/_start_hour/_end_hour, **invert_colors**
- `lottery` — probability_per_block, expected_years_to_block, blocks_found, closest_diff_this_session

Example:
```bash
curl -H "X-AxeHub-Compat: 1" http://DEV/api/axehub/v1/info | jq
```

### `POST /pool/set`

Change primary pool. Immediately reconnects stratum.

Body:
```json
{"url":"pool.example.com","port":3333,"user":"bc1qxxx","pass":"x"}
```

All of `url`, `port`, `user` are required; `pass` optional (defaults to "x").

### `POST /pool/set_fallback`

Set or clear the fallback pool. Empty object `{}` clears it.

Body (set): same shape as `/pool/set`.
Body (clear): `{}`.

### `POST /pool/stats_api`

Override the URL used to fetch pool worker/difficulty stats for the bottom
section of the display. The wallet address is appended to the URL.

Body: `{"url":"http://lan.pool/api/client/"}` or `{}` to clear.

When cleared, the firmware auto-detects from known pools (public-pool.io,
pool.nerdminers.org, pool.sethforprivacy.com, pool.solomining.de, :2018 local).
For unknown pools it falls back to local on-device statistics.

### `POST /system/restart`

Reboots the device after ~800 ms. Returns `200 ok` before rebooting.

### `POST /wifi/reset`

Clears the WiFi credentials and reboots into the setup AP (`NerdMinerAP`).

### `POST /webhook/set`

Configure outbound webhook target for event notifications.

Body:
```json
{"url":"https://hook.example.com/nerdminer",
 "share_above_diff":0.0}
```

Events pushed: `boot`, `pool_connect`, `pool_disconnect`, `share_accepted`,
`share_above_diff` (if threshold > 0). Empty `url` disables webhooks.

### `GET /display`

Returns current display state.

```json
{
  "mode": 0,
  "num_modes": 4,
  "width": 130,
  "height": 170,
  "brightness": 128,
  "brightness_persisted": 128,
  "sleep_window": "disabled"
}
```

When a sleep window is set, `sleep_window` is replaced with:
```json
{"sleep_start":"22:00","sleep_end":"06:00","sleep_in_window":false}
```

### `POST /display/mode`

Change current cyclic display screen.

Body (absolute):
```json
{"mode": 1}
```

Body (relative):
```json
{"action": "next"}    // or "prev", "backlight_toggle"
```

Returns `{"status":"ok","mode":<new_mode>}`.

### `POST /display/brightness`

Set TFT backlight brightness (LEDC PWM on channel 0).

Body:
```json
{"value": 128, "persist": true}
```

`value`: 0–255 (immediate effect). `persist` (optional, default false) — saves
to NVS so it survives reboot.

Returns `{"status":"ok","value":128,"persisted":true}`.

### `POST /display/invert`

Toggle TFT colour inversion at runtime — fixes the white-background look
on opposite-polarity CYD 2.8/2.4 panels (some sellers/batches ship the
TFT with reversed default polarity even though the model name is the
same).

Body:
```json
{"on": true}
```

Returns `{"status":"ok","invert_colors":true}`. Persisted to NVS, applied
to the live framebuffer immediately (no reboot needed). Current state is
also exposed as `display.invert_colors` in the `GET /info` payload.

### `POST /display/sleep_window`

Turn the backlight off during a time-of-day window. Supports wrap-around
(e.g. 22:00–06:00). Uses NTP-derived time.

Body (set): `{"start":"22:00","end":"06:00"}`
Body (clear): `{}`

Time format: `"HH:MM"` (24-hour). `start == end` rejected.

The firmware polls every 5 s and transitions backlight on/off when crossing
the window boundary. `sleep_in_window` in `/display` reflects current state.

### `POST /buzzer/test`

Plays a 3-note confirmation melody on the buzzer output (CYD: GPIO26).

No body.

### `POST /buzzer/tone`

Play a single tone.

Body:
```json
{"freq": 440, "duration_ms": 300}
```

Range: `freq` 30–20000 Hz, `duration_ms` 1–10000 ms. Tone plays asynchronously
(response returns immediately).

### `GET /coin`

Current coin/chain configuration for network-data polling.

```json
{
  "ticker": "BTC",
  "height_url": "",
  "difficulty_url": "",
  "price_url": "",
  "global_hash_url": "",
  "pool_stats_url": ""
}
```

### `POST /coin`

Set the coin ticker and optional per-endpoint URL overrides.

Body:
```json
{"ticker": "BC2",
 "height_url":     "",
 "difficulty_url": "",
 "price_url":      "",
 "global_hash_url":""}
```

Supported tickers (SHA-256 only):

| ticker | defaults |
|---|---|
| `BTC`    | mempool.space + coingecko `bitcoin` |
| `BC2`    | bc2mempool.com + coingecko `bitcoinii` |
| `custom` | uses URL overrides (empty = skip that poll) |

Changing ticker forces a fresh fetch of price/height/hashrate; stale values
are cleared so the display updates on the next screen refresh.

URL overrides only apply when non-empty. They must start with `http://` or
`https://`. Setting an empty string on a `BTC`/`BC2` ticker falls back to the
preset URL for that coin.

---

## Example client (Python)

```python
import requests

BASE = "http://<device-ip>/api/axehub/v1"
H = {"X-AxeHub-Compat": "1", "Content-Type": "application/json"}

# basics
requests.get(f"{BASE}/ping", headers=H).json()
info = requests.get(f"{BASE}/info", headers=H).json()

# switch to BC2
requests.post(f"{BASE}/coin", headers=H, json={"ticker": "BC2"}).json()

# set pool
requests.post(f"{BASE}/pool/set", headers=H,
    json={"url": "pool.local", "port": 3333, "user": "bc1qxxx", "pass": "x"})

# dim display + schedule night sleep
requests.post(f"{BASE}/display/brightness", headers=H,
    json={"value": 80, "persist": True})
requests.post(f"{BASE}/display/sleep_window", headers=H,
    json={"start": "22:00", "end": "06:00"})

# fix opposite-polarity TFT panel (white background instead of dark)
requests.post(f"{BASE}/display/invert", headers=H, json={"on": True})

# play a tone
requests.post(f"{BASE}/buzzer/tone", headers=H,
    json={"freq": 1000, "duration_ms": 200})
```

---

## Example client (JavaScript)

```javascript
const BASE = "http://<device-ip>/api/axehub/v1";
const H = {"X-AxeHub-Compat": "1", "Content-Type": "application/json"};

const get  = (p)    => fetch(`${BASE}${p}`, {headers: H}).then(r => r.json());
const post = (p, b) => fetch(`${BASE}${p}`, {method:"POST", headers: H, body: JSON.stringify(b)}).then(r => r.json());

await get("/info");
await post("/coin", {ticker: "BC2"});
await post("/display/mode", {action: "next"});
```
