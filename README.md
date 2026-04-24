# NerdMiner Web Flasher

In-browser firmware flasher for NerdMiner — no esptool / PlatformIO install required.

## Requirements

- **Chrome / Edge / Opera** — Web Serial API is required (Firefox and Safari do NOT work)
- USB cable to the ESP32 (for the S3-DevKitC: use the "USB" port, not "UART")

## Local hosting

```bash
cd web-flasher
python -m http.server 8000
```

Then open: **http://localhost:8000/**

## Usage

1. Pick a board from the dropdown (S3 / CYD / CAM)
2. Click **Connect & Flash**
3. Select the ESP32's serial port from the browser dialog
4. Wait — flashing takes ~30-60s
5. Once done the chip auto-resets and boots the new firmware

## Supported boards

- ESP32-S3 DevKitC-1 N16R8 — 16MB flash, native USB CDC
- CYD 2.8" original (ESP32-2432S028R) — TFT_BL=21
- CYD 2.4"/2.8" alternative seller (ESP32-2432S024) — TFT_BL=27, ILI9341_2_DRIVER
- ESP32-CAM (no display)

## Updating firmware

After `pio run -e <env>` the file `firmware/<env>_factory.bin` is produced
by `post_build_merge.py`. Copy fresh binaries into `web-flasher/firmware/`:

```bash
LATEST=$(ls -t firmware/ | head -1)
cp firmware/$LATEST/*_factory.bin web-flasher/firmware/
```

## Public hosting

Hosted via **GitHub Pages** (Settings → Pages → Source: `main` / `/web-flasher`).
Live at:

    https://dwespl.github.io/nerdminer-axehub/

Anyone with the URL can flash their board with no local setup.

## Stack

- HTML/JS/CSS, no build step
- [esptool-js](https://github.com/espressif/esptool-js) loaded from CDN (jsdelivr +esm)
- JSON manifest enumerating supported boards
