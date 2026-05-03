#include "displayDriver.h"

#ifdef AXEHUB_DISPLAY

#include <Arduino.h>
#include <WiFi.h>
#include <TFT_eSPI.h>
#include <TFT_eTouch.h>
#include "../../monitor.h"
#include "../../mining.h"
#include "../../axehub_metrics.h"
#include "../../axehub_price_history.h"
#include "../../wManager.h"
#include "../../timeconst.h"
#include "../storage/storage.h"
#include "../../media/bc2_logo.h"

extern TSettings Settings;

TFT_eSPI tft = TFT_eSPI();
SPIClass touchSPI = SPIClass(HSPI);
TFT_eTouch<TFT_eSPI> touch(tft, ETOUCH_CS, 0xFF, touchSPI);

#define COL_BG          TFT_BLACK
#define COL_CARD        TFT_BLACK
#define COL_BORDER      0x7BE8
#define COL_FG          0xFFF0
#define COL_DIM         0xC610
#define COL_HASHRATE    TFT_ORANGE
#define COL_BEST        TFT_MAGENTA
#define COL_WORKERS     TFT_GREEN
#define COL_NET         TFT_YELLOW
#define COL_HEADER      TFT_BLACK

extern DisplayDriver axehubCydDriver;

static int    s_lastScreen     = -1;
static bool   s_needFullRedraw = true;
static String s_lastCoinTicker = "";
static String s_lastPoolAddr   = "";

extern uint64_t upTime;
extern unsigned long mHeightUpdate;
extern unsigned long mBTCUpdate;
extern unsigned long mGlobalUpdate;

extern void   getTime(unsigned long* h, unsigned long* m, unsigned long* s);
extern String getDate();
extern String getBTCprice(void);

struct {
    String hashrate, timeMining;
    String pool_best, pool_workers, pool_hash;
    String local_best, local_shares, local_mhashes;
    String wifi;
} mC;
struct {
    String price, time, date, blockNo, halving, retarget, netHash, netDiff;
} nC;
struct {
    String   clock, date, coinHeader, priceLine, deltaLine, rangeMax, rangeMin;
    uint16_t chartVer;
} tC;

static String formatUptime() {
    uint64_t t = upTime;
    int s = t % 60; t /= 60;
    int m = t % 60; t /= 60;
    int h = t % 24;
    int d = t / 24;
    char buf[28];
    if (d > 0) snprintf(buf, sizeof(buf), "Uptime  %dd %02dh %02dm", d, h, m);
    else       snprintf(buf, sizeof(buf), "Uptime  %02d:%02d:%02d", h, m, s);
    return String(buf);
}

static const unsigned long BLOCKS_PER_RETARGET = 2016;

static void clearCacheAll() { mC = {}; nC = {}; tC = {}; tC.chartVer = 0xFFFF; }

static void redrawIfChanged(String& cache, const String& val,
                            int16_t x, int16_t y, int16_t w, int16_t h,
                            uint16_t color, uint8_t font, uint16_t bg = COL_CARD) {
    if (cache == val) return;
    tft.fillRect(x, y, w, h, bg);
    tft.setTextColor(color, bg);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(font);
    tft.drawString(val, x, y);
    cache = val;
}

static void drawCard(int x, int y, int w, int h) {
    tft.fillRoundRect(x, y, w, h, 4, COL_CARD);
    tft.drawRoundRect(x, y, w, h, 4, COL_BORDER);
}

static void drawCoinIcon() {
    int ix = 320 - BC2_LOGO_W - 6;
    int iy = (30 - BC2_LOGO_H) / 2;
    if (Settings.CoinTicker == "BC2") {
        for (int row = 0; row < BC2_LOGO_H; row++) {
            for (int col = 0; col < BC2_LOGO_W; col++) {
                uint16_t px = bc2Logo40[row * BC2_LOGO_W + col];
                if (px != BC2_LOGO_TRANSPARENT)
                    tft.drawPixel(ix + col, iy + row, px);
            }
        }
    } else {
        tft.fillRect(ix - 6, iy - 1, BC2_LOGO_W + 6, BC2_LOGO_H + 2, COL_HEADER);
        tft.setTextColor(COL_HASHRATE, COL_HEADER);
        tft.setTextDatum(MR_DATUM);
        tft.setTextFont(2);
        tft.drawString("BTC", 316, 14);
    }
}

static void drawHeader(const char* subtitle) {
    tft.fillRect(0, 0, 320, 30, COL_HEADER);
    tft.drawFastHLine(0, 30, 320, COL_BORDER);
    tft.setTextColor(COL_HASHRATE, COL_HEADER);
    tft.setTextDatum(ML_DATUM);
    tft.setTextFont(4);
    tft.drawString("AxeHub", 8, 16);
    tft.setTextColor(COL_FG, COL_HEADER);
    tft.setTextFont(2);
    tft.drawString(subtitle, 110, 17);
    drawCoinIcon();
}

static void drawMinerStatic() {
    String coin = Settings.CoinTicker.length() ? Settings.CoinTicker : String("BC2");
    String subtitle = String("solo ") + coin + " miner";
    drawHeader(subtitle.c_str());

    String poolLine = Settings.PoolAddress.length()
                        ? Settings.PoolAddress
                        : String("(no pool)");
    if (poolLine.length() > 24) poolLine = poolLine.substring(0, 24);
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(2);
    tft.drawString(poolLine, 8, 34);

    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextDatum(TC_DATUM);
    tft.setTextFont(1);
    tft.drawString("HASHRATE", 160, 56);
    tft.setTextDatum(TL_DATUM);

    int gx = 8, gy = 122, gw = 150, gh = 52;
    drawCard(gx,           gy,         gw, gh);
    drawCard(gx + 154,     gy,         gw, gh);
    drawCard(gx,           gy + 56,    gw, gh);
    drawCard(gx + 154,     gy + 56,    gw, gh);

    tft.setTextColor(COL_DIM, COL_CARD);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(1);
    tft.drawString("POOL BEST",   gx + 12,       gy + 6);
    tft.drawString("LOCAL BEST",  gx + 154 + 12, gy + 6);
    tft.drawString("WORKERS",     gx + 12,       gy + 56 + 6);
    tft.drawString("SHARES",      gx + 154 + 12, gy + 56 + 6);
}

static void axehubCyd_MinerScreen(unsigned long mElapsed) {
    if (s_needFullRedraw) {
        tft.fillScreen(COL_BG);
        clearCacheAll();
        drawMinerStatic();
        s_needFullRedraw = false;
    }

    mining_data md = getMiningData(mElapsed);
    pool_data   pd = getPoolData();

    if (mC.hashrate != md.currentHashRate) {
        tft.fillRect(0, 64, 320, 38, COL_BG);
        tft.setTextDatum(TL_DATUM);
        tft.setTextFont(6);
        int w1 = tft.textWidth(md.currentHashRate);
        tft.setTextFont(2);
        int w2 = tft.textWidth(" kH/s");
        int sx = (320 - (w1 + w2)) / 2;
        tft.setTextFont(6);
        tft.setTextColor(COL_HASHRATE, COL_BG);
        tft.drawString(md.currentHashRate, sx, 64);
        tft.setTextFont(2);
        tft.setTextColor(COL_DIM, COL_BG);
        tft.drawString(" kH/s", sx + w1, 64 + 36 - 16);
        mC.hashrate = md.currentHashRate;
    }

    String upt = formatUptime();
    if (mC.timeMining != upt) {
        tft.fillRect(0, 104, 320, 18, COL_BG);
        tft.setTextColor(COL_FG, COL_BG);
        tft.setTextDatum(TC_DATUM);
        tft.setTextFont(2);
        tft.drawString(upt, 160, 104);
        mC.timeMining = upt;
    }

    int gx = 8, gy = 122;
    auto orDash = [](const String& s) -> String { return s.length() ? s : String("--"); };
    redrawIfChanged(mC.pool_best,    orDash(pd.bestDifficulty),  gx + 12,       gy + 22, 136, 22, COL_FG, 2);
    redrawIfChanged(mC.local_best,   orDash(md.bestDiff),        gx + 154 + 12, gy + 22, 136, 22, COL_FG, 2);
    redrawIfChanged(mC.pool_workers, String(pd.workersCount),    gx + 12,       gy + 78, 136, 22, COL_FG, 2);
    String acceptedStr = String(axehub_metrics_get_accept_total());
    redrawIfChanged(mC.local_shares, acceptedStr,                 gx + 154 + 12, gy + 78, 136, 22, COL_FG, 2);

    String wifi = (WiFi.status() == WL_CONNECTED)
                  ? (String(WiFi.RSSI()) + " dBm")
                  : String("offline");
    if (mC.wifi != wifi) {
        tft.fillRect(220, 36, 100, 14, COL_BG);
        tft.setTextColor(COL_DIM, COL_BG);
        tft.setTextDatum(TR_DATUM);
        tft.setTextFont(1);
        tft.drawString(wifi, 312, 38);
        mC.wifi = wifi;
    }
}

static void drawNetworkStatic() {
    String coin = Settings.CoinTicker.length() ? Settings.CoinTicker : String("BC2");
    String subtitle = coin + " network";
    drawHeader(subtitle.c_str());

    // Override the coin icon area in the header with the miner's local IP —
    // gives users a quick "what's my device IP" reference without opening
    // a separate screen. WiFi-disconnected = leave coin icon as-is.
    if (WiFi.status() == WL_CONNECTED) {
        tft.fillRect(232, 1, 88, 28, COL_HEADER);
        String ip = WiFi.localIP().toString();
        tft.setTextColor(COL_DIM, COL_HEADER);
        tft.setTextDatum(MR_DATUM);
        tft.setTextFont(2);
        tft.drawString(ip.c_str(), 314, 16);
    }

    int gx = 8;
    drawCard(gx,        36,  150, 64);
    drawCard(gx + 154,  36,  150, 64);
    drawCard(gx,        108, 304, 76);
    drawCard(gx,        188, 150, 48);
    drawCard(gx + 154,  188, 150, 48);

    tft.setTextColor(COL_DIM, COL_CARD);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(1);
    tft.drawString("PRICE",         gx + 12,         42);
    tft.drawString("TIME",          gx + 154 + 12,   42);
    tft.drawString("BLOCK / HALVING / RETARGET", gx + 12, 114);
    tft.drawString("NET HASHRATE",  gx + 12,         192);
    tft.drawString("DIFFICULTY",    gx + 154 + 12,   192);
}

static void axehubCyd_NetworkScreen(unsigned long mElapsed) {
    if (s_needFullRedraw) {
        tft.fillScreen(COL_BG);
        clearCacheAll();
        drawNetworkStatic();
        s_needFullRedraw = false;
    }

    coin_data  cd = getCoinData(mElapsed);
    clock_data ck = getClockData(mElapsed);

    bool blockReady  = (mHeightUpdate != 0);
    bool priceReady  = (mBTCUpdate    != 0);
    bool globalReady = (mGlobalUpdate != 0);

    int gx = 8;
    String priceStr = priceReady ? cd.btcPrice    : String("...");
    String timeStr  = cd.currentTime.length() ? cd.currentTime : String("...");
    redrawIfChanged(nC.price, priceStr, gx + 12,       60, 132, 32, COL_HASHRATE, 4);
    redrawIfChanged(nC.time,  timeStr,  gx + 154 + 12, 60, 132, 32, COL_FG,       4);

    String blockLine, halvLine, retarget;
    if (blockReady) {
        unsigned long bh = cd.blockHeight.toInt();
        String rb = cd.remainingBlocks;
        rb.replace(" BLOCKS", "");
        blockLine = String("Block: #") + cd.blockHeight;
        halvLine  = String("Halving in: ") + rb + " blk";
        unsigned long left = BLOCKS_PER_RETARGET - (bh % BLOCKS_PER_RETARGET);
        retarget = String("Retarget in: ") + left + " blk";
    } else {
        blockLine = String("Block: ...");
        halvLine  = String("Halving in: ...");
        retarget  = String("Retarget in: ...");
    }
    redrawIfChanged(nC.blockNo,  blockLine, gx + 12, 130, 280, 18, COL_FG,  2);
    redrawIfChanged(nC.halving,  halvLine,  gx + 12, 150, 280, 14, COL_DIM, 1);
    redrawIfChanged(nC.retarget, retarget,  gx + 12, 166, 280, 14, COL_DIM, 1);

    String netHashStr = (globalReady && cd.globalHashRate.length())
                        ? (cd.globalHashRate + " EH/s") : String("...");
    String netDiffStr = (globalReady && cd.netwrokDifficulty.length())
                        ? cd.netwrokDifficulty : String("...");
    redrawIfChanged(nC.netHash, netHashStr, gx + 12,       208, 132, 22, COL_NET, 2);
    redrawIfChanged(nC.netDiff, netDiffStr, gx + 154 + 12, 208, 132, 22, COL_NET, 2);
}

#define CHART_X       10
#define CHART_Y       148
#define CHART_W       300
#define CHART_H       82
#define COL_TREND_UP   0x07E0   // TFT_GREEN
#define COL_TREND_DOWN 0xF800   // TFT_RED

static String formatPriceUSD(float v) {
    char buf[24];
    if (v >= 1000.0f)       snprintf(buf, sizeof(buf), "$%.0f", v);
    else if (v >= 10.0f)    snprintf(buf, sizeof(buf), "$%.2f", v);
    else if (v >= 1.0f)     snprintf(buf, sizeof(buf), "$%.3f", v);
    else                    snprintf(buf, sizeof(buf), "$%.4f", v);
    return String(buf);
}

static void drawTimeChartStatic() {
    String header = String(axehub_price_history_label()) + "/USD 24h";
    drawHeader(header.c_str());

    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextDatum(TC_DATUM);
    tft.setTextFont(1);
    tft.drawString("LOCAL TIME", 160, 36);
    tft.setTextDatum(TL_DATUM);
}

static void drawSparkline(uint8_t n, const float* hist, float yMin, float yMax) {
    tft.fillRect(CHART_X, CHART_Y, CHART_W, CHART_H, COL_BG);
    tft.drawRect(CHART_X, CHART_Y, CHART_W, CHART_H, COL_BORDER);

    if (n < 2) {
        tft.setTextColor(COL_DIM, COL_BG);
        tft.setTextDatum(MC_DATUM);
        tft.setTextFont(2);
        tft.drawString("loading 24h data...", CHART_X + CHART_W / 2,
                       CHART_Y + CHART_H / 2);
        tft.setTextDatum(TL_DATUM);
        return;
    }

    float span = yMax - yMin;
    if (span <= 0.0f) span = (yMax > 0.0f ? yMax * 0.001f : 1.0f);

    int innerX = CHART_X + 1;
    int innerY = CHART_Y + 1;
    int innerW = CHART_W - 2;
    int innerH = CHART_H - 2;

    for (uint8_t i = 1; i < n; i++) {
        int x0 = innerX + (int)((uint32_t)(i - 1) * innerW / (n - 1));
        int x1 = innerX + (int)((uint32_t) i      * innerW / (n - 1));
        int y0 = innerY + innerH - (int)((hist[i - 1] - yMin) / span * innerH);
        int y1 = innerY + innerH - (int)((hist[i]     - yMin) / span * innerH);
        if (y0 < innerY) y0 = innerY; if (y0 > innerY + innerH - 1) y0 = innerY + innerH - 1;
        if (y1 < innerY) y1 = innerY; if (y1 > innerY + innerH - 1) y1 = innerY + innerH - 1;
        uint16_t col;
        if      (hist[i] > hist[i - 1]) col = COL_TREND_UP;
        else if (hist[i] < hist[i - 1]) col = COL_TREND_DOWN;
        else                            col = COL_HASHRATE;
        tft.drawLine(x0, y0, x1, y1, col);
    }
}

static void axehubCyd_TimeChartScreen(unsigned long mElapsed) {
    if (s_needFullRedraw) {
        tft.fillScreen(COL_BG);
        clearCacheAll();
        drawTimeChartStatic();
        s_needFullRedraw = false;
    }

    unsigned long h = 0, m = 0, sec = 0;
    getTime(&h, &m, &sec);
    char hms[12];
    snprintf(hms, sizeof(hms), "%02lu:%02lu:%02lu", h, m, sec);
    String clk = String(hms);
    if (tC.clock != clk) {
        tft.fillRect(0, 50, 320, 50, COL_BG);
        tft.setTextColor(COL_HASHRATE, COL_BG);
        tft.setTextDatum(TC_DATUM);
        tft.setTextFont(6);
        tft.drawString(clk, 160, 50);
        tft.setTextDatum(TL_DATUM);
        tC.clock = clk;
    }

    String date = ::getDate();
    if (tC.date != date) {
        tft.fillRect(0, 102, 320, 18, COL_BG);
        tft.setTextColor(COL_FG, COL_BG);
        tft.setTextDatum(TC_DATUM);
        tft.setTextFont(2);
        tft.drawString(date, 160, 102);
        tft.setTextDatum(TL_DATUM);
        tC.date = date;
    }

    String currentPrice = getBTCprice();
    String label = String(axehub_price_history_label());
    String hdr   = label + ((Settings.CoinTicker != "BTC" && Settings.CoinTicker != "BC2")
                            ? String(" (fallback)")
                            : String(""));
    if (tC.coinHeader != hdr) {
        tft.fillRect(0, 124, 200, 18, COL_BG);
        tft.setTextColor(COL_NET, COL_BG);
        tft.setTextDatum(TL_DATUM);
        tft.setTextFont(2);
        tft.drawString(hdr, 12, 126);
        tC.coinHeader = hdr;
    }

    String priceStr = (mBTCUpdate != 0) ? currentPrice : String("...");
    if (tC.priceLine != priceStr) {
        tft.fillRect(120, 124, 130, 18, COL_BG);
        tft.setTextColor(COL_FG, COL_BG);
        tft.setTextDatum(TR_DATUM);
        tft.setTextFont(2);
        tft.drawString(priceStr, 248, 126);
        tft.setTextDatum(TL_DATUM);
        tC.priceLine = priceStr;
    }

    {
        float histDelta[AXEHUB_PRICE_HIST_SIZE];
        uint8_t nDelta = axehub_price_history_get(histDelta, AXEHUB_PRICE_HIST_SIZE, nullptr, nullptr);
        String deltaStr = "";
        uint16_t deltaCol = COL_DIM;
        if (nDelta >= 2 && histDelta[0] > 0.0f) {
            float pct = (histDelta[nDelta - 1] - histDelta[0]) * 100.0f / histDelta[0];
            char dbuf[16];
            snprintf(dbuf, sizeof(dbuf), "%+.2f%%", pct);
            deltaStr = String(dbuf);
            if      (pct > 0.05f)  deltaCol = COL_TREND_UP;
            else if (pct < -0.05f) deltaCol = COL_TREND_DOWN;
            else                   deltaCol = COL_DIM;
        }
        if (tC.deltaLine != deltaStr) {
            tft.fillRect(252, 124, 68, 18, COL_BG);
            if (deltaStr.length()) {
                tft.setTextColor(deltaCol, COL_BG);
                tft.setTextDatum(TR_DATUM);
                tft.setTextFont(2);
                tft.drawString(deltaStr, 314, 126);
                tft.setTextDatum(TL_DATUM);
            }
            tC.deltaLine = deltaStr;
        }
    }

    uint16_t ver = axehub_price_history_version();
    if (tC.chartVer != ver) {
        float hist[AXEHUB_PRICE_HIST_SIZE];
        float lo = 0.0f, hi = 0.0f;
        uint8_t n = axehub_price_history_get(hist, AXEHUB_PRICE_HIST_SIZE, &lo, &hi);

        float pad = (hi - lo) * 0.05f;
        if (pad < hi * 0.001f) pad = (hi > 0.0f ? hi * 0.001f : 1.0f);
        float yMin = lo - pad;
        float yMax = hi + pad;

        drawSparkline(n, hist, yMin, yMax);

        if (n >= 2) {
            String maxStr = String("hi ") + formatPriceUSD(hi);
            String minStr = String("lo ") + formatPriceUSD(lo);
            tft.setTextColor(COL_DIM, COL_BG);
            tft.setTextDatum(TR_DATUM);
            tft.setTextFont(1);
            tft.drawString(maxStr, CHART_X + CHART_W - 4, CHART_Y + 4);
            tft.drawString(minStr, CHART_X + CHART_W - 4, CHART_Y + CHART_H - 12);
            tft.setTextDatum(TL_DATUM);
            tC.rangeMax = maxStr;
            tC.rangeMin = minStr;
        }

        tC.chartVer = ver;
    }
}

static void cyd_screenSwitchHook() {
    if (axehubCydDriver.current_cyclic_screen != s_lastScreen) {
        s_needFullRedraw = true;
        s_lastScreen = axehubCydDriver.current_cyclic_screen;
    }
    if (Settings.CoinTicker != s_lastCoinTicker ||
        Settings.PoolAddress != s_lastPoolAddr) {
        s_needFullRedraw  = true;
        s_lastCoinTicker  = Settings.CoinTicker;
        s_lastPoolAddr    = Settings.PoolAddress;
    }
}

static void axehubCyd_MinerScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubCyd_MinerScreen(mElapsed);
}
static void axehubCyd_NetworkScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubCyd_NetworkScreen(mElapsed);
}
static void axehubCyd_TimeChartScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubCyd_TimeChartScreen(mElapsed);
}

void axehubCyd_Init(void) {
    tft.init();
    tft.writecommand(0x3A);
    tft.writedata(0x55);
    tft.invertDisplay(!Settings.invertColors);
    tft.setRotation(1);
    tft.setSwapBytes(true);
    tft.fillScreen(COL_BG);
#ifdef TFT_BL
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);
#endif
    touchSPI.begin(TOUCH_CLK, TOUCH_MISO, TOUCH_MOSI, ETOUCH_CS);
    touch.init();
    TFT_eTouchBase::Calibation cal = { 233, 3785, 3731, 120, 2 };
    touch.setCalibration(cal);
    s_needFullRedraw = true;
    s_lastScreen = -1;
}

void axehubCyd_ApplyInvertColors(void) {
    tft.invertDisplay(!Settings.invertColors);
    s_needFullRedraw = true;
}

void axehubCyd_AlternateScreenState(void) {
#ifdef TFT_BL
    static bool bl = true;
    bl = !bl;
    digitalWrite(TFT_BL, bl ? HIGH : LOW);
#endif
}

void axehubCyd_AlternateRotation(void) {
    int rot = tft.getRotation();
    tft.setRotation(rot == 1 ? 3 : 1);
    s_needFullRedraw = true;
}

void axehubCyd_LoadingScreen(void) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_HASHRATE, COL_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(4);
    tft.drawString("AxeHub", 160, 100);
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextFont(2);
    tft.drawString("starting...", 160, 130);
}

void axehubCyd_SetupScreen(void) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_HASHRATE, COL_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(4);
    tft.drawString("setup", 160, 50);
    tft.setTextColor(COL_FG, COL_BG);
    tft.setTextFont(2);
    tft.drawString("connect to wifi:", 160, 100);
    tft.drawString("NerdMinerAP", 160, 125);
    tft.drawString("password: MineYourCoins", 160, 155);
}

void axehubCyd_AnimateCurrentScreen(unsigned long frame) {}

void axehubCyd_DoLedStuff(unsigned long frame) {
    static unsigned long lastTouch = 0;
    unsigned long now = millis();
    if (now - lastTouch < 300) return;

    int16_t tx, ty;
    if (!touch.getXY(tx, ty)) return;
    lastTouch = now;

    int n = axehubCydDriver.num_cyclic_screens;
    if (tx >= 160) {
        axehubCydDriver.current_cyclic_screen = (axehubCydDriver.current_cyclic_screen + 1) % n;
    } else {
        axehubCydDriver.current_cyclic_screen = (axehubCydDriver.current_cyclic_screen + n - 1) % n;
    }
}

CyclicScreenFunction axehubCydCyclicScreens[] = {
    axehubCyd_MinerScreen_Wrap,
    axehubCyd_NetworkScreen_Wrap,
    axehubCyd_TimeChartScreen_Wrap,
};

DisplayDriver axehubCydDriver = {
    axehubCyd_Init,
    axehubCyd_AlternateScreenState,
    axehubCyd_AlternateRotation,
    axehubCyd_LoadingScreen,
    axehubCyd_SetupScreen,
    axehubCydCyclicScreens,
    axehubCyd_AnimateCurrentScreen,
    axehubCyd_DoLedStuff,
    SCREENS_ARRAY_SIZE(axehubCydCyclicScreens),
    0,
    320,
    240,
};

#endif