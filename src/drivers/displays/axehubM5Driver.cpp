#include "displayDriver.h"

#if defined(AXEHUB_DISPLAY) && defined(M5STICK_C_PLUS2)

#include <Arduino.h>
#include <WiFi.h>
#include <TFT_eSPI.h>
#include "../../monitor.h"
#include "../../mining.h"
#include "../../axehub_metrics.h"
#include "../../axehub_price_history.h"
#include "../../wManager.h"
#include "../../timeconst.h"
#include "../storage/storage.h"

extern TSettings Settings;

static TFT_eSPI tft = TFT_eSPI();

#define W 240
#define H 135

#define COL_BG          TFT_BLACK
#define COL_BORDER      0x7BE8
#define COL_FG          0xFFF0
#define COL_DIM         0xC610
#define COL_HASHRATE    TFT_ORANGE
#define COL_NET         TFT_YELLOW
#define COL_TREND_UP    TFT_GREEN
#define COL_TREND_DOWN  TFT_RED

extern DisplayDriver axehubM5Driver;

static int    s_lastScreen     = -1;
static bool   s_needFullRedraw = true;
static String s_lastCoinTicker = "";

extern uint64_t upTime;
extern unsigned long mBTCUpdate;

extern void   getTime(unsigned long* h, unsigned long* m, unsigned long* s);
extern String getDate();
extern String getBTCprice(void);

struct {
    String hashrate, uptime, poolBest, localBest, workers, shares, wifi;
} mC;
struct {
    String price, time, blockNo, halving, netHash, netDiff;
} nC;
struct {
    String   clock, date, coinHeader, priceLine, deltaLine;
    uint16_t chartVer;
} tC;

static void clearCacheAll() { mC = {}; nC = {}; tC = {}; tC.chartVer = 0xFFFF; }

static String formatUptimeShort() {
    uint64_t t = upTime;
    int s = t % 60; t /= 60;
    int m = t % 60; t /= 60;
    int h = t % 24;
    int d = t / 24;
    char buf[20];
    if (d > 0) snprintf(buf, sizeof(buf), "%dd %02d:%02d", d, h, m);
    else       snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
    return String(buf);
}

static void redrawIfChanged(String& cache, const String& val,
                            int16_t x, int16_t y, int16_t w, int16_t h,
                            uint16_t color, uint8_t font, uint8_t datum = TL_DATUM,
                            uint16_t bg = COL_BG) {
    if (cache == val) return;
    tft.fillRect(x, y, w, h, bg);
    tft.setTextColor(color, bg);
    tft.setTextDatum(datum);
    tft.setTextFont(font);
    int dx = (datum == TR_DATUM) ? (x + w - 1)
           : (datum == TC_DATUM) ? (x + w / 2)
           :                         x;
    int dy = y;
    tft.drawString(val, dx, dy);
    cache = val;
}

static void drawHeader(const char* subtitle) {
    tft.fillRect(0, 0, W, 20, COL_BG);
    tft.drawFastHLine(0, 20, W, COL_BORDER);
    tft.setTextColor(COL_HASHRATE, COL_BG);
    tft.setTextDatum(ML_DATUM);
    tft.setTextFont(2);
    tft.drawString("AxeHub", 4, 10);
    tft.setTextColor(COL_FG, COL_BG);
    tft.setTextFont(1);
    tft.setTextDatum(MR_DATUM);
    tft.drawString(subtitle, W - 4, 11);
    tft.setTextDatum(TL_DATUM);
}

static void drawMinerStatic() {
    String coin = Settings.CoinTicker.length() ? Settings.CoinTicker : String("BC2");
    String subtitle = String("solo ") + coin + " miner";
    drawHeader(subtitle.c_str());

    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(1);
    String poolLine = Settings.PoolAddress.length() ? Settings.PoolAddress : String("(no pool)");
    if (poolLine.length() > 28) poolLine = poolLine.substring(0, 28);
    tft.drawString(poolLine, 4, 24);

    // Inline labels left of each value — single-line rows, no overflow.
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextFont(1);
    tft.drawString("BEST",  4,    86);
    tft.drawString("LOCAL", 124,  86);
    tft.drawString("WORK",  4,    110);
    tft.drawString("ACC",   124,  110);
}

static void axehubM5_MinerScreen(unsigned long mElapsed) {
    if (s_needFullRedraw) {
        tft.fillScreen(COL_BG);
        clearCacheAll();
        drawMinerStatic();
        s_needFullRedraw = false;
    }

    mining_data md = getMiningData(mElapsed);
    pool_data   pd = getPoolData();

    if (mC.hashrate != md.currentHashRate) {
        tft.fillRect(0, 36, W, 30, COL_BG);
        tft.setTextDatum(TC_DATUM);
        tft.setTextFont(4);
        tft.setTextColor(COL_HASHRATE, COL_BG);
        tft.drawString(md.currentHashRate + " kH/s", W / 2, 38);
        mC.hashrate = md.currentHashRate;
    }

    String upt = formatUptimeShort();
    redrawIfChanged(mC.uptime, upt, 0, 68, W, 14, COL_FG, 2, TC_DATUM);

    // Two compact rows — label font 1 leftmost, value font 2 right of label.
    auto orDash = [](const String& s) -> String { return s.length() ? s : String("--"); };
    redrawIfChanged(mC.poolBest,  orDash(pd.bestDifficulty), 30,  84, 86,  16, COL_FG, 2);
    redrawIfChanged(mC.localBest, orDash(md.bestDiff),       154, 84, 82,  16, COL_FG, 2);
    redrawIfChanged(mC.workers,   String(pd.workersCount),   30,  108, 86, 16, COL_FG, 2);
    String acceptedStr = String(axehub_metrics_get_accept_total());
    redrawIfChanged(mC.shares,    acceptedStr,               154, 108, 82, 16, COL_FG, 2);

    String wifi = (WiFi.status() == WL_CONNECTED)
                  ? (String(WiFi.RSSI()) + "dBm") : String("offline");
    redrawIfChanged(mC.wifi, wifi, W - 56, 24, 56, 10, COL_DIM, 1, TR_DATUM);
}

static const unsigned long BLOCKS_PER_RETARGET_M5 = 2016;

static void drawNetworkStatic() {
    String coin = Settings.CoinTicker.length() ? Settings.CoinTicker : String("BC2");
    String subtitle = coin + " network";
    drawHeader(subtitle.c_str());
}

static void axehubM5_NetworkScreen(unsigned long mElapsed) {
    if (s_needFullRedraw) {
        tft.fillScreen(COL_BG);
        clearCacheAll();
        drawNetworkStatic();
        s_needFullRedraw = false;
    }

    coin_data cd = getCoinData(mElapsed);

    // Stacked single-line facts, font 2 (16 px). Each row sits in a 16-px
    // band so nothing overlaps in 135-px tall screen.
    bool priceReady = (mBTCUpdate != 0);
    String priceLine = String("Price: ") + (priceReady ? cd.btcPrice : String("..."));
    String timeLine  = String("Time:  ") + (cd.currentTime.length() ? cd.currentTime : String("..."));

    String blockLine, halvLine, retargetLine;
    if (cd.blockHeight.toInt() > 0) {
        unsigned long bh = cd.blockHeight.toInt();
        String rb = cd.remainingBlocks; rb.replace(" BLOCKS", "");
        blockLine    = String("Block:    #") + cd.blockHeight;
        halvLine     = String("Halving:  ") + rb + " blk";
        unsigned long left = BLOCKS_PER_RETARGET_M5 - (bh % BLOCKS_PER_RETARGET_M5);
        retargetLine = String("Retarget: ") + left + " blk";
    } else {
        blockLine    = String("Block:    ...");
        halvLine     = String("Halving:  ...");
        retargetLine = String("Retarget: ...");
    }

    String netHashStr = (cd.globalHashRate.length())   ? (String("NetHash:  ") + cd.globalHashRate + " EH/s") : String("NetHash:  ...");
    String netDiffStr = (cd.netwrokDifficulty.length()) ? (String("Diff:     ") + cd.netwrokDifficulty)        : String("Diff:     ...");

    redrawIfChanged(nC.price,    priceLine,     4, 24, W - 8, 16, COL_HASHRATE, 2);
    redrawIfChanged(nC.time,     timeLine,      4, 42, W - 8, 16, COL_FG,       2);
    redrawIfChanged(nC.blockNo,  blockLine,     4, 60, W - 8, 16, COL_FG,       2);
    redrawIfChanged(nC.halving,  halvLine,      4, 78, W - 8, 16, COL_DIM,      2);
    redrawIfChanged(nC.netHash,  retargetLine,  4, 96, W - 8, 16, COL_DIM,      2);
    redrawIfChanged(nC.netDiff,  netHashStr,    4, 114, W - 8, 16, COL_NET,     2);
    // Difficulty rendered separately below — would clash with NetHash row.
    // For 135-px we drop one of them; pick NetHash since it's the more
    // common at-a-glance value. Difficulty stays available via API.
    (void)netDiffStr;
}

#define M5_CHART_X  4
#define M5_CHART_Y  90
#define M5_CHART_W  232
#define M5_CHART_H  42

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
}

static void drawSparkline(uint8_t n, const float* hist, float yMin, float yMax) {
    tft.fillRect(M5_CHART_X, M5_CHART_Y, M5_CHART_W, M5_CHART_H, COL_BG);
    tft.drawRect(M5_CHART_X, M5_CHART_Y, M5_CHART_W, M5_CHART_H, COL_BORDER);

    if (n < 2) {
        tft.setTextColor(COL_DIM, COL_BG);
        tft.setTextDatum(MC_DATUM);
        tft.setTextFont(1);
        tft.drawString("loading 24h data...", M5_CHART_X + M5_CHART_W / 2,
                       M5_CHART_Y + M5_CHART_H / 2);
        tft.setTextDatum(TL_DATUM);
        return;
    }

    float span = yMax - yMin;
    if (span <= 0.0f) span = (yMax > 0.0f ? yMax * 0.001f : 1.0f);

    int innerX = M5_CHART_X + 1;
    int innerY = M5_CHART_Y + 1;
    int innerW = M5_CHART_W - 2;
    int innerH = M5_CHART_H - 2;

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

static void axehubM5_TimeChartScreen(unsigned long mElapsed) {
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
    redrawIfChanged(tC.clock, String(hms), 0, 24, W, 26, COL_HASHRATE, 4, TC_DATUM);

    String date = ::getDate();
    redrawIfChanged(tC.date, date, 0, 52, W, 12, COL_FG, 1, TC_DATUM);

    String currentPrice = getBTCprice();
    String label = String(axehub_price_history_label());
    String hdr   = label + ((Settings.CoinTicker != "BTC" && Settings.CoinTicker != "BC2")
                            ? String(" (fallback)") : String(""));
    redrawIfChanged(tC.coinHeader, hdr, 4, 70, 60, 14, COL_NET, 2, TL_DATUM);

    String priceStr = (mBTCUpdate != 0) ? currentPrice : String("...");
    redrawIfChanged(tC.priceLine, priceStr, 70, 70, 100, 14, COL_FG, 2, TL_DATUM);

    // 24h delta % from cached history — sign-coloured.
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
    }
    if (tC.deltaLine != deltaStr) {
        tft.fillRect(170, 70, W - 170, 14, COL_BG);
        if (deltaStr.length()) {
            tft.setTextColor(deltaCol, COL_BG);
            tft.setTextDatum(TR_DATUM);
            tft.setTextFont(2);
            tft.drawString(deltaStr, W - 4, 70);
            tft.setTextDatum(TL_DATUM);
        }
        tC.deltaLine = deltaStr;
    }

    uint16_t ver = axehub_price_history_version();
    if (tC.chartVer != ver) {
        float hist[AXEHUB_PRICE_HIST_SIZE];
        float lo = 0.0f, hi = 0.0f;
        uint8_t n = axehub_price_history_get(hist, AXEHUB_PRICE_HIST_SIZE, &lo, &hi);
        float pad = (hi - lo) * 0.05f;
        if (pad < hi * 0.001f) pad = (hi > 0.0f ? hi * 0.001f : 1.0f);
        drawSparkline(n, hist, lo - pad, hi + pad);

        // Hi/lo overlaid in the chart's right-side corners (font 1 ~8 px).
        if (n >= 2) {
            tft.setTextColor(COL_DIM, COL_BG);
            tft.setTextDatum(TR_DATUM);
            tft.setTextFont(1);
            tft.drawString(formatPriceUSD(hi), M5_CHART_X + M5_CHART_W - 3, M5_CHART_Y + 2);
            tft.drawString(formatPriceUSD(lo), M5_CHART_X + M5_CHART_W - 3, M5_CHART_Y + M5_CHART_H - 10);
            tft.setTextDatum(TL_DATUM);
        }

        tC.chartVer = ver;
    }
}

static void cyd_screenSwitchHook() {
    if (axehubM5Driver.current_cyclic_screen != s_lastScreen) {
        s_needFullRedraw = true;
        s_lastScreen = axehubM5Driver.current_cyclic_screen;
    }
    if (Settings.CoinTicker != s_lastCoinTicker) {
        s_needFullRedraw = true;
        s_lastCoinTicker = Settings.CoinTicker;
    }
}

static void axehubM5_MinerScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubM5_MinerScreen(mElapsed);
}
static void axehubM5_NetworkScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubM5_NetworkScreen(mElapsed);
}
static void axehubM5_TimeChartScreen_Wrap(unsigned long mElapsed) {
    cyd_screenSwitchHook();
    axehubM5_TimeChartScreen(mElapsed);
}

void axehubM5_Init(void) {
    tft.init();
    tft.setRotation(3);
    tft.setSwapBytes(true);
    tft.fillScreen(COL_BG);
#ifdef TFT_BL
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);
#endif
    s_needFullRedraw = true;
    s_lastScreen = -1;
}

void axehubCyd_ApplyInvertColors(void) {
    tft.invertDisplay(Settings.invertColors);
    s_needFullRedraw = true;
}

void axehubM5_AlternateScreenState(void) {
#ifdef TFT_BL
    static bool bl = true;
    bl = !bl;
    digitalWrite(TFT_BL, bl ? HIGH : LOW);
#endif
}

void axehubM5_AlternateRotation(void) {
    int rot = tft.getRotation();
    tft.setRotation(rot == 1 ? 3 : 1);
    s_needFullRedraw = true;
}

void axehubM5_LoadingScreen(void) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_HASHRATE, COL_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(4);
    tft.drawString("AxeHub", W / 2, H / 2 - 12);
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setTextFont(1);
    tft.drawString("starting...", W / 2, H / 2 + 12);
}

void axehubM5_SetupScreen(void) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_HASHRATE, COL_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(2);
    tft.drawString("setup", W / 2, 16);
    tft.setTextColor(COL_FG, COL_BG);
    tft.setTextFont(1);
    tft.drawString("connect to wifi:", W / 2, 50);
    tft.drawString("NerdMinerAP", W / 2, 70);
    tft.drawString("MineYourCoins", W / 2, 90);
}

void axehubM5_AnimateCurrentScreen(unsigned long frame) {}

void axehubM5_DoLedStuff(unsigned long frame) {
    // Buttons (PIN_BUTTON_1 = 37, PIN_BUTTON_2 = 39) are wired through the
    // upstream OneButton handler that calls switchToNextScreen — no extra
    // work needed here.
}

CyclicScreenFunction axehubM5CyclicScreens[] = {
    axehubM5_MinerScreen_Wrap,
    axehubM5_NetworkScreen_Wrap,
    axehubM5_TimeChartScreen_Wrap,
};

DisplayDriver axehubM5Driver = {
    axehubM5_Init,
    axehubM5_AlternateScreenState,
    axehubM5_AlternateRotation,
    axehubM5_LoadingScreen,
    axehubM5_SetupScreen,
    axehubM5CyclicScreens,
    axehubM5_AnimateCurrentScreen,
    axehubM5_DoLedStuff,
    SCREENS_ARRAY_SIZE(axehubM5CyclicScreens),
    0,
    W,
    H,
};

#endif
