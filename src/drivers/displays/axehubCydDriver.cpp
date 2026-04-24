#include "displayDriver.h"

#ifdef AXEHUB_DISPLAY

#include <Arduino.h>
#include <WiFi.h>
#include <TFT_eSPI.h>
#include <TFT_eTouch.h>
#include "../../monitor.h"
#include "../../mining.h"
#include "../../axehub_metrics.h"
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

struct {
    String hashrate, timeMining;
    String pool_best, pool_workers, pool_hash;
    String local_best, local_shares, local_mhashes;
    String wifi;
} mC;
struct {
    String price, time, date, blockNo, halving, retarget, netHash, netDiff;
} nC;

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

static void clearCacheAll() { mC = {}; nC = {}; }

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
    tft.drawString("axehub", 8, 16);
    tft.setTextColor(COL_FG, COL_HEADER);
    tft.setTextFont(2);
    tft.drawString(subtitle, 110, 17);
    drawCoinIcon();
}

static void drawMinerStatic() {
    String coin = Settings.CoinTicker.length() ? Settings.CoinTicker : String("BTC");
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
    drawHeader("network");

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

void axehubCyd_Init(void) {
    tft.init();
    tft.writecommand(0x3A);
    tft.writedata(0x55);
    tft.invertDisplay(true);
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
    tft.drawString("axehub", 160, 100);
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