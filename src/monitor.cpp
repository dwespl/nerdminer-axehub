#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "mbedtls/md.h"
#include "HTTPClient.h"
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <list>

static WiFiClientSecure s_https_client;
static bool axehub_http_begin(HTTPClient& http, const String& url, uint16_t handshakeSec = 3) {
    if (url.startsWith("https://")) {
        s_https_client.setInsecure();
        s_https_client.setHandshakeTimeout(handshakeSec);
        return http.begin(s_https_client, url);
    }
    return http.begin(url);
}

static TaskHandle_t s_axehubFetchTaskHandle = nullptr;
static inline bool axehub_in_fetch_task() {
    return s_axehubFetchTaskHandle != nullptr &&
           xTaskGetCurrentTaskHandle() == s_axehubFetchTaskHandle;
}
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "drivers/storage/storage.h"
#include "drivers/devices/device.h"
#include "axehub_metrics.h"
#include "axehub_price_history.h"

extern uint32_t templates;
extern uint32_t hashes;
extern uint32_t Mhashes;
extern uint32_t totalKHashes;
extern uint32_t elapsedKHs;
extern uint64_t upTime;

extern uint32_t shares; // increase if blockhash has 32 bits of zeroes
extern uint32_t valids; // increased if blockhash <= targethalfshares

extern double best_diff; // track best diff

extern monitor_data mMonitor;

//from saved config
extern TSettings Settings;
bool invertColors = false;

// Parse a hashrate string ("5.92T", "451.2K") into raw H/s; 0 on error.
static double parse_hashrate_suffix(const char* s) {
    if (!s || !*s) return 0.0;
    char* endp = nullptr;
    double v = strtod(s, &endp);
    if (v <= 0.0 || !endp) return 0.0;
    while (*endp == ' ') endp++;
    switch (*endp) {
        case 'k': case 'K': return v * 1e3;
        case 'm': case 'M': return v * 1e6;
        case 'g': case 'G': return v * 1e9;
        case 't': case 'T': return v * 1e12;
        case 'p': case 'P': return v * 1e15;
        case 'e': case 'E': return v * 1e18;
        default:            return v;
    }
}

WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "europe.pool.ntp.org", 3600, 60000);
double bitcoin_price=0.0;
String current_block = "793261";
global_data gData;
pool_data pData;
String poolAPIUrl;

// Coin-data API router. Supported tickers: BTC, BC2, custom.
// Empty URL from any helper = skip the HTTP call.
static String coinHeightUrl() {
    if (Settings.CoinTicker == "BC2") {
        if (Settings.CoinHeightApiUrl.length() > 0) return Settings.CoinHeightApiUrl;
        return "https://bc2mempool.com/api/blocks/tip/height";
    }
    if (Settings.CoinTicker == "custom" && Settings.CoinHeightApiUrl.length() > 0) return Settings.CoinHeightApiUrl;
    if (Settings.CoinTicker == "custom") return "";
    return String(getHeightAPI);
}
static String coinDifficultyUrl() {
    if (Settings.CoinTicker == "BC2") {
        if (Settings.CoinDifficultyApiUrl.length() > 0) return Settings.CoinDifficultyApiUrl;
        return "https://bc2mempool.com/api/v1/difficulty-adjustment";
    }
    if (Settings.CoinTicker == "custom" && Settings.CoinDifficultyApiUrl.length() > 0) return Settings.CoinDifficultyApiUrl;
    if (Settings.CoinTicker == "custom") return "";
    return String(getDifficulty);
}
static String coinGlobalHashUrl() {
    if (Settings.CoinTicker == "BC2") {
        if (Settings.CoinGlobalHashApiUrl.length() > 0) return Settings.CoinGlobalHashApiUrl;
        return "https://bc2mempool.com/api/v1/mining/hashrate/3d";
    }
    if (Settings.CoinTicker == "custom" && Settings.CoinGlobalHashApiUrl.length() > 0) return Settings.CoinGlobalHashApiUrl;
    if (Settings.CoinTicker == "custom") return "";
    return String(getGlobalHash);
}
static String coinPriceUrl() {
    if (Settings.CoinTicker == "BC2") {
        if (Settings.CoinPriceApiUrl.length() > 0) return Settings.CoinPriceApiUrl;
        return "https://api.coingecko.com/api/v3/simple/price?ids=bitcoinii&vs_currencies=usd";
    }
    if (Settings.CoinTicker == "custom" && Settings.CoinPriceApiUrl.length() > 0) return Settings.CoinPriceApiUrl;
    if (Settings.CoinTicker == "custom") return "";
    return String(getBTCAPI);
}
static const char* coinPriceJsonKey() {
    if (Settings.CoinTicker == "BC2") return "bitcoinii";
    return "bitcoin";
}


static void axehubNetworkFetchTask(void*);
String getBlockHeight(void);
String getBTCprice(void);
void   updateGlobalData(void);

void setup_monitor(void){
    /******** TIME ZONE SETTING *****/

    timeClient.begin();

    // Adjust offset depending on your zone
    // GMT +2 in seconds (zona horaria de Europa Central)
    timeClient.setTimeOffset(3600 * Settings.Timezone);

    Serial.println("TimeClient setup done");
#ifdef SCREEN_WORKERS_ENABLE
    poolAPIUrl = getPoolAPIUrl();
    Serial.println("poolAPIUrl: " + poolAPIUrl);
#endif

    xTaskCreatePinnedToCore(axehubNetworkFetchTask, "AxhFetch", 8192,
                            nullptr, 11, &s_axehubFetchTaskHandle, 0);
}

static void axehubNetworkFetchTask(void*) {
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
    vTaskDelay(2000 / portTICK_PERIOD_MS);

    for (;;) {
        getBlockHeight();
        vTaskDelay(500 / portTICK_PERIOD_MS);
        getBTCprice();
        vTaskDelay(500 / portTICK_PERIOD_MS);
        updateGlobalData();
        vTaskDelay(500 / portTICK_PERIOD_MS);
        axehub_price_history_tick();
       vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}

unsigned long mGlobalUpdate =0;

void updateGlobalData(void){
   if (!axehub_in_fetch_task()) return;

    if((mGlobalUpdate == 0) || (millis() - mGlobalUpdate > UPDATE_Global_min * 60 * 1000)){

        if (WiFi.status() != WL_CONNECTED) return;

        String ghUrl = coinGlobalHashUrl();
        if (ghUrl.length() == 0) { mGlobalUpdate = millis(); return; }   // BC2 / custom with no URL

        HTTPClient http;
        http.setConnectTimeout(6000);
        http.setTimeout(6000);
        Serial.printf("[Global] GET %s\n", ghUrl.c_str());
        try {
        axehub_http_begin(http, ghUrl);
        int httpCode = http.GET();
        Serial.printf("[Global] HTTP %d\n", httpCode);

        if (httpCode == HTTP_CODE_OK) {
            String payload = http.getString();
            Serial.printf("[Global] payload len=%d\n", (int)payload.length());

            // Three payload shapes: blockchain.info /stats (object, GH/s),
            // mempool /mining/hashrate (object, H/s), mempool /blocks (array).
            double diff = 0.0;
            double hs   = 0.0;
            payload.trim();
            bool isArray = payload.length() > 0 && payload[0] == '[';
            if (isArray) {
              StaticJsonDocument<48> filter;
              filter[0]["difficulty"] = true;
              StaticJsonDocument<128> doc;
              deserializeJson(doc, payload, DeserializationOption::Filter(filter));
              JsonArray arr = doc.as<JsonArray>();
              if (arr.size() > 0 && arr[0].containsKey("difficulty")) {
                diff = arr[0]["difficulty"].as<double>();
                hs = diff * 4294967296.0 / 600.0;   // BTC: ~600s block target.
              }
            } else {
              StaticJsonDocument<96> filter;
              filter["currentHashrate"]   = true;
              filter["currentDifficulty"] = true;
              filter["hash_rate"]         = true;
              filter["difficulty"]        = true;
              StaticJsonDocument<256> doc;
              deserializeJson(doc, payload, DeserializationOption::Filter(filter));
              // mempool.space ships both scalars AND `difficulty` as a history
              // array — branch on shape to avoid reading the array as a scalar.
              if (doc.containsKey("currentHashrate") || doc.containsKey("currentDifficulty")) {
                if (doc.containsKey("currentHashrate"))   hs   = doc["currentHashrate"].as<double>();
                if (doc.containsKey("currentDifficulty")) diff = doc["currentDifficulty"].as<double>();
              } else if (doc.containsKey("hash_rate") || doc.containsKey("difficulty")) {
                // blockchain.info /stats: hash_rate is in GH/s, difficulty raw.
                if (doc.containsKey("hash_rate"))  hs   = doc["hash_rate"].as<double>() * 1.0e9;
                if (doc.containsKey("difficulty")) diff = doc["difficulty"].as<double>();
              }
            }

            // Scale H/s to EH/s for the network-hashrate display label.
            if (hs > 0.0) {
              double eh = hs / 1.0e18;
              char buf[16];
              if (eh >= 100.0)        snprintf(buf, sizeof(buf), "%.0f", eh);
              else if (eh >= 10.0)    snprintf(buf, sizeof(buf), "%.1f", eh);
              else if (eh >= 1.0)     snprintf(buf, sizeof(buf), "%.2f", eh);
              else if (eh >= 0.01)    snprintf(buf, sizeof(buf), "%.3f", eh);
              else                    snprintf(buf, sizeof(buf), "%.4f", eh);
              gData.globalHash = String(buf);
            }
            if (diff > 0.0) {
              axehub_metrics_set_network_difficulty(diff);
              // Auto-scale to the largest SI prefix that keeps the number
              // readable (T/G/M/K). BTC ~140T, BC2 ~38G.
              char dbuf[16];
              const char* unit;
              double scaled;
              if      (diff >= 1.0e12) { scaled = diff / 1.0e12; unit = "T"; }
              else if (diff >= 1.0e9 ) { scaled = diff / 1.0e9 ; unit = "G"; }
              else if (diff >= 1.0e6 ) { scaled = diff / 1.0e6 ; unit = "M"; }
              else if (diff >= 1.0e3 ) { scaled = diff / 1.0e3 ; unit = "K"; }
              else                     { scaled = diff;         unit = "";  }
              if      (scaled >= 100.0) snprintf(dbuf, sizeof(dbuf), "%.0f%s",  scaled, unit);
              else if (scaled >= 10.0 ) snprintf(dbuf, sizeof(dbuf), "%.1f%s",  scaled, unit);
              else                      snprintf(dbuf, sizeof(dbuf), "%.2f%s",  scaled, unit);
              gData.difficulty = String(dbuf);
            }

        }
        // Always advance the timer so a slow/failing endpoint can't pin
        // every display frame on a 6s HTTP attempt — retry once per cycle.
        mGlobalUpdate = millis();
        http.end();


        //Make third API call to get fees
        axehub_http_begin(http, String(getFees));
        httpCode = http.GET();

        if (httpCode == HTTP_CODE_OK) {
            String payload = http.getString();
            
            StaticJsonDocument<1024> doc;
            deserializeJson(doc, payload);
            String temp = "";
            if (doc.containsKey("halfHourFee")) gData.halfHourFee = doc["halfHourFee"].as<int>();
#ifdef SCREEN_FEES_ENABLE
            if (doc.containsKey("fastestFee"))  gData.fastestFee = doc["fastestFee"].as<int>();
            if (doc.containsKey("hourFee"))     gData.hourFee = doc["hourFee"].as<int>();
            if (doc.containsKey("economyFee"))  gData.economyFee = doc["economyFee"].as<int>();
            if (doc.containsKey("minimumFee"))  gData.minimumFee = doc["minimumFee"].as<int>();
#endif
            doc.clear();

            mGlobalUpdate = millis();
        }
        
        http.end();
        } catch(...) {
          Serial.println("Global data HTTP error caught");
          http.end();
        }
    }
}

unsigned long mHeightUpdate = 0;

String getBlockHeight(void){
    // Monitor / screen callers get the cached value only — actual TLS
    // fetch happens on the dedicated fetch task to keep the screen alive.
    if (!axehub_in_fetch_task()) return current_block;

    if((mHeightUpdate == 0) || (millis() - mHeightUpdate > UPDATE_Height_min * 60 * 1000)){

        if (WiFi.status() != WL_CONNECTED) return current_block;

        String hUrl = coinHeightUrl();
        if (hUrl.length() == 0) {
            current_block = "0";
            mHeightUpdate = millis();
            return current_block;
        }

        HTTPClient http;
        http.setConnectTimeout(8000);
        http.setTimeout(10000);
        mHeightUpdate = millis();
        Serial.printf("[Height] GET %s\n", hUrl.c_str());
        try {
        axehub_http_begin(http, hUrl);
        int httpCode = http.GET();
        Serial.printf("[Height] HTTP %d\n", httpCode);

        if (httpCode == HTTP_CODE_OK) {
            String payload = http.getString();
            payload.trim();
            Serial.printf("[Height] payload: '%s'\n", payload.c_str());

            current_block = payload;
        }
        http.end();
        } catch(...) {
          Serial.println("Height HTTP error caught");
          http.end();
        }
    }
  
  return current_block;
}

unsigned long mBTCUpdate = 0;

String getBTCprice(void){
    if (!axehub_in_fetch_task()) {
        static char price_buffer[16];
        if (bitcoin_price >= 1.0) snprintf(price_buffer, sizeof(price_buffer), "$%u", (unsigned int)bitcoin_price);
        else                      snprintf(price_buffer, sizeof(price_buffer), "$%.3f", bitcoin_price);
        return String(price_buffer);
    }

    if((mBTCUpdate == 0) || (millis() - mBTCUpdate > UPDATE_BTC_min * 60 * 1000)){

        if (WiFi.status() != WL_CONNECTED) {
            static char price_buffer[16];
            if (bitcoin_price >= 1.0) snprintf(price_buffer, sizeof(price_buffer), "$%u", (unsigned int)bitcoin_price);
            else                      snprintf(price_buffer, sizeof(price_buffer), "$%.3f", bitcoin_price);
            return String(price_buffer);
        }

        String pUrl = coinPriceUrl();
        if (pUrl.length() == 0) {
            // No market price for this coin (e.g. BC2 private chain).
            mBTCUpdate = millis();
            static char price_buffer[16];
            snprintf(price_buffer, sizeof(price_buffer), "N/A");
            return String(price_buffer);
        }

        HTTPClient http;
        http.setConnectTimeout(8000);
        http.setTimeout(10000);
        bool priceUpdated = false;
        mBTCUpdate = millis();

        Serial.printf("[Price] GET %s\n", pUrl.c_str());
        try {
        axehub_http_begin(http, pUrl);
        int httpCode = http.GET();
        Serial.printf("[Price] HTTP %d\n", httpCode);

        if (httpCode == HTTP_CODE_OK) {
            String payload = http.getString();
            Serial.printf("[Price] payload: '%s'\n", payload.c_str());

            StaticJsonDocument<1024> doc;
            deserializeJson(doc, payload);

            const char* key = coinPriceJsonKey();
            if (doc.containsKey(key) && doc[key].containsKey("usd")) {
                bitcoin_price = doc[key]["usd"].as<double>();
                Serial.printf("[Price] parsed %.4f (key=%s)\n", bitcoin_price, key);
            } else {
                Serial.printf("[Price] JSON missing key '%s'\n", key);
            }

            doc.clear();

            mBTCUpdate = millis();
        }
        
        http.end();
        } catch(...) {
          Serial.println("BTC price HTTP error caught");
          http.end();
        }
    }  
  
  static char price_buffer[16];
  if (bitcoin_price >= 1.0) snprintf(price_buffer, sizeof(price_buffer), "$%u", (unsigned int)bitcoin_price);
  else                      snprintf(price_buffer, sizeof(price_buffer), "$%.3f", bitcoin_price);
  return String(price_buffer);
}

unsigned long mTriggerUpdate = 0;
unsigned long initialMillis = millis();
unsigned long initialTime = 0;
unsigned long mPoolUpdate = 0;

void getTime(unsigned long* currentHours, unsigned long* currentMinutes, unsigned long* currentSeconds){
  
  //Check if need an NTP call to check current time
  if((mTriggerUpdate == 0) || (millis() - mTriggerUpdate > UPDATE_PERIOD_h * 60 * 60 * 1000)){ //60 sec. * 60 min * 1000ms
    if(WiFi.status() == WL_CONNECTED) {
        if(timeClient.update()) mTriggerUpdate = millis(); //NTP call to get current time
        initialTime = timeClient.getEpochTime(); // Guarda la hora inicial (en segundos desde 1970)
        Serial.print("TimeClient NTPupdateTime ");
    }
  }

  unsigned long elapsedTime = (millis() - mTriggerUpdate) / 1000; // Tiempo transcurrido en segundos
  unsigned long currentTime = initialTime + elapsedTime; // La hora actual

  // convierte la hora actual en horas, minutos y segundos
  *currentHours = currentTime % 86400 / 3600;
  *currentMinutes = currentTime % 3600 / 60;
  *currentSeconds = currentTime % 60;
}

String getDate(){
  
  unsigned long elapsedTime = (millis() - mTriggerUpdate) / 1000; // Tiempo transcurrido en segundos
  unsigned long currentTime = initialTime + elapsedTime; // La hora actual

  // Convierte la hora actual (epoch time) en una estructura tm
  struct tm *tm = localtime((time_t *)&currentTime);

  int year = tm->tm_year + 1900; // tm_year es el número de años desde 1900
  int month = tm->tm_mon + 1;    // tm_mon es el mes del año desde 0 (enero) hasta 11 (diciembre)
  int day = tm->tm_mday;         // tm_mday es el día del mes

  char currentDate[20];
  sprintf(currentDate, "%02d/%02d/%04d", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900);

  return String(currentDate);
}

String getTime(void){
  unsigned long currentHours, currentMinutes, currentSeconds;
  getTime(&currentHours, &currentMinutes, &currentSeconds);

  char LocalHour[10];
  sprintf(LocalHour, "%02d:%02d", currentHours, currentMinutes);
  
  String mystring(LocalHour);
  return LocalHour;
}

enum EHashRateScale
{
  HashRateScale_99KH,
  HashRateScale_999KH,
  HashRateScale_9MH
};

static EHashRateScale s_hashrate_scale = HashRateScale_99KH;
static uint32_t s_skip_first = 3;
static double s_top_hashrate = 0.0;

static std::list<double> s_hashrate_avg_list;
static double s_hashrate_summ = 0.0;
static uint8_t s_hashrate_recalc = 0;

String getCurrentHashRate(unsigned long mElapsed)
{
  // Per-worker counters (instant, pool-diff-independent). Pool_eff is
  // the truth metric but its 1/sqrt(N) variance wobbles the LCD.
  double hashrate = (double)(axehub_metrics_get_hw_khs() + axehub_metrics_get_sw_khs());
  (void)mElapsed;

  s_hashrate_summ += hashrate;
  s_hashrate_avg_list.push_back(hashrate);
  if (s_hashrate_avg_list.size() > 10)
  {
    s_hashrate_summ -= s_hashrate_avg_list.front();
    s_hashrate_avg_list.pop_front();
  }

  ++s_hashrate_recalc;
  if (s_hashrate_recalc == 0)
  {
    s_hashrate_summ = 0.0;
    for (auto itt = s_hashrate_avg_list.begin(); itt != s_hashrate_avg_list.end(); ++itt)
      s_hashrate_summ += *itt;
  }

  double avg_hashrate = s_hashrate_summ / (double)s_hashrate_avg_list.size();
  if (avg_hashrate < 0.0)
    avg_hashrate = 0.0;

  if (s_skip_first > 0)
  {
    s_skip_first--;
  } else
  {
    if (avg_hashrate > s_top_hashrate)
    {
      s_top_hashrate = avg_hashrate;
      if (avg_hashrate > 999.9)
        s_hashrate_scale = HashRateScale_9MH;
      else if (avg_hashrate > 99.9)
        s_hashrate_scale = HashRateScale_999KH;
    }
  }

  switch (s_hashrate_scale)
  {
    case HashRateScale_99KH:
      return String(avg_hashrate, 2);
    case HashRateScale_999KH:
      return String(avg_hashrate, 1);
    default:
      return String((int)avg_hashrate );
  }
}

mining_data getMiningData(unsigned long mElapsed)
{
  mining_data data;

  char best_diff_string[16] = {0};
  suffix_string(best_diff, best_diff_string, 16, 0);

  char timeMining[15] = {0};
  uint64_t tm = upTime;
  int secs = tm % 60;
  tm /= 60;
  int mins = tm % 60;
  tm /= 60;
  int hours = tm % 24;
  int days = tm / 24;
  sprintf(timeMining, "%01d  %02d:%02d:%02d", days, hours, mins, secs);

  data.completedShares = shares;
  data.totalMHashes = Mhashes;
  data.totalKHashes = totalKHashes;
  data.currentHashRate = getCurrentHashRate(mElapsed);
  data.templates = templates;
  data.bestDiff = best_diff_string;
  data.timeMining = timeMining;
  data.valids = valids;
  data.temp = String(temperatureRead(), 0);
  data.currentTime = getTime();

  return data;
}

clock_data getClockData(unsigned long mElapsed)
{
  clock_data data;

  data.completedShares = shares;
  data.totalKHashes = totalKHashes;
  data.currentHashRate = getCurrentHashRate(mElapsed);
  data.btcPrice = getBTCprice();
  data.blockHeight = getBlockHeight();
  data.currentTime = getTime();
  data.currentDate = getDate();

  return data;
}

clock_data_t getClockData_t(unsigned long mElapsed)
{
  clock_data_t data;

  data.valids = valids;
  data.currentHashRate = getCurrentHashRate(mElapsed);
  getTime(&data.currentHours, &data.currentMinutes, &data.currentSeconds);

  return data;
}

coin_data getCoinData(unsigned long mElapsed)
{
  coin_data data;

  // Cheap endpoints first (height + price land within ~1s); heavy global
  // stats fetch last to avoid blocking first paint.
  data.blockHeight     = getBlockHeight();
  data.btcPrice        = getBTCprice();
  data.completedShares = shares;
  data.totalKHashes    = totalKHashes;
  data.currentHashRate = getCurrentHashRate(mElapsed);
  data.currentTime     = getTime();

  updateGlobalData(); // Heavier mempool poll — runs after fast paints.
#ifdef SCREEN_FEES_ENABLE
  data.hourFee = String(gData.hourFee);
  data.fastestFee = String(gData.fastestFee);
  data.economyFee = String(gData.economyFee);
  data.minimumFee = String(gData.minimumFee);
#endif
  data.halfHourFee = String(gData.halfHourFee) + " sat/vB";
  data.netwrokDifficulty = gData.difficulty;
  data.globalHashRate = gData.globalHash;

  unsigned long currentBlock = data.blockHeight.toInt();
  unsigned long remainingBlocks = (((currentBlock / HALVING_BLOCKS) + 1) * HALVING_BLOCKS) - currentBlock;
  data.progressPercent = (HALVING_BLOCKS - remainingBlocks) * 100 / HALVING_BLOCKS;
  data.remainingBlocks = String(remainingBlocks) + " BLOCKS";

  return data;
}

bool g_pool_has_stats_api = false;

String getPoolAPIUrl(void) {
    poolAPIUrl = String(getPublicPool);
    g_pool_has_stats_api = false;

    if (Settings.PoolStatsApiUrl.length() > 0) {
        poolAPIUrl = Settings.PoolStatsApiUrl;
        g_pool_has_stats_api = true;
        return poolAPIUrl;
    }

    if (Settings.PoolAddress == "public-pool.io") {
        poolAPIUrl = "https://public-pool.io:40557/api/client/";
        g_pool_has_stats_api = true;
    }
    else {
        if (Settings.PoolAddress == "pool.nerdminers.org") {
            poolAPIUrl = "https://pool.nerdminers.org/users/";
            g_pool_has_stats_api = true;
        }
        else {
            switch (Settings.PoolPort) {
                case 3333:
                    if (Settings.PoolAddress == "pool.sethforprivacy.com") {
                        poolAPIUrl = "https://pool.sethforprivacy.com/api/client/";
                        g_pool_has_stats_api = true;
                    }
                    if (Settings.PoolAddress == "pool.solomining.de") {
                        poolAPIUrl = "https://pool.solomining.de/api/client/";
                        g_pool_has_stats_api = true;
                    }
                    // Add more cases for other addresses with port 3333 if needed
                    break;
                case 2018:
                    // Local instance of public-pool.io on Umbrel or Start9
                    poolAPIUrl = "http://" + Settings.PoolAddress + ":2019/api/client/";
                    g_pool_has_stats_api = true;
                    break;
                default:
                    poolAPIUrl = String(getPublicPool);
                    break;
            }
        }
    }
    return poolAPIUrl;
}

pool_data getPoolData(void){
    if((mPoolUpdate == 0) || (millis() - mPoolUpdate > UPDATE_POOL_min * 60 * 1000)){
        if (WiFi.status() != WL_CONNECTED) return pData;
        if (!g_pool_has_stats_api) {
            char best_diff_string[16] = {0};
            suffix_string(best_diff, best_diff_string, 16, 0);
            pData.bestDifficulty = String(best_diff_string);
            pData.workersCount = 1;
            char worker_hash_s[16] = {0};
            // totalKHashes already includes Mhashes*1000 — original formula
            // was double-counting Mhashes (~2x inflated Total Hash Rate).
            uint64_t totalH = (uint64_t)totalKHashes * 1000ULL;
            double runTimeSec = upTime ? (double)upTime : 1.0;
            double avgHs = totalH / runTimeSec;
            suffix_string(avgHs, worker_hash_s, 16, 0);
            pData.workersHash = String(worker_hash_s);
            mPoolUpdate = millis();
            return pData;
        }
        if (ESP.getFreeHeap() < 15000) {
            return pData;
        }
        //Make first API call to get global hash and current difficulty
        HTTPClient http;
        http.setTimeout(10000);        
        try {          
          String btcWallet = Settings.BtcWallet;
          // Serial.println(btcWallet);
          if (btcWallet.indexOf(".")>0) btcWallet = btcWallet.substring(0,btcWallet.indexOf("."));
#ifdef SCREEN_WORKERS_ENABLE
          Serial.println("Pool API : " + poolAPIUrl+btcWallet);
          http.begin(poolAPIUrl+btcWallet);
#else
          http.begin(String(getPublicPool)+btcWallet);
#endif
          int httpCode = http.GET();
          if (httpCode == HTTP_CODE_OK) {
              String payload = http.getString();
              // Use stack StaticJsonDocument with filter (matches upstream
              // strategy — no heap allocation per fetch). Filter accepts
              // both public-pool and CKpool key shapes.
              StaticJsonDocument<512> filter;
              filter["bestDifficulty"] = true;
              filter["bestshare"]      = true;
              filter["bestever"]       = true;
              filter["workersCount"]   = true;
              filter["workers"]        = true;
              filter["worker"]         = true;
              filter["worker"][0]["sessionId"]  = true;
              filter["worker"][0]["hashRate"]   = true;
              filter["worker"][0]["hashrate1m"] = true;
              filter["worker"][0]["hashrate5m"] = true;
              filter["workers"][0]["sessionId"]  = true;
              filter["workers"][0]["hashRate"]   = true;
              filter["workers"][0]["hashrate1m"] = true;
              filter["workers"][0]["hashrate5m"] = true;
              StaticJsonDocument<3072> doc;
              DeserializationError jerr = deserializeJson(doc, payload, DeserializationOption::Filter(filter));
              if (jerr) {
                  Serial.printf("####### Pool Data JSON parse error: %s — fallback to local stats\n", jerr.c_str());
                  {
                      char best_diff_string[16] = {0};
                      suffix_string(best_diff, best_diff_string, 16, 0);
                      pData.bestDifficulty = String(best_diff_string);
                      pData.workersCount = 1;
                      uint64_t totalH = (uint64_t)totalKHashes * 1000ULL;
                      double runTimeSec = upTime ? (double)upTime : 1.0;
                      double avgHs = totalH / runTimeSec;
                      char worker_hash_s[16] = {0};
                      suffix_string(avgHs, worker_hash_s, 16, 0);
                      pData.workersHash = String(worker_hash_s);
                  }
                  mPoolUpdate = millis();
                  http.end();
                  return pData;
              }

              double bd = 0.0;
              if      (doc.containsKey("bestDifficulty")) bd = doc["bestDifficulty"].as<double>();
              else if (doc.containsKey("bestshare"))      bd = doc["bestshare"].as<double>();
              else if (doc.containsKey("bestever"))       bd = doc["bestever"].as<double>();
              if (bd > 0.0) {
                  char best_diff_string[16] = {0};
                 if (bd >= 1e9 && bd < 1e12) {
                      snprintf(best_diff_string, sizeof(best_diff_string), "%.0fM", bd / 1e6);
                  } else {
                      suffix_string(bd, best_diff_string, 16, 0);
                  }
                  pData.bestDifficulty = String(best_diff_string);
              }

              JsonVariant wv = doc["workers"];
              bool workers_is_array = wv.is<JsonArray>();
              if (!workers_is_array) wv = doc["worker"];

              if (doc.containsKey("workersCount")) {
                  pData.workersCount = doc["workersCount"].as<int>();
              } else if (!workers_is_array && doc["workers"].is<int>()) {
                  pData.workersCount = doc["workers"].as<int>();
              } else if (wv.is<JsonArray>()) {
                  pData.workersCount = wv.size();
              }

              float totalhashs = 0.0f;
              if (wv.is<JsonArray>()) {
                  for (JsonObject worker : wv.as<JsonArray>()) {
                      if (worker.containsKey("hashRate")) {
                          totalhashs += worker["hashRate"].as<double>();
                      } else if (worker.containsKey("hashrate1m")) {
                          double h = parse_hashrate_suffix(worker["hashrate1m"].as<const char*>());
                          if (h <= 0.0 && worker.containsKey("hashrate5m")) {
                              h = parse_hashrate_suffix(worker["hashrate5m"].as<const char*>());
                          }
                          totalhashs += h;
                      }
                  }
              }
              if (totalhashs <= 0.0f) {
                  uint64_t totalH = (uint64_t)totalKHashes * 1000ULL;
                  double runTimeSec = upTime ? (double)upTime : 1.0;
                  totalhashs = (float)(totalH / runTimeSec);
              }
              char totalhashs_s[16] = {0};
              suffix_string(totalhashs, totalhashs_s, 16, 0);
              pData.workersHash = String(totalhashs_s);
              doc.clear();
              mPoolUpdate = millis();
              Serial.println("\n####### Pool Data OK!");
          } else {
              Serial.printf("\n####### Pool Data HTTP %d — fallback to local stats\n", httpCode);
              {
                  char best_diff_string[16] = {0};
                  suffix_string(best_diff, best_diff_string, 16, 0);
                  pData.bestDifficulty = String(best_diff_string);
                  pData.workersCount = 1;
                  uint64_t totalH = (uint64_t)totalKHashes * 1000ULL;
                  double runTimeSec = upTime ? (double)upTime : 1.0;
                  double avgHs = totalH / runTimeSec;
                  char worker_hash_s[16] = {0};
                  suffix_string(avgHs, worker_hash_s, 16, 0);
                  pData.workersHash = String(worker_hash_s);
              }
              mPoolUpdate = millis();
              http.end();
              return pData;
          }
          http.end();
        } catch(...) {
          Serial.println("####### Pool Error — fallback to local stats");
          {
              char best_diff_string[16] = {0};
              suffix_string(best_diff, best_diff_string, 16, 0);
              pData.bestDifficulty = String(best_diff_string);
              pData.workersCount = 1;
              uint64_t totalH = (uint64_t)totalKHashes * 1000ULL;
              double runTimeSec = upTime ? (double)upTime : 1.0;
              double avgHs = totalH / runTimeSec;
              char worker_hash_s[16] = {0};
              suffix_string(avgHs, worker_hash_s, 16, 0);
              pData.workersHash = String(worker_hash_s);
          }
          mPoolUpdate = millis();
          http.end();
          return pData;
        }
    }
    return pData;
}
