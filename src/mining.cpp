#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <nvs.h>
//#include "ShaTests/nerdSHA256.h"
#include "ShaTests/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "timeconst.h"
#include "drivers/displays/display.h"
#include "drivers/storage/storage.h"
#include <mutex>
#include <list>
#include <map>
#include "mbedtls/sha256.h"
#include "i2c_master.h"
#include "axehub_metrics.h"
#include "axehub_webhook.h"
#include "axehub_sha_fast.h"

//10 Jobs per second
#define NONCE_PER_JOB_SW 4096
#define NONCE_PER_JOB_HW 16*1024

//#define I2C_SLAVE

//#define SHA256_VALIDATE
//#define RANDOM_NONCE
#define RANDOM_NONCE_MASK 0xFFFFC000

#ifdef HARDWARE_SHA265
#include <sha/sha_dma.h>
#include <hal/sha_hal.h>
#include <hal/sha_ll.h>

#if defined(CONFIG_IDF_TARGET_ESP32)
#include <sha/sha_parallel_engine.h>
#endif

#endif

nvs_handle_t stat_handle;

uint32_t templates = 0;
uint32_t hashes = 0;
uint32_t Mhashes = 0;
uint32_t totalKHashes = 0;
uint32_t elapsedKHs = 0;
uint64_t upTime = 0;

volatile uint32_t shares; // increase if blockhash has 32 bits of zeroes
volatile uint32_t valids; // increased if blockhash <= target

// Track best diff
double best_diff = 0.0;

// Variables to hold data from custom textboxes
//Track mining stats in non volatile memory
extern TSettings Settings;

IPAddress serverIP(1, 1, 1, 1); //Temporally save poolIPaddres

//Global work data 
static WiFiClient client;
static miner_data mMiner; //Global miner data (Create a miner class TODO)
mining_subscribe mWorker;
mining_job mJob;
monitor_data mMonitor;
static bool volatile isMinerSuscribed = false;
unsigned long mLastTXtoPool = millis();

// Primary vs fallback pool selection state. Flipped by fallback-activation
// logic inside checkPoolConnection and by direct callers of
// mining_invalidate_pool_connection() when they change primary config.
static volatile bool s_using_fallback = false;
static volatile int  s_connect_failures = 0;

// How many consecutive connect attempts on the currently-active target may
// fail before we flip to the other target (if it has anything configured).
#define AXEHUB_POOL_FAILOVER_THRESHOLD 3

static inline bool _fallback_configured() {
    return Settings.FallbackPoolAddress.length() > 0 && Settings.FallbackPoolPort > 0;
}

static inline const String& _active_pool_address() {
    return s_using_fallback ? Settings.FallbackPoolAddress : Settings.PoolAddress;
}

static inline int _active_pool_port() {
    return s_using_fallback ? Settings.FallbackPoolPort : Settings.PoolPort;
}

static inline const char* _active_pool_user() {
    return s_using_fallback ? Settings.FallbackBtcWallet : Settings.BtcWallet;
}

static inline const char* _active_pool_pass() {
    return s_using_fallback ? Settings.FallbackPoolPassword : Settings.PoolPassword;
}

bool mining_is_using_fallback() {
    return s_using_fallback;
}

void mining_invalidate_pool_connection() {
    serverIP = IPAddress(1, 1, 1, 1);
    client.stop();
    isMinerSuscribed = false;
    axehub_metrics_set_pool_connected(false);
    s_connect_failures = 0;
}

int saveIntervals[7] = {5 * 60, 15 * 60, 30 * 60, 1 * 3600, 3 * 3600, 6 * 3600, 12 * 3600};
int saveIntervalsSize = sizeof(saveIntervals)/sizeof(saveIntervals[0]);
int currentIntervalIndex = 0;

bool checkPoolConnection(void) {

  if (client.connected()) {
    s_connect_failures = 0;
    return true;
  }

  isMinerSuscribed = false;
  axehub_metrics_set_pool_connected(false);

  const String& targetAddr = _active_pool_address();
  int           targetPort = _active_pool_port();
  Serial.printf("Client not connected, trying to connect (%s:%d, fallback=%d)...\n",
                targetAddr.c_str(), targetPort, (int)s_using_fallback);

  //Resolve first time pool DNS and save IP
  if(serverIP == IPAddress(1,1,1,1)) {
    WiFi.hostByName(targetAddr.c_str(), serverIP);
    Serial.printf("Resolved DNS and save ip (first time) got: %s\n", serverIP.toString());
  }

  //Try connecting pool IP
  if (!client.connect(serverIP, targetPort)) {
    Serial.println("Imposible to connect to : " + targetAddr);
    WiFi.hostByName(targetAddr.c_str(), serverIP);
    Serial.printf("Resolved DNS got: %s\n", serverIP.toString());
    s_connect_failures++;
    // After too many failures on the current target, flip to the other one
    // (primary↔fallback) if it has anything configured. Next invocation
    // will retry with the new Settings.
    if (s_connect_failures >= AXEHUB_POOL_FAILOVER_THRESHOLD && _fallback_configured()) {
        s_using_fallback = !s_using_fallback;
        s_connect_failures = 0;
        serverIP = IPAddress(1, 1, 1, 1);
        Serial.printf("[AxeHub] Pool failover — now using %s pool\n",
                      s_using_fallback ? "fallback" : "primary");
        if (s_using_fallback) {
            axehub_webhook_emit("fallback_activated",
                String("{\"reason\":\"connect_failed\",\"failures\":") +
                AXEHUB_POOL_FAILOVER_THRESHOLD + "}");
        }
    }
    return false;
  }

  s_connect_failures = 0;
  return true;
}

//Implements a socketKeepAlive function and 
//checks if pool is not sending any data to reconnect again.
//Even connection could be alive, pool could stop sending new job NOTIFY
unsigned long mStart0Hashrate = 0;
bool checkPoolInactivity(unsigned int keepAliveTime, unsigned long inactivityTime){ 

    unsigned long currentKHashes = (Mhashes*1000) + hashes/1000;
    unsigned long elapsedKHs = currentKHashes - totalKHashes;

    uint32_t time_now = millis();

    // If no shares sent to pool
    // send something to pool to hold socket oppened
    if (time_now < mLastTXtoPool) //32bit wrap
      mLastTXtoPool = time_now;
    if ( time_now > mLastTXtoPool + keepAliveTime)
    {
      mLastTXtoPool = time_now;
      Serial.println("  Sending  : KeepAlive suggest_difficulty");
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
    }

    if(elapsedKHs == 0){
      //Check if hashrate is 0 during inactivityTIme
      if(mStart0Hashrate == 0) mStart0Hashrate  = time_now; 
      if((time_now-mStart0Hashrate) > inactivityTime) { mStart0Hashrate=0; return true;}
      return false;
    }

  mStart0Hashrate = 0;
  return false;
}

struct JobRequest
{
  uint32_t id;
  uint32_t nonce_start;
  uint32_t nonce_count;
  double difficulty;
  uint8_t sha_buffer[128];
  uint32_t midstate[8];
  uint32_t bake[16];
};

struct JobResult
{
  uint32_t id;
  uint32_t nonce;
  uint32_t nonce_count;
  double difficulty;
  uint8_t hash[32];
};

static std::mutex s_job_mutex;
std::list<std::shared_ptr<JobRequest>> s_job_request_list_sw;
#ifdef HARDWARE_SHA265
std::list<std::shared_ptr<JobRequest>> s_job_request_list_hw;
#endif
std::list<std::shared_ptr<JobResult>> s_job_result_list;
static volatile uint8_t s_working_current_job_id = 0xFF;

static void JobPush(std::list<std::shared_ptr<JobRequest>> &job_list,  uint32_t id, uint32_t nonce_start, uint32_t nonce_count, double difficulty,
                    const uint8_t* sha_buffer, const uint32_t* midstate, const uint32_t* bake)
{
  std::shared_ptr<JobRequest> job = std::make_shared<JobRequest>();
  job->id = id;
  job->nonce_start = nonce_start;
  job->nonce_count = nonce_count;
  job->difficulty = difficulty;
  memcpy(job->sha_buffer, sha_buffer, sizeof(job->sha_buffer));
  memcpy(job->midstate, midstate, sizeof(job->midstate));
  memcpy(job->bake, bake, sizeof(job->bake));
  job_list.push_back(job);
}

struct Submition
{
  double diff;
  bool is32bit;
  bool isValid;
};

static void MiningJobStop(uint32_t &job_pool, std::map<uint32_t, std::shared_ptr<Submition>> & submition_map)
{
  {
    std::lock_guard<std::mutex> lock(s_job_mutex);
    s_job_result_list.clear();
    s_job_request_list_sw.clear();
    #ifdef HARDWARE_SHA265
    s_job_request_list_hw.clear();
    #endif
  }
  s_working_current_job_id = 0xFF;
  job_pool = 0xFFFFFFFF;
  submition_map.clear();
}

#ifdef RANDOM_NONCE
uint64_t s_random_state = 1;
static uint32_t RandomGet()
{
    s_random_state += 0x9E3779B97F4A7C15ull;
    uint64_t z = s_random_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

#endif

void runStratumWorker(void *name) {

// TEST: https://bitcoin.stackexchange.com/questions/22929/full-example-data-for-scrypt-stratum-client

  Serial.println("");
  Serial.printf("\n[WORKER] Started. Running %s on core %d\n", (char *)name, xPortGetCoreID());

  #ifdef DEBUG_MEMORY
  Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
  #endif

  std::map<uint32_t, std::shared_ptr<Submition>> s_submition_map;

#ifdef I2C_SLAVE
  std::vector<uint8_t> i2c_slave_vector;

  //scan for i2c slaves
  if (i2c_master_start() == 0)
    i2c_slave_vector = i2c_master_scan(0x0, 0x80);
  Serial.printf("Found %d slave workers\n", i2c_slave_vector.size());
  if (!i2c_slave_vector.empty())
  {
    Serial.print("  Workers: ");
    for (size_t n = 0; n < i2c_slave_vector.size(); ++n)
      Serial.printf("0x%02X,", (uint32_t)i2c_slave_vector[n]);
    Serial.println("");
  }
#endif

  // connect to pool  
  double currentPoolDifficulty = DEFAULT_DIFFICULTY;
  uint32_t nonce_pool = 0;
  uint32_t job_pool = 0xFFFFFFFF;
  uint32_t last_job_time = millis();

  while(true) {
      
    if(WiFi.status() != WL_CONNECTED){
      // WiFi is disconnected, so reconnect now
      mMonitor.NerdStatus = NM_Connecting;
      MiningJobStop(job_pool, s_submition_map);
      WiFi.reconnect();
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    } 

    if(!checkPoolConnection()){
      //If server is not reachable add random delay for connection retries
      //Generate value between 1 and 60 secs
      MiningJobStop(job_pool, s_submition_map);
      vTaskDelay(((1 + rand() % 60) * 1000) / portTICK_PERIOD_MS);
      continue;
    }

    if(!isMinerSuscribed)
    {
      //Stop miner current jobs
      mWorker = init_mining_subscribe();

      // Reset to LOW so pool's vardiff starts from baseline. If we re-suggest
      // the previous high value (e.g. 42), pool keeps that and we never get
      // shares accepted (1 MH/s × diff 42 ≈ 47h per share).
      currentPoolDifficulty = DEFAULT_DIFFICULTY;

      // STEP 1: Pool server connection (SUBSCRIBE)
      if(!tx_mining_subscribe(client, mWorker)) {
        client.stop();
        MiningJobStop(job_pool, s_submition_map);
        continue;
      }

      strcpy(mWorker.wName, _active_pool_user());
      strcpy(mWorker.wPass, _active_pool_pass());

      // STEP 2: Suggest pool difficulty BEFORE authorize. Stratum extension
      // (BIP/ckpool/public-pool) requires suggest to arrive before authorize,
      // otherwise pool sets initial vardiff during authorize and ignores
      // later suggests until next reconnect.
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);

      // STEP 3: Pool authorize work (Block Info)
      tx_mining_auth(client, mWorker.wName, mWorker.wPass);

      isMinerSuscribed=true;
      axehub_metrics_set_pool_connected(true);
      uint32_t time_now = millis();
      mLastTXtoPool = time_now;
      last_job_time = time_now;
    }

    //Check if pool is down for almost 5minutes and then restart connection with pool (1min=600000ms)
    if(checkPoolInactivity(KEEPALIVE_TIME_ms, POOLINACTIVITY_TIME_ms)){
      //Restart connection
      Serial.println("  Detected more than 2 min without data form stratum server. Closing socket and reopening...");
      client.stop();
      isMinerSuscribed=false;
      axehub_metrics_set_pool_connected(false);
      MiningJobStop(job_pool, s_submition_map);
      continue;
    }

    {
      uint32_t time_now = millis();
      if (time_now < last_job_time) //32bit wrap
        last_job_time = time_now;
      if (time_now >= last_job_time + 10*60*1000)  //10minutes without job
      {
        client.stop();
        isMinerSuscribed=false;
        axehub_metrics_set_pool_connected(false);
        MiningJobStop(job_pool, s_submition_map);
        continue;
      }
    }

    uint32_t hw_midstate[8];
    uint32_t diget_mid[8];
    uint32_t bake[16];
    #if defined(CONFIG_IDF_TARGET_ESP32)
    uint8_t sha_buffer_swap[128];
    #endif

    //Read pending messages from pool
    while(client.connected() && client.available())
    {
      String line = client.readStringUntil('\n');
      axehub_metrics_pool_recv_marker();
      //Serial.println("  Received message from pool");
      stratum_method result = parse_mining_method(line);
      switch (result)
      {
          case MINING_NOTIFY:         if(parse_mining_notify(line, mJob))
                                      {
                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            s_job_request_list_sw.clear();
                                            #ifdef HARDWARE_SHA265
                                            s_job_request_list_hw.clear();
                                            #endif
                                          }
                                          //Increse templates readed
                                          templates++;
                                          job_pool++;
                                          s_working_current_job_id = job_pool & 0xFF; //Terminate current job in thread

                                          last_job_time = millis();
                                          mLastTXtoPool = last_job_time;

                                          uint32_t mh = hashes/1000000;
                                          Mhashes += mh;
                                          hashes -= mh*1000000;

                                          //Prepare data for new jobs
                                          mMiner=calculateMiningData(mWorker, mJob);

                                          memset(mMiner.bytearray_blockheader+80, 0, 128-80);
                                          mMiner.bytearray_blockheader[80] = 0x80;
                                          mMiner.bytearray_blockheader[126] = 0x02;
                                          mMiner.bytearray_blockheader[127] = 0x80;

                                          nerd_mids(diget_mid, mMiner.bytearray_blockheader);
                                          nerd_sha256_bake(diget_mid, mMiner.bytearray_blockheader+64, bake);

                                          #ifdef HARDWARE_SHA265
                                          #if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)
                                            esp_sha_acquire_hardware();
                                            sha_hal_hash_block(SHA2_256,  mMiner.bytearray_blockheader, 64/4, true);
                                            sha_hal_read_digest(SHA2_256, hw_midstate);
                                            esp_sha_release_hardware();
                                          #endif
                                          #endif

                                          #if defined(CONFIG_IDF_TARGET_ESP32)
                                          for (int i = 0; i < 32; ++i)
                                            ((uint32_t*)sha_buffer_swap)[i] = __builtin_bswap32(((const uint32_t*)(mMiner.bytearray_blockheader))[i]);
                                          #endif

                                          #ifdef RANDOM_NONCE
                                          nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                          #else
                                            #ifdef I2C_SLAVE
                                            if (!i2c_slave_vector.empty())
                                              nonce_pool = 0x10000000;
                                            else
                                            #endif
                                              nonce_pool = 0xDA54E700;  //nonce 0x00000000 is not possible, start from some random nonce
                                          #endif
                                          

                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            for (int i = 0; i < 4; ++ i)
                                            {
                                              #if 1
                                              JobPush( s_job_request_list_sw, job_pool, nonce_pool, NONCE_PER_JOB_SW, currentPoolDifficulty, mMiner.bytearray_blockheader, diget_mid, bake);
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_SW;
                                              #endif
                                              #endif
                                              #ifdef HARDWARE_SHA265
                                                #if defined(CONFIG_IDF_TARGET_ESP32)
                                                  JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, sha_buffer_swap, hw_midstate, bake);
                                                #else
                                                  JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, mMiner.bytearray_blockheader, hw_midstate, bake);
                                                #endif
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_HW;
                                              #endif
                                              #endif
                                            }
                                          }
                                          #ifdef I2C_SLAVE
                                          //Nonce for nonce_pool starts from 0x10000000
                                          //For i2c slave we give nonces from 0x20000000, that is 0x10000000 nonces per slave
                                          i2c_feed_slaves(i2c_slave_vector, job_pool & 0xFF, 0x20, currentPoolDifficulty, mMiner.bytearray_blockheader);
                                          #endif
                                      } else
                                      {
                                        Serial.println("Parsing error, need restart");
                                        client.stop();
                                        isMinerSuscribed=false;
                                        MiningJobStop(job_pool, s_submition_map);
                                      }
                                      break;
          case MINING_SET_DIFFICULTY: parse_mining_set_difficulty(line, currentPoolDifficulty);
                                      break;
          case STRATUM_SUCCESS:       {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          if (itt->second->diff > best_diff)
                                            best_diff = itt->second->diff;
                                          axehub_metrics_record_session_diff(itt->second->diff);
                                          // Full pool-accepted count for AxeHub API (`shares` global tracks the 32-bit-prefix subset).
                                          axehub_metrics_record_accept();
                                          if (Settings.WebhookShareAboveDiffThreshold > 0 &&
                                              itt->second->diff > Settings.WebhookShareAboveDiffThreshold) {
                                            String p = String("{\"diff\":") + String(itt->second->diff, 6) +
                                                       ",\"threshold\":" + String(Settings.WebhookShareAboveDiffThreshold, 6) + "}";
                                            axehub_webhook_emit("share_above_diff", p);
                                          }
                                          if (itt->second->is32bit)
                                            shares++;
                                          if (itt->second->isValid)
                                          {
                                            Serial.println("CONGRATULATIONS! Valid block found");
                                            valids++;
                                            String p = String("{\"valid_blocks\":") + valids +
                                                       ",\"diff\":" + String(itt->second->diff, 6) + "}";
                                            axehub_webhook_emit("block_found", p);
                                          }
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          case STRATUM_PARSE_ERROR:   {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          Serial.printf("Refuse submition %d\n", id);
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          default:                    Serial.println("  Parsed JSON: unknown"); break;

      }
    }

    std::list<std::shared_ptr<JobResult>> job_result_list;
    #ifdef I2C_SLAVE
    if (i2c_slave_vector.empty() || job_pool == 0xFFFFFFFF)
    {
      vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    } else
    {
      uint32_t time_start = millis();
      i2c_hit_slaves(i2c_slave_vector);
      vTaskDelay(5 / portTICK_PERIOD_MS);
      uint32_t nonces_done = 0;
      std::vector<uint32_t> nonce_vector = i2c_harvest_slaves(i2c_slave_vector, job_pool & 0xFF, nonces_done);
      hashes += nonces_done;
      for (size_t n = 0; n < nonce_vector.size(); ++n)
      {
        std::shared_ptr<JobResult> result = std::make_shared<JobResult>();
        ((uint32_t*)(mMiner.bytearray_blockheader+64+12))[0] = nonce_vector[n];
        if (nerd_sha256d_baked(diget_mid, mMiner.bytearray_blockheader+64, bake, result->hash))
        {
          result->id = job_pool;
          result->nonce = nonce_vector[n];
          result->nonce_count = 0;
          result->difficulty = diff_from_target(result->hash);
          job_result_list.push_back(result);
        }
      }
      uint32_t time_end = millis();
      //if (nonces_done > 16384)
        //Serial.printf("Harvest slaves in %dms hashes=%d\n", time_end - time_start, nonces_done);
      if (time_end > time_start)
      {
        uint32_t elapsed = time_end - time_start;
        if (elapsed < 50)
          vTaskDelay((50 - elapsed) / portTICK_PERIOD_MS);
      } else
        vTaskDelay(40 / portTICK_PERIOD_MS);
    }
    #else
    vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    #endif

    
    if (job_pool != 0xFFFFFFFF)
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      job_result_list.insert(job_result_list.end(), s_job_result_list.begin(), s_job_result_list.end());
      s_job_result_list.clear();

#if 1
      while (s_job_request_list_sw.size() < 4)
      {
        JobPush( s_job_request_list_sw, job_pool, nonce_pool, NONCE_PER_JOB_SW, currentPoolDifficulty, mMiner.bytearray_blockheader, diget_mid, bake);
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_SW;
        #endif
      }
#endif

      #ifdef HARDWARE_SHA265
      while (s_job_request_list_hw.size() < 4)
      {
        #if defined(CONFIG_IDF_TARGET_ESP32)
          JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, sha_buffer_swap, hw_midstate, bake);
        #else
          JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, mMiner.bytearray_blockheader, hw_midstate, bake);
        #endif
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_HW;
        #endif
      }
      #endif
    }

    while (!job_result_list.empty())
    {
      std::shared_ptr<JobResult> res = job_result_list.front();
      job_result_list.pop_front();

      hashes += res->nonce_count;
      if (res->difficulty > currentPoolDifficulty && job_pool == res->id && res->nonce != 0xFFFFFFFF)
      {
        if (!client.connected())
          break;
        unsigned long sumbit_id = 0;
        tx_mining_submit(client, mWorker, mJob, res->nonce, sumbit_id);
        Serial.print("   - Current diff share: "); Serial.println(res->difficulty,12);
        Serial.print("   - Current pool diff : "); Serial.println(currentPoolDifficulty,12);
        Serial.print("   - TX SHARE: ");
        for (size_t i = 0; i < 32; i++)
            Serial.printf("%02x", res->hash[i]);
        Serial.println("");
        mLastTXtoPool = millis();

        std::shared_ptr<Submition> submition = std::make_shared<Submition>();
        submition->diff = res->difficulty;
        submition->is32bit = (res->hash[29] == 0 && res->hash[28] == 0);
        if (submition->is32bit)
        {
          submition->isValid = checkValid(res->hash, mMiner.bytearray_target);
        } else
          submition->isValid = false;

        s_submition_map.insert(std::make_pair(sumbit_id, submition));
        if (s_submition_map.size() > 32)
          s_submition_map.erase(s_submition_map.begin());
      }
    }
  }
}

//////////////////THREAD CALLS///////////////////

void minerWorkerSw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerSw Task on core %d!\n", miner_id, xPortGetCoreID());

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint32_t wdt_counter = 0;
  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_sw.empty())
      {
        job = s_job_request_list_sw.front();
        s_job_request_list_sw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->difficulty = job->difficulty;
      result->nonce = 0xFFFFFFFF;
      result->id = job->id;
      result->nonce_count = job->nonce_count;
      uint8_t job_in_work = job->id & 0xFF;
      // Per-nonce cycle instrumentation — SW worker's actual hot-loop cost.
      // Bench-on-core-0 numbers don't match production sw_khs; this instruments
      // the real loop directly so we can see cycles/nonce in situ.
      static uint64_t s_sw_cycles_acc = 0;
      static uint64_t s_sw_nonces_acc = 0;
      static uint32_t s_sw_cycles_min = 0xFFFFFFFFu;
      static uint32_t s_sw_cycles_max = 0;
      static uint32_t s_sw_print_at   = 5000;
      auto rdcc = [](){ uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c; };

      for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        ((uint32_t*)(job->sha_buffer+64+12))[0] = job->nonce_start+n;

        uint32_t _t0 = rdcc();
        bool _hit = nerd_sha256d_baked(job->midstate, job->sha_buffer+64, job->bake, hash);
        uint32_t _dc = rdcc() - _t0;
        // Filter outliers (preempted by FreeRTOS context switch) — anything
        // > 50000 cycles is clearly a context-switch wallclock, not actual
        // SHA work, so excluded from the avg/min/max.
        if (_dc < 50000) {
          s_sw_cycles_acc += _dc;
          s_sw_nonces_acc++;
          if (_dc < s_sw_cycles_min) s_sw_cycles_min = _dc;
          if (_dc > s_sw_cycles_max) s_sw_cycles_max = _dc;
        }

        if (_hit)
        {
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            result->difficulty = diff_hash;
            result->nonce = job->nonce_start+n;
            memcpy(result->hash, hash, 32);
          }
        }

        if ( (uint16_t)(n & 0xFF) == 0 &&s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n+1;
          break;
        }
      }
      axehub_metrics_record_sw_hashes(result->nonce_count);

      if (s_sw_nonces_acc >= s_sw_print_at) {
        Serial.printf("[SW BENCH IN-PROD] %llu nonces, avg=%llu cyc/nonce, min=%u, max=%u\n",
                      (unsigned long long)s_sw_nonces_acc,
                      (unsigned long long)(s_sw_cycles_acc / s_sw_nonces_acc),
                      (unsigned)s_sw_cycles_min, (unsigned)s_sw_cycles_max);
        s_sw_cycles_acc = 0;
        s_sw_nonces_acc = 0;
        s_sw_cycles_min = 0xFFFFFFFFu;
        s_sw_cycles_max = 0;
      }
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#ifdef HARDWARE_SHA265

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

#pragma GCC push_options
#pragma GCC optimize("O3")

static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text, uint32_t nonce)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    REG_WRITE(&reg_addr_buf[0], data_words[0]);
    REG_WRITE(&reg_addr_buf[1], data_words[1]);
    REG_WRITE(&reg_addr_buf[2], data_words[2]);
#if 0
    REG_WRITE(&reg_addr_buf[3], nonce);
    //REG_WRITE(&reg_addr_buf[3], data_words[3]);    
    REG_WRITE(&reg_addr_buf[4], data_words[4]);
    REG_WRITE(&reg_addr_buf[5], data_words[5]);
    REG_WRITE(&reg_addr_buf[6], data_words[6]);
    REG_WRITE(&reg_addr_buf[7], data_words[7]);
    REG_WRITE(&reg_addr_buf[8], data_words[8]);
    REG_WRITE(&reg_addr_buf[9], data_words[9]);
    REG_WRITE(&reg_addr_buf[10], data_words[10]);
    REG_WRITE(&reg_addr_buf[11], data_words[11]);
    REG_WRITE(&reg_addr_buf[12], data_words[12]);
    REG_WRITE(&reg_addr_buf[13], data_words[13]);
    REG_WRITE(&reg_addr_buf[14], data_words[14]);
    REG_WRITE(&reg_addr_buf[15], data_words[15]);
#else
    REG_WRITE(&reg_addr_buf[3], nonce);
    REG_WRITE(&reg_addr_buf[4], 0x00000080);
    REG_WRITE(&reg_addr_buf[5], 0x00000000);
    REG_WRITE(&reg_addr_buf[6], 0x00000000);
    REG_WRITE(&reg_addr_buf[7], 0x00000000);
    REG_WRITE(&reg_addr_buf[8], 0x00000000);
    REG_WRITE(&reg_addr_buf[9], 0x00000000);
    REG_WRITE(&reg_addr_buf[10], 0x00000000);
    REG_WRITE(&reg_addr_buf[11], 0x00000000);
    REG_WRITE(&reg_addr_buf[12], 0x00000000);
    REG_WRITE(&reg_addr_buf[13], 0x00000000);
    REG_WRITE(&reg_addr_buf[14], 0x00000000);
    REG_WRITE(&reg_addr_buf[15], 0x80020000);
#endif
}

static inline void nerd_sha_ll_fill_text_block_sha256_inter()
{
  uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

  DPORT_INTERRUPT_DISABLE();
  REG_WRITE(&reg_addr_buf[0], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4));
  REG_WRITE(&reg_addr_buf[1], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4));
  REG_WRITE(&reg_addr_buf[2], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4));
  REG_WRITE(&reg_addr_buf[3], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4));
  REG_WRITE(&reg_addr_buf[4], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4));
  REG_WRITE(&reg_addr_buf[5], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4));
  REG_WRITE(&reg_addr_buf[6], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4));
  REG_WRITE(&reg_addr_buf[7], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4));
  DPORT_INTERRUPT_RESTORE();

  REG_WRITE(&reg_addr_buf[8], 0x00000080);
  REG_WRITE(&reg_addr_buf[9], 0x00000000);
  REG_WRITE(&reg_addr_buf[10], 0x00000000);
  REG_WRITE(&reg_addr_buf[11], 0x00000000);
  REG_WRITE(&reg_addr_buf[12], 0x00000000);
  REG_WRITE(&reg_addr_buf[13], 0x00000000);
  REG_WRITE(&reg_addr_buf[14], 0x00000000);
  REG_WRITE(&reg_addr_buf[15], 0x00010000);
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  ((uint32_t*)ptr)[7] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  DPORT_INTERRUPT_RESTORE();
}


static inline bool nerd_sha_ll_read_digest_if(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  uint32_t last = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  #if 1
  if ( (uint16_t)(last >> 16) != 0)
  {
    DPORT_INTERRUPT_RESTORE();
    return false;
  }
  #endif

  ((uint32_t*)ptr)[7] = last;
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  DPORT_INTERRUPT_RESTORE();
  return true;
}

static inline void nerd_sha_ll_write_digest(void *digest_state)
{
    uint32_t *digest_state_words = (uint32_t *)digest_state;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_H_BASE);

    REG_WRITE(&reg_addr_buf[0], digest_state_words[0]);
    REG_WRITE(&reg_addr_buf[1], digest_state_words[1]);
    REG_WRITE(&reg_addr_buf[2], digest_state_words[2]);
    REG_WRITE(&reg_addr_buf[3], digest_state_words[3]);
    REG_WRITE(&reg_addr_buf[4], digest_state_words[4]);
    REG_WRITE(&reg_addr_buf[5], digest_state_words[5]);
    REG_WRITE(&reg_addr_buf[6], digest_state_words[6]);
    REG_WRITE(&reg_addr_buf[7], digest_state_words[7]);
}

static inline void nerd_sha_hal_wait_idle()
{
    while (REG_READ(SHA_BUSY_REG))
    {}
}

//#define VALIDATION
void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHw Task on core %d!\n", miner_id, xPortGetCoreID());

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t interResult[64];
  uint8_t hash[32];
  uint8_t digest_mid[32];
  uint8_t sha_buffer[64];
  uint32_t wdt_counter = 0;

#ifdef VALIDATION
  uint8_t doubleHash[32];
  uint32_t diget_mid[8];
  uint32_t bake[16];
#endif

  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->id = job->id;
      result->nonce = 0xFFFFFFFF;
      result->nonce_count = job->nonce_count;
      result->difficulty = job->difficulty;
      uint8_t job_in_work = job->id & 0xFF;
      memcpy(digest_mid, job->midstate, sizeof(digest_mid));
      memcpy(sha_buffer, job->sha_buffer+64, sizeof(sha_buffer));
#ifdef VALIDATION
      nerd_mids(diget_mid, job->sha_buffer);
      nerd_sha256_bake(diget_mid, job->sha_buffer+64, bake);
#endif

      esp_sha_acquire_hardware();
      REG_WRITE(SHA_MODE_REG, SHA2_256);

#ifdef AXEHUB_HW_FAST
      // Fast path: persistent-zeros + memw-discipline + per-register-address
      // technique. Runs the inner loop in batches; each batch returns when a
      // candidate hash is found (filter passes) or nonce range is exhausted.
      axehub_sha_fast_init_job();
      const uint32_t *midstate_words = (const uint32_t *)digest_mid;
      const uint32_t *block2_words   = (const uint32_t *)sha_buffer;
      uint32_t fast_nonce = job->nonce_start;
      uint32_t fast_end   = job->nonce_start + job->nonce_count;
      volatile bool   fast_active = true;
      volatile uint32_t fast_counter = 0;
      while (fast_nonce < fast_end) {
          if ((uint8_t)(fast_nonce & 0xFF) == 0 && s_working_current_job_id != job_in_work) {
              break;
          }
          uint32_t batch_end = fast_nonce + 4096;   // larger batch amortises per-call overhead
          if (batch_end > fast_end) batch_end = fast_end;
          uint8_t fast_hash[32] __attribute__((aligned(4)));
#ifdef AXEHUB_HW_ASM_PURE
          uint32_t nonce_before = fast_nonce;
          int32_t pret = axehub_sha_asm_s3_mine_batch(
              midstate_words, block2_words, &fast_nonce, batch_end, fast_hash);
          bool candidate = (pret != 0);
          if (candidate) {
              fast_counter += (fast_nonce - nonce_before) + 1;
              fast_nonce++;  // advance past candidate to match mining.cpp convention
          } else {
              fast_counter += (fast_nonce - nonce_before);
          }
          (void)fast_active;  // mining_active polled OUTSIDE pure-asm (between batches)
#elif defined(AXEHUB_HW_ASM)
          bool candidate = axehub_sha_fast_mine_batch_asm(
              midstate_words, block2_words, &fast_nonce, batch_end,
              fast_hash, &fast_counter, &fast_active);
#else
          bool candidate = axehub_sha_fast_mine_batch(
              midstate_words, block2_words, &fast_nonce, batch_end,
              fast_hash, &fast_counter, &fast_active);
#endif
          if (candidate) {
              double diff_hash = diff_from_target(fast_hash);
              if (diff_hash > result->difficulty) {
                  if (isSha256Valid(fast_hash)) {
                      result->difficulty = diff_hash;
                      result->nonce = fast_nonce - 1;  // candidate is the prior nonce
                      memcpy(result->hash, fast_hash, sizeof(fast_hash));
                  }
              }
          }
      }
      result->nonce_count = fast_nonce - job->nonce_start;
      esp_sha_release_hardware();
      axehub_metrics_record_hw_hashes(result->nonce_count);
#else
      uint32_t nend = job->nonce_start + job->nonce_count;
      for (uint32_t n = job->nonce_start; n < nend; ++n)
      {
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_write_digest(digest_mid);
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256(sha_buffer, n);
        //sha_ll_continue_block(SHA2_256);
        REG_WRITE(SHA_CONTINUE_REG, 1);
        
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256_inter();
        //sha_ll_start_block(SHA2_256);
        REG_WRITE(SHA_START_REG, 1);
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        if (nerd_sha_ll_read_digest_if(hash))
        {
          //Serial.printf("Hw 16bit Share, nonce=0x%X\n", n);
#ifdef VALIDATION
          //Validation
          ((uint32_t*)(job->sha_buffer+64+12))[0] = n;
          nerd_sha256d_baked(diget_mid, job->sha_buffer+64, bake, doubleHash);
          for (int i = 0; i < 32; ++i)
          {
            if (hash[i] != doubleHash[i])
            {
              Serial.println("***HW sha256 esp32s3 bug detected***");
              break;
            }
          }
#endif
          //~5 per second
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            if (isSha256Valid(hash))
            {
              result->difficulty = diff_hash;
              result->nonce = n;
              memcpy(result->hash, hash, sizeof(hash));
            }
          }
        }
        if (
             (uint8_t)(n & 0xFF) == 0 &&
             s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n-job->nonce_start+1;
          break;
        }
      }
      esp_sha_release_hardware();
      axehub_metrics_record_hw_hashes(result->nonce_count);
#endif // !AXEHUB_HW_FAST
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#pragma GCC pop_options

#endif  //#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

#if defined(CONFIG_IDF_TARGET_ESP32)

// ESP32 classic — TEXT overlap canary
// On ESP32-S3 we verified the SHA peripheral snapshots TEXT at trigger time so
// it's safe to write TEXT for the next block while the current block is still
// computing. The classic SHA peripheral has different architecture (TEXT is
// both input and output, internal state separate) so the same property may not
// hold. This canary tests it: hash a known input cleanly, then hash again and
// stomp TEXT[10] mid-compute. If outputs match, peripheral snapshots TEXT;
// if they differ, peripheral reads TEXT during compute and overlap is unsafe.
static bool s_classic_overlap_safe = false;
static bool s_classic_overlap_ran  = false;

void axehub_classic_overlap_canary(void)
{
    volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
    static const uint32_t test_input[16] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444,
        0x55555555, 0x66666666, 0x77777777, 0x88888888,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000200,
    };
    uint32_t h_clean[8];
    uint32_t h_stomp[8];

    esp_sha_lock_engine(SHA2_256);

    // Clean run
    for (int i = 0; i < 16; ++i) text[i] = test_input[i];
    sha_ll_start_block(SHA2_256);
    while (DPORT_REG_READ(SHA_256_BUSY_REG)) {}
    sha_ll_load(SHA2_256);
    for (int i = 0; i < 8; ++i) h_clean[i] = text[i];

    // Stomped run #1 — same input, stomp TEXT[10] IMMEDIATELY after trigger
    for (int i = 0; i < 16; ++i) text[i] = test_input[i];
    sha_ll_start_block(SHA2_256);
    text[10] = 0xDEADBEEF;     // ATTACK in cycle 0-1 after trigger
    while (DPORT_REG_READ(SHA_256_BUSY_REG)) {}
    sha_ll_load(SHA2_256);
    for (int i = 0; i < 8; ++i) h_stomp[i] = text[i];

    // Stomped run #2 — delay 8 cycles (5 nops) BEFORE stomp. Tests if peripheral
    // snapshots TEXT only in the first few cycles after trigger (peripheral
    // observed overlap pattern would imply this).
    uint32_t h_delayed[8];
    for (int i = 0; i < 16; ++i) text[i] = test_input[i];
    sha_ll_start_block(SHA2_256);
    asm volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n" ::: "memory");
    text[10] = 0xCAFEBABEU;    // ATTACK after ~8 cycle delay
    while (DPORT_REG_READ(SHA_256_BUSY_REG)) {}
    sha_ll_load(SHA2_256);
    for (int i = 0; i < 8; ++i) h_delayed[i] = text[i];

    esp_sha_unlock_engine(SHA2_256);

    bool stomp_immediate_safe = true;
    bool stomp_delayed_safe   = true;
    for (int i = 0; i < 8; ++i) {
        if (h_clean[i] != h_stomp[i])   stomp_immediate_safe = false;
        if (h_clean[i] != h_delayed[i]) stomp_delayed_safe   = false;
    }
    s_classic_overlap_safe = stomp_delayed_safe;  // delayed write is the realistic case
    s_classic_overlap_ran = true;
    Serial.printf("[AxeHub] CLASSIC overlap canary:\n");
    Serial.printf("  immediate stomp: %s (clean h0=%08x stomp h0=%08x)\n",
                  stomp_immediate_safe ? "SAFE" : "UNSAFE", h_clean[0], h_stomp[0]);
    Serial.printf("  delayed  stomp: %s (clean h0=%08x stomp h0=%08x)\n",
                  stomp_delayed_safe   ? "SAFE" : "UNSAFE", h_clean[0], h_delayed[0]);
}

// -O3 for HW SHA fast path inline helpers + minerWorkerHw below.
#pragma GCC push_options
#pragma GCC optimize("O3")

// ESP32 classic optimisation:
// The DPORT_INTERRUPT_DISABLE / DPORT_SEQUENCE_REG_READ wrappers exist to work
// around the DPORT bus access erratum on early ESP32 silicon revisions (ECO V0
// / V1). Our chip is rev v3.1 — the erratum is fixed in silicon. Each
// DPORT_INTERRUPT_DISABLE pair is a heavy spinlock that pessimises the hot
// loop. Plain REG_READ via the volatile pointer is safe on rev v3+.
static inline bool nerd_sha_ll_read_digest_swap_if(void* ptr)
{
  volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
  uint32_t fin = text[7];
  // [axehub fix] Tightened from `(fin & 0xFFFF) != 0` to `fin != 0`. The
  // 16-bit version checked low 16 bits of text[7] (which after bswap32
  // land at bytes 28..29 of the stored hash — the *middle* bytes of the
  // high uint32). Bytes 30..31 (the actual MSB per diff_from_target's
  // LE-256 convention) were left random → pool computed diff ~e-10 →
  // rejected as "Difficulty too low". Requiring the full word to be zero
  // guarantees bytes 28..31 all zero ⇒ diff ≥ ~1e-5 minimum, matching
  // typical pool session diff floors. Confirmed in field: 0 reject.
  if (fin != 0)
    return false;
  ((uint32_t*)ptr)[7] = __builtin_bswap32(fin);
  ((uint32_t*)ptr)[0] = __builtin_bswap32(text[0]);
  ((uint32_t*)ptr)[1] = __builtin_bswap32(text[1]);
  ((uint32_t*)ptr)[2] = __builtin_bswap32(text[2]);
  ((uint32_t*)ptr)[3] = __builtin_bswap32(text[3]);
  ((uint32_t*)ptr)[4] = __builtin_bswap32(text[4]);
  ((uint32_t*)ptr)[5] = __builtin_bswap32(text[5]);
  ((uint32_t*)ptr)[6] = __builtin_bswap32(text[6]);
  return true;
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
  ((uint32_t*)ptr)[0] = text[0];
  ((uint32_t*)ptr)[1] = text[1];
  ((uint32_t*)ptr)[2] = text[2];
  ((uint32_t*)ptr)[3] = text[3];
  ((uint32_t*)ptr)[4] = text[4];
  ((uint32_t*)ptr)[5] = text[5];
  ((uint32_t*)ptr)[6] = text[6];
  ((uint32_t*)ptr)[7] = text[7];
}

static inline void nerd_sha_hal_wait_idle()
{
    // Plain volatile load — DPORT erratum wrapper is unnecessary on rev v3.1+.
    // Compiles to a tight l32i + bnez loop; vs DPORT_REG_READ which may include
    // atomic-sequence instrumentation on old silicon.
    volatile uint32_t * const busy = (volatile uint32_t *)SHA_256_BUSY_REG;
    while (*busy)
    {}
}

static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
}

static inline void nerd_sha_ll_fill_text_block_sha256_upper(const void *input_text, uint32_t nonce)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = __builtin_bswap32(nonce);
#if 1
    reg_addr_buf[4]  = 0x80000000;
    reg_addr_buf[5]  = 0x00000000;
    reg_addr_buf[6]  = 0x00000000;
    reg_addr_buf[7]  = 0x00000000;
    reg_addr_buf[8]  = 0x00000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000280;
#else
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
#endif
}

static inline void nerd_sha_ll_fill_text_block_sha256_double()
{
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

#if 0
    //No change
    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
#endif
    reg_addr_buf[8]  = 0x80000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000100;
}

void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHwEsp32D Task on core %d!\n", miner_id, xPortGetCoreID());

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint8_t sha_buffer[128];

  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->id = job->id;
      result->nonce = 0xFFFFFFFF;
      result->nonce_count = job->nonce_count;
      result->difficulty = job->difficulty;
      uint8_t job_in_work = job->id & 0xFF;
      memcpy(sha_buffer, job->sha_buffer, 80);

      esp_sha_lock_engine(SHA2_256);


      // C path — three optimisations:
      //   1. OVERLAP 1: write block-2 TEXT input immediately after start_block
      //      for block 1 (peripheral snapshots TEXT at trigger).
      //   2. Reduced inter-padding writes: only TEXT[8] and TEXT[15] differ
      //      between block-2 residual padding and inter padding (TEXT[9..14]
      //      already zero from block-2 setup).
      //   3. Skip final sha_ll_load: peripheral writes inter digest directly
      //      to TEXT[0..7] after compute.
      // First iteration: write full block-1 input. Subsequent iterations write
      // only TEXT[0..7] because TEXT[8..15] was pre-filled during the previous
      // iter's inter compute (OVERLAP 3).
      uint32_t * const _sha_text = (uint32_t *)SHA_TEXT_BASE;
      const uint32_t *src = (const uint32_t *)sha_buffer;
      const uint32_t *src2 = (const uint32_t *)(sha_buffer+64);  // block-2 input upper half

      // OVERLAP 2: block-1 SHA_START moved to end of loop body so block-1
      // computes during the next iter's block-2 TEXT fill at top of loop.
      // Pre-loop kicks off iter 0's block-1 with full TEXT fill.
      _sha_text[0]  = src[0];  _sha_text[1]  = src[1];
      _sha_text[2]  = src[2];  _sha_text[3]  = src[3];
      _sha_text[4]  = src[4];  _sha_text[5]  = src[5];
      _sha_text[6]  = src[6];  _sha_text[7]  = src[7];
      _sha_text[8]  = src[8];  _sha_text[9]  = src[9];
      _sha_text[10] = src[10]; _sha_text[11] = src[11];
      _sha_text[12] = src[12]; _sha_text[13] = src[13];
      _sha_text[14] = src[14]; _sha_text[15] = src[15];
      sha_ll_start_block(SHA2_256);                   // block-1 iter 0

      // NOP-pad counts tuned per peripheral phase to avoid premature reads.
      #define NOPN(n) __asm__ __volatile__(".rept " #n "\n\tnop\n.endr")
      // Outer-inner loop split: job-change check moved to outer (every 256 iters)
      // so inner hot loop has no per-iter branch.
      uint32_t n = 0;
      const uint32_t n_total = job->nonce_count;
      bool _done = false;
      while (n < n_total && !_done) {
        uint32_t inner_end = n + 256;
        if (inner_end > n_total) inner_end = n_total;
        for (; n < inner_end; ++n)
        {
        // Inline bswap32(nonce) via asm — GCC emits callx8 __bswapsi2 even at
        // O3 (~15 cyc wasted). This inline is 7 instr ~7 cyc.
        uint32_t sn;
        {
          uint32_t nonce_raw = job->nonce_start + n;
          uint32_t tmp;
          __asm__ (
            "ssai 8\n\t"
            "src %[sn], %[nin], %[nin]\n\t"
            "ssai 24\n\t"
            "src %[tmp], %[nin], %[nin]\n\t"
            "and %[sn], %[sn], %[m1]\n\t"
            "and %[tmp], %[tmp], %[m2]\n\t"
            "or  %[sn], %[sn], %[tmp]\n\t"
            : [sn]"=&r"(sn), [tmp]"=&r"(tmp)
            : [nin]"r"(nonce_raw), [m1]"r"(0xFF00FF00), [m2]"r"(0x00FF00FF)
          );
        }

        // OVERLAP 2: block-1 (started at end of prev iter / pre-loop) is
        // computing now. Fill block-2 TEXT input via inline asm with base+offset.
        {
          uint32_t s0 = src2[0], s1 = src2[1], s2 = src2[2];
          __asm__ __volatile__ (
            "s32i.n %0, %4, 0\n\t"
            "s32i.n %1, %4, 4\n\t"
            "s32i.n %2, %4, 8\n\t"
            "s32i.n %3, %4, 12\n\t"
            "s32i.n %5, %4, 16\n\t"
            "s32i.n %6, %4, 20\n\t"
            "s32i.n %6, %4, 24\n\t"
            "s32i.n %6, %4, 28\n\t"
            "s32i.n %6, %4, 32\n\t"
            "s32i.n %6, %4, 36\n\t"
            "s32i.n %6, %4, 40\n\t"
            "s32i.n %6, %4, 44\n\t"
            "s32i.n %6, %4, 48\n\t"
            "s32i.n %6, %4, 52\n\t"
            "s32i.n %6, %4, 56\n\t"
            "s32i.n %7, %4, 60\n\t"
            :
            : "r"(s0), "r"(s1), "r"(s2), "r"(sn),
              "r"(_sha_text), "r"(0x80000000), "r"(0), "r"(0x00000280)
            : "memory"
          );
        }

        // Middle block: pre-CONTINUE NOPs + CONTINUE + OVERLAP 4 + post-CONTINUE
        // NOPs + LOAD + post-LOAD NOPs + START_inter + OVERLAP 3 (8 stores from
        // sha_buffer to TEXT[8..15] for next iter's block-1 upper half) + post-
        // START_inter NOPs (wait for inter compute). All via single base reg.
        __asm__ __volatile__ (
          ".rept 13\n\tnop\n.endr\n\t"          // Pre-CONTINUE 13 NOPs
          "s32i %[one],  %[base], 0x94\n\t"     // CONTINUE trigger
          "s32i.n %[c80], %[base], 32\n\t"      // OVERLAP 4: TEXT[8]=0x80000000
          "s32i.n %[c100],%[base], 60\n\t"      // OVERLAP 4: TEXT[15]=0x100
          ".rept 59\n\tnop\n.endr\n\t"          // Post-CONTINUE 59 NOPs
          "s32i %[one],  %[base], 0x98\n\t"     // LOAD trigger
          ".rept 9\n\tnop\n.endr\n\t"           // Post-LOAD 9 NOPs
          "s32i %[one],  %[base], 0x90\n\t"     // START_inter trigger
          // OVERLAP 3: TEXT[8..15] = sha_buffer[8..15] via l32i.n (3 cyc/store)
          "l32i.n a4, %[src], 32\n\t"  "s32i.n a4, %[base], 32\n\t"
          "l32i.n a4, %[src], 36\n\t"  "s32i.n a4, %[base], 36\n\t"
          "l32i.n a4, %[src], 40\n\t"  "s32i.n a4, %[base], 40\n\t"
          "l32i.n a4, %[src], 44\n\t"  "s32i.n a4, %[base], 44\n\t"
          "l32i.n a4, %[src], 48\n\t"  "s32i.n a4, %[base], 48\n\t"
          "l32i.n a4, %[src], 52\n\t"  "s32i.n a4, %[base], 52\n\t"
          "l32i.n a4, %[src], 56\n\t"  "s32i.n a4, %[base], 56\n\t"
          "l32i.n a4, %[src], 60\n\t"  "s32i.n a4, %[base], 60\n\t"
          // Post-START_inter NOPs (inter compute: 16 cyc OVERLAP 3 + 29 NOPs = 45)
          ".rept 29\n\tnop\n.endr\n\t"
          :
          : [base]"r"(_sha_text), [one]"r"(1),
            [c80]"r"(0x80000000), [c100]"r"(0x00000100),
            [src]"r"(sha_buffer)
          : "a4", "memory"
        );

        if (nerd_sha_ll_read_digest_swap_if(hash))
        {
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            if (isSha256Valid(hash))
            {
              result->difficulty = diff_hash;
              result->nonce = job->nonce_start+n;
              memcpy(result->hash, hash, sizeof(hash));
            }
          }
        }
        // End-of-iter: prep TEXT[0..7] for NEXT iter's block-1 and trigger
        // SHA_START. Inline asm with 3 operands (base, src, one).
        __asm__ __volatile__ (
          "l32i.n a4, %[src], 0\n\t"  "s32i.n a4, %[base], 0\n\t"
          "l32i.n a4, %[src], 4\n\t"  "s32i.n a4, %[base], 4\n\t"
          "l32i.n a4, %[src], 8\n\t"  "s32i.n a4, %[base], 8\n\t"
          "l32i.n a4, %[src], 12\n\t" "s32i.n a4, %[base], 12\n\t"
          "l32i.n a4, %[src], 16\n\t" "s32i.n a4, %[base], 16\n\t"
          "l32i.n a4, %[src], 20\n\t" "s32i.n a4, %[base], 20\n\t"
          "l32i.n a4, %[src], 24\n\t" "s32i.n a4, %[base], 24\n\t"
          "l32i.n a4, %[src], 28\n\t" "s32i.n a4, %[base], 28\n\t"
          "s32i %[one], %[base], 0x90\n\t"  // SHA_START block-1 next iter
          :
          : [base]"r"(_sha_text), [src]"r"(sha_buffer), [one]"r"(1)
          : "a4", "memory"
        );
        }  // end inner for-loop
        // Outer loop: job-change check happens here, every 256 iters.
        if (s_working_current_job_id != job_in_work) {
          result->nonce_count = n;
          _done = true;
        }
      }  // end outer while-loop
      // Drain any in-flight block-1 from end of last iter.
      nerd_sha_hal_wait_idle();
      esp_sha_unlock_engine(SHA2_256);
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    esp_task_wdt_reset();
  }
}

#pragma GCC pop_options

#endif  //CONFIG_IDF_TARGET_ESP32

#endif  //HARDWARE_SHA265


#define DELAY 100
#define REDRAW_EVERY 10

void restoreStat() {
  if(!Settings.saveStats) return;
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.printf("[MONITOR] NVS partition is full or has invalid version, erasing...\n");
    nvs_flash_init();
  }

  ret = nvs_open("state", NVS_READWRITE, &stat_handle);

  size_t required_size = sizeof(double);
  nvs_get_blob(stat_handle, "best_diff", &best_diff, &required_size);
  nvs_get_u32(stat_handle, "Mhashes", &Mhashes);
  uint32_t nv_shares, nv_valids;
  nvs_get_u32(stat_handle, "shares", &nv_shares);
  nvs_get_u32(stat_handle, "valids", &nv_valids);
  shares = nv_shares;
  valids = nv_valids;
  nvs_get_u32(stat_handle, "templates", &templates);
  nvs_get_u64(stat_handle, "upTime", &upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &Mhashes, sizeof(Mhashes));
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);

  uint32_t nv_crc;
  nvs_get_u32(stat_handle, "crc32", &nv_crc);
  if (nv_crc != crc)
  {
    best_diff = 0.0;
    Mhashes = 0;
    shares = 0;
    valids = 0;
    templates = 0;
    upTime = 0;
  }
}

void saveStat() {
  if(!Settings.saveStats) return;
  Serial.printf("[MONITOR] Saving stats\n");
  nvs_set_blob(stat_handle, "best_diff", &best_diff, sizeof(best_diff));
  nvs_set_u32(stat_handle, "Mhashes", Mhashes);
  nvs_set_u32(stat_handle, "shares", shares);
  nvs_set_u32(stat_handle, "valids", valids);
  nvs_set_u32(stat_handle, "templates", templates);
  nvs_set_u64(stat_handle, "upTime", upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &Mhashes, sizeof(Mhashes));
  uint32_t nv_shares = shares;
  uint32_t nv_valids = valids;
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);
  nvs_set_u32(stat_handle, "crc32", crc);
}

void resetStat() {
    Serial.printf("[MONITOR] Resetting NVS stats\n");
    templates = hashes = Mhashes = totalKHashes = elapsedKHs = upTime = shares = valids = 0;
    best_diff = 0.0;
    // Force-write zeros even when Settings.saveStats is false (bypass saveStat
    // gate). Open the namespace ourselves in case stat_handle wasn't initialized.
    nvs_handle_t h;
    if (nvs_open("state", NVS_READWRITE, &h) == ESP_OK) {
        uint32_t z32 = 0;
        uint64_t z64 = 0;
        double   zd  = 0.0;
        nvs_set_blob(h, "best_diff", &zd, sizeof(zd));
        nvs_set_u32 (h, "Mhashes",   z32);
        nvs_set_u32 (h, "shares",    z32);
        nvs_set_u32 (h, "valids",    z32);
        nvs_set_u32 (h, "templates", z32);
        nvs_set_u64 (h, "upTime",    z64);
        // CRC of all-zeros payload so restoreStat sees a match next boot.
        uint32_t crc = crc32_reset();
        crc = crc32_add(crc, &zd,  sizeof(zd));
        crc = crc32_add(crc, &z32, sizeof(z32));
        crc = crc32_add(crc, &z32, sizeof(z32));
        crc = crc32_add(crc, &z32, sizeof(z32));
        crc = crc32_add(crc, &z32, sizeof(z32));
        crc = crc32_add(crc, &z64, sizeof(z64));
        crc = crc32_finish(crc);
        nvs_set_u32(h, "crc32", crc);
        nvs_commit(h);
        nvs_close(h);
    }
}

void runMonitor(void *name)
{

  Serial.println("[MONITOR] started");
  restoreStat();

  unsigned long mLastCheck = 0;

  resetToFirstScreen();

  unsigned long frame = 0;

  uint32_t seconds_elapsed = 0;

  totalKHashes = (Mhashes * 1000) + hashes / 1000;
  uint32_t last_update_millis = millis();
  uint32_t uptime_frac = 0;

  while (1)
  {
    uint32_t now_millis = millis();
    if (now_millis < last_update_millis)
      now_millis = last_update_millis;
    
    uint32_t mElapsed = now_millis - mLastCheck;
    if (mElapsed >= 1000)
    {
      // Cap at 5s — if the task was blocked (SSL fetch, sprite stalls, etc),
      // mElapsed may be huge and cause uptime/elapsedKHs to skyrocket.
      if (mElapsed > 5000) mElapsed = 5000;
      mLastCheck = now_millis;
      last_update_millis = now_millis;
      unsigned long currentKHashes = (Mhashes * 1000) + hashes / 1000;
      uint32_t deltaK = (currentKHashes >= totalKHashes) ? (currentKHashes - totalKHashes) : 0;
      // Cap elapsedKHs to a sane upper bound (~3 MH/s sustained) to prevent
      // post-hangup catch-up from poisoning the rolling averages.
      if (deltaK > 3000) deltaK = 3000;
      elapsedKHs = deltaK;
      totalKHashes = currentKHashes;

      axehub_metrics_sample_rssi();
      axehub_metrics_sample_khs(elapsedKHs);
      axehub_metrics_sample_per_worker_khs();

      uptime_frac += mElapsed;
      while (uptime_frac >= 1000)
      {
        uptime_frac -= 1000;
        upTime ++;
      }

      drawCurrentScreen(mElapsed);

      // Monitor state when hashrate is 0.0
      if (elapsedKHs == 0)
      {
        Serial.printf(">>> [i] Miner: newJob>%s / inRun>%s) - Client: connected>%s / subscribed>%s / wificonnected>%s\n",
            "true",//(1) ? "true" : "false",
            isMinerSuscribed ? "true" : "false",
            client.connected() ? "true" : "false", isMinerSuscribed ? "true" : "false", WiFi.status() == WL_CONNECTED ? "true" : "false");
      }

      #ifdef DEBUG_MEMORY
      Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
      Serial.printf("### Max stack usage: %d\n", uxTaskGetStackHighWaterMark(NULL));
      #endif

      seconds_elapsed++;

      if(seconds_elapsed % (saveIntervals[currentIntervalIndex]) == 0){
        saveStat();
        seconds_elapsed = 0;
        if(currentIntervalIndex < saveIntervalsSize - 1)
          currentIntervalIndex++;
      }    
    }
    animateCurrentScreen(frame);
    doLedStuff(frame);

    vTaskDelay(DELAY / portTICK_PERIOD_MS);
    frame++;
  }
}
