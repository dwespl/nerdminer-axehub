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
#include <soc/dport_reg.h>
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

      // STEP 2: suggest pool difficulty BEFORE authorize (ckpool/public-pool
      // ignore later suggests until reconnect).
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
                                                #if defined(CONFIG_IDF_TARGET_ESP32) && defined(AXEHUB_HW_PIPELINED_ASM)
                                                // Push ONE HW job per stratum cycle with huge budget — multiple
                                                // overlapping local jobs in swap space converge on the same hit
                                                // and trigger pool "Duplicate share" rejects.
                                                if (i == 0) {
                                                  JobPush( s_job_request_list_hw, job_pool, nonce_pool, 0xFFFFFFFFu, currentPoolDifficulty, sha_buffer_swap, hw_midstate, bake);
                                                  #ifdef RANDOM_NONCE
                                                  nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                                  #else
                                                  nonce_pool += NONCE_PER_JOB_HW;
                                                  #endif
                                                }
                                                #else
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
      #if defined(CONFIG_IDF_TARGET_ESP32) && defined(AXEHUB_HW_PIPELINED_ASM)
      // ASM mode: single HW job pushed at notify covers the whole stratum
      // cycle (refill creates overlapping local jobs → duplicate-share rejects).
      while (false)
      #else
      while (s_job_request_list_hw.size() < 4)
      #endif
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
      for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        ((uint32_t*)(job->sha_buffer+64+12))[0] = job->nonce_start+n;

        if (nerd_sha256d_baked(job->midstate, job->sha_buffer+64, job->bake, hash))
        {
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            result->difficulty = diff_hash;
            result->nonce = job->nonce_start+n;
            memcpy(result->hash, hash, 32);
          }
        }

        if ( (uint16_t)(n & 0xFF) == 0 && s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n+1;
          break;
        }
      }
      axehub_metrics_record_sw_hashes(result->nonce_count);
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

// Forward decls for production fill helpers used by the cycle probe — their
// definitions live further down in this file (after the probe).
static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text);
static inline void nerd_sha_ll_fill_text_block_sha256_upper(const void *input_text, uint32_t nonce);
static inline void nerd_sha_ll_fill_text_block_sha256_double();

// Forward decls for SW asm path (classic + S3) — defined in
// axehub_sha_sw_classic.cpp under AXEHUB_SW_ASM_PURE.
#ifdef AXEHUB_SW_ASM_PURE
extern "C" {
    bool axehub_sha_sw_asm_classic_mine(const uint32_t midstate[8],
                                        const uint8_t  tail[16],
                                        uint8_t        out_hash[32]);
    void axehub_sha_sw_asm_classic_double(const uint32_t midstate[8],
                                          const uint8_t  tail[16],
                                          uint8_t        out_hash[32]);
}
#endif

// SHA peripheral cycle probe (CCOUNT, ±1 cyc): peripheral compute times,
// fill costs, safe grace for TEXT overwrite. Designs the pipelined hot loop.
void axehub_classic_overlap_canary(void)
{
    auto rdcc = []() __attribute__((always_inline)) {
        uint32_t c; __asm__ __volatile__("rsr.ccount %0":"=r"(c)); return c;
    };

    volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
    volatile uint32_t * const busy = (volatile uint32_t *)SHA_256_BUSY_REG;

    static const uint32_t test_input[16] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444,
        0x55555555, 0x66666666, 0x77777777, 0x88888888,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000200,
    };
    static const uint32_t alt_input[16] = {
        0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD,
        0xEEEEEEEE, 0xFFFFFFFF, 0x12345678, 0x9ABCDEF0,
        0xCAFEBABE, 0xDEADC0DE, 0xFEEDFACE, 0xBADDCAFE,
        0xC0FFEE00, 0x1BADB002, 0xDEADBEEF, 0x00000200,
    };

    esp_sha_lock_engine(SHA2_256);

    // ---- Reference clean digest (block-1 → load → read) ----
    uint32_t h_clean[8];
    for (int i = 0; i < 16; ++i) text[i] = test_input[i];
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 8; ++i) h_clean[i] = text[i];

    const int N_RUNS = 16;

    // ---- Probe 1: block-1 compute time (start → busy=0) ----
    uint32_t cb1_min = 0xFFFFFFFFu, cb1_max = 0;
    uint64_t cb1_sum = 0;
    for (int r = 0; r < N_RUNS; ++r) {
        for (int i = 0; i < 16; ++i) text[i] = test_input[i];
        uint32_t t0 = rdcc();
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        uint32_t dt = rdcc() - t0;
        if (dt < cb1_min) cb1_min = dt;
        if (dt > cb1_max) cb1_max = dt;
        cb1_sum += dt;
        sha_ll_load(SHA2_256);
        while (*busy) {}
    }

    // ---- Probe 2: block-2 (CONTINUE) compute time ----
    uint32_t cb2_min = 0xFFFFFFFFu;
    uint64_t cb2_sum = 0;
    for (int r = 0; r < N_RUNS; ++r) {
        for (int i = 0; i < 16; ++i) text[i] = test_input[i];
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        for (int i = 0; i < 16; ++i) text[i] = alt_input[i];
        uint32_t t0 = rdcc();
        sha_ll_continue_block(SHA2_256);
        while (*busy) {}
        uint32_t dt = rdcc() - t0;
        if (dt < cb2_min) cb2_min = dt;
        cb2_sum += dt;
        sha_ll_load(SHA2_256);
        while (*busy) {}
    }

    // ---- Probe 3: LOAD time (short, peripheral copies internal H → TEXT) ----
    uint32_t ld_min = 0xFFFFFFFFu;
    uint64_t ld_sum = 0;
    for (int r = 0; r < N_RUNS; ++r) {
        for (int i = 0; i < 16; ++i) text[i] = test_input[i];
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        uint32_t t0 = rdcc();
        sha_ll_load(SHA2_256);
        while (*busy) {}
        uint32_t dt = rdcc() - t0;
        if (dt < ld_min) ld_min = dt;
        ld_sum += dt;
    }

    // ---- Probe 4: pure CPU fill-16-words (no peripheral activity) ----
    uint32_t fill16_min = 0xFFFFFFFFu;
    for (int r = 0; r < N_RUNS; ++r) {
        uint32_t t0 = rdcc();
        text[0]  = alt_input[0];  text[1]  = alt_input[1];
        text[2]  = alt_input[2];  text[3]  = alt_input[3];
        text[4]  = alt_input[4];  text[5]  = alt_input[5];
        text[6]  = alt_input[6];  text[7]  = alt_input[7];
        text[8]  = alt_input[8];  text[9]  = alt_input[9];
        text[10] = alt_input[10]; text[11] = alt_input[11];
        text[12] = alt_input[12]; text[13] = alt_input[13];
        text[14] = alt_input[14]; text[15] = alt_input[15];
        uint32_t dt = rdcc() - t0;
        if (dt < fill16_min) fill16_min = dt;
    }

    // ---- Probe 5: bisect minimum safe grace before TEXT overwrite ----
    // For each (slot_lo..slot_hi) range, find min cycles after SHA_START_REG
    // at which writing alt_input there does NOT corrupt the block-1 digest.
    auto test_grace_once = [&](uint32_t grace, int slot_lo, int slot_hi) -> bool {
        for (int i = 0; i < 16; ++i) text[i] = test_input[i];
        uint32_t t0 = rdcc();
        sha_ll_start_block(SHA2_256);
        while ((rdcc() - t0) < grace) { /* spin until grace elapsed */ }
        for (int i = slot_lo; i <= slot_hi; ++i) text[i] = alt_input[i];
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        for (int i = 0; i < 8; ++i) {
            if (text[i] != h_clean[i]) return false;
        }
        return true;
    };
    auto test_grace = [&](uint32_t grace, int slot_lo, int slot_hi) -> bool {
        // 4 trials must all pass — random-bit collision could falsely match.
        for (int t = 0; t < 4; ++t) {
            if (!test_grace_once(grace, slot_lo, slot_hi)) return false;
        }
        return true;
    };

    static const uint32_t G[] = {
        0, 8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536
    };
    static const int N_G = sizeof(G)/sizeof(G[0]);

    bool safe_full[N_G];   // TEXT[0..15] (whole block)
    bool safe_data[N_G];   // TEXT[0..3]  (data words — reused in rounds 0..3 of W expansion)
    bool safe_pad[N_G];    // TEXT[4..15] (padding — never reused as data, but used for W[4..15])
    for (int g = 0; g < N_G; ++g) {
        safe_full[g] = test_grace(G[g], 0, 15);
        safe_data[g] = test_grace(G[g], 0, 3);
        safe_pad[g]  = test_grace(G[g], 4, 15);
    }

    esp_sha_unlock_engine(SHA2_256);

    // ---- Output ----
    uint32_t cpu_mhz = getCpuFrequencyMhz();
    Serial.printf("[CYCLE PROBE] CPU=%u MHz, runs/measurement=%d\n", (unsigned)cpu_mhz, N_RUNS);
    Serial.printf("[CYCLE PROBE] block-1 compute  : min %u, avg %u, max %u cyc (%.2f us min)\n",
                  (unsigned)cb1_min, (unsigned)(cb1_sum/N_RUNS), (unsigned)cb1_max,
                  (double)cb1_min / cpu_mhz);
    Serial.printf("[CYCLE PROBE] block-2 continue : min %u, avg %u cyc\n",
                  (unsigned)cb2_min, (unsigned)(cb2_sum/N_RUNS));
    Serial.printf("[CYCLE PROBE] LOAD              : min %u, avg %u cyc\n",
                  (unsigned)ld_min, (unsigned)(ld_sum/N_RUNS));
    Serial.printf("[CYCLE PROBE] CPU fill 16 words : min %u cyc\n", (unsigned)fill16_min);
    Serial.printf("[CYCLE PROBE] grace bisect (4 trials each, all must pass):\n");
    Serial.printf("    grace | TEXT[0..15] | TEXT[0..3] data | TEXT[4..15] pad\n");
    for (int g = 0; g < N_G; ++g) {
        Serial.printf("    %5u | %s        | %s            | %s\n",
                      (unsigned)G[g],
                      safe_full[g] ? "SAFE" : "----",
                      safe_data[g] ? "SAFE" : "----",
                      safe_pad[g]  ? "SAFE" : "----");
    }

    auto first_safe = [&](const bool *arr) -> int32_t {
        for (int g = 0; g < N_G; ++g) if (arr[g]) return (int32_t)G[g];
        return -1;
    };
    int32_t s_full = first_safe(safe_full);
    int32_t s_data = first_safe(safe_data);
    int32_t s_pad  = first_safe(safe_pad);

    Serial.printf("[CYCLE PROBE] SUMMARY:\n");
    Serial.printf("  min safe grace TEXT[0..15] = %s\n",
                  s_full < 0 ? "NEVER (within 1536c)" : (String((unsigned)s_full) + " cyc").c_str());
    Serial.printf("  min safe grace TEXT[0..3]  = %s\n",
                  s_data < 0 ? "NEVER" : (String((unsigned)s_data) + " cyc").c_str());
    Serial.printf("  min safe grace TEXT[4..15] = %s\n",
                  s_pad  < 0 ? "NEVER" : (String((unsigned)s_pad)  + " cyc").c_str());

    if (s_full >= 0 && (uint32_t)s_full < cb1_min) {
        uint32_t budget = cb1_min - (uint32_t)s_full;
        Serial.printf("[CYCLE PROBE] A.1 v2 VIABLE (full overlap): budget %u cyc, fill16=%u cyc\n",
                      (unsigned)budget, (unsigned)fill16_min);
    } else if (s_pad >= 0 && (uint32_t)s_pad < cb1_min && s_data >= 0 && (uint32_t)s_data < cb1_min) {
        Serial.printf("[CYCLE PROBE] A.1 v2 VIABLE (split fill): pad@%u cyc, data@%u cyc, compute=%u cyc\n",
                      (unsigned)s_pad, (unsigned)s_data, (unsigned)cb1_min);
    } else {
        Serial.printf("[CYCLE PROBE] A.1 v2 BLOCKED: TEXT writes never safe before compute end\n");
    }

    // ---- Probe 6: FULL CHAIN test ----
    // Validates block-1 → overlap fill block-2 → CONTINUE → LOAD chain
    // (the actual production flow), not just the grace test above.
    static const uint32_t blk2_input[16] = {
        0xCAFE0001, 0xCAFE0002, 0xCAFE0003, 0xCAFE0004,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000280,
    };

    esp_sha_lock_engine(SHA2_256);

    // Reference: clean two-block hash, no overlap.
    uint32_t hh_clean[8];
    for (int i = 0; i < 16; ++i) text[i] = test_input[i];
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 16; ++i) text[i] = blk2_input[i];
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 8; ++i) hh_clean[i] = text[i];

    // A.1 v2 candidate: overlap block-2 fill with block-1 compute.
    // Bisect grace from 0 to find where this stays correct.
    auto test_chain_grace = [&](uint32_t grace) -> bool {
        for (int trial = 0; trial < 4; ++trial) {
            for (int i = 0; i < 16; ++i) text[i] = test_input[i];
            uint32_t t0 = rdcc();
            sha_ll_start_block(SHA2_256);
            while ((rdcc() - t0) < grace) {}
            for (int i = 0; i < 16; ++i) text[i] = blk2_input[i];
            while (*busy) {}
            sha_ll_continue_block(SHA2_256);
            while (*busy) {}
            sha_ll_load(SHA2_256);
            while (*busy) {}
            for (int i = 0; i < 8; ++i) {
                if (text[i] != hh_clean[i]) return false;
            }
        }
        return true;
    };

    bool chain_safe[N_G];
    for (int g = 0; g < N_G; ++g) chain_safe[g] = test_chain_grace(G[g]);

    esp_sha_unlock_engine(SHA2_256);

    Serial.printf("[CYCLE PROBE] FULL CHAIN test (block-1 + overlap fill block-2 + CONTINUE → digest):\n");
    Serial.printf("    grace | result\n");
    for (int g = 0; g < N_G; ++g) {
        Serial.printf("    %5u | %s\n", (unsigned)G[g], chain_safe[g] ? "SAFE" : "CORRUPT");
    }
    int32_t s_chain = -1;
    for (int g = 0; g < N_G; ++g) if (chain_safe[g]) { s_chain = G[g]; break; }
    if (s_chain == 0) {
        Serial.printf("[CYCLE PROBE] inline-loop chain: SAFE from grace=0\n");
    } else if (s_chain > 0) {
        Serial.printf("[CYCLE PROBE] inline-loop chain: needs grace>=%u cyc\n", (unsigned)s_chain);
    } else {
        Serial.printf("[CYCLE PROBE] inline-loop chain: BLOCKED\n");
    }

    // ---- Probe 7: production helpers vs clean baseline (reorder hazard).
    static uint8_t prod_buffer[80];
    for (int i = 0; i < 80; ++i) prod_buffer[i] = (uint8_t)(0xA1 + i * 7);
    uint8_t h_base[32], h_a1v2[32], h_memw[32];

    esp_sha_lock_engine(SHA2_256);

    // Baseline: fill_b1 → start → wait → fill_upper → continue
    nerd_sha_ll_fill_text_block_sha256(prod_buffer);
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    nerd_sha_ll_fill_text_block_sha256_upper(prod_buffer+64, 0xCAFEBABE);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 8; ++i) ((uint32_t*)h_base)[i] = __builtin_bswap32(text[i]);

    // A.1 v2 plain: fill_b1 → start → fill_upper (overlap) → wait → continue
    nerd_sha_ll_fill_text_block_sha256(prod_buffer);
    sha_ll_start_block(SHA2_256);
    nerd_sha_ll_fill_text_block_sha256_upper(prod_buffer+64, 0xCAFEBABE);
    while (*busy) {}
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 8; ++i) ((uint32_t*)h_a1v2)[i] = __builtin_bswap32(text[i]);

    // A.1 v2 + memw: same but with explicit memory barrier after start trigger
    nerd_sha_ll_fill_text_block_sha256(prod_buffer);
    sha_ll_start_block(SHA2_256);
    asm volatile("memw" ::: "memory");
    nerd_sha_ll_fill_text_block_sha256_upper(prod_buffer+64, 0xCAFEBABE);
    while (*busy) {}
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    for (int i = 0; i < 8; ++i) ((uint32_t*)h_memw)[i] = __builtin_bswap32(text[i]);

    esp_sha_unlock_engine(SHA2_256);

    auto eq32 = [](const uint8_t *a, const uint8_t *b) -> bool {
        for (int i = 0; i < 32; ++i) if (a[i] != b[i]) return false;
        return true;
    };
    auto print_hash = [&](const char *label, const uint8_t *h, const char *tag) {
        Serial.printf("  %-13s : %02x%02x%02x%02x%02x%02x%02x%02x...%s\n",
                      label, h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], tag);
    };
    Serial.printf("[CYCLE PROBE] PROD-HELPER A.1 v2 test:\n");
    print_hash("baseline",     h_base, "");
    print_hash("a1v2 plain",   h_a1v2, eq32(h_base, h_a1v2) ? " MATCH" : " DIFFERS (compiler reorder hazard)");
    print_hash("a1v2 + memw",  h_memw, eq32(h_base, h_memw) ? " MATCH" : " DIFFERS");

    // ---- Probe 8: HOT-LOOP simulation ----
    // 1024 nonces of full double-SHA chain; catches state-dependent
    // corruption that single-shot probes would miss.
    esp_sha_lock_engine(SHA2_256);
    uint32_t mismatch_count = 0;
    uint32_t first_bad_n = 0xFFFFFFFFu;
    uint8_t first_bad_base[32], first_bad_a1v2[32];
    const uint32_t LOOP_N = 1024;
    for (uint32_t n = 0; n < LOOP_N; ++n) {
        uint8_t hb[32], hv[32];
        uint32_t nonce_v = 0xDEADBEEFu + n;

        // BASELINE full double-SHA (current production order)
        nerd_sha_ll_fill_text_block_sha256(prod_buffer);
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        nerd_sha_ll_fill_text_block_sha256_upper(prod_buffer+64, nonce_v);
        sha_ll_continue_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        nerd_sha_ll_fill_text_block_sha256_double();
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        for (int i = 0; i < 8; ++i) ((uint32_t*)hb)[i] = __builtin_bswap32(text[i]);

        // A.1 v2 + memw full double-SHA
        nerd_sha_ll_fill_text_block_sha256(prod_buffer);
        sha_ll_start_block(SHA2_256);
        asm volatile("memw" ::: "memory");
        nerd_sha_ll_fill_text_block_sha256_upper(prod_buffer+64, nonce_v);
        while (*busy) {}
        sha_ll_continue_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        nerd_sha_ll_fill_text_block_sha256_double();
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        for (int i = 0; i < 8; ++i) ((uint32_t*)hv)[i] = __builtin_bswap32(text[i]);

        if (!eq32(hb, hv)) {
            if (mismatch_count == 0) {
                first_bad_n = n;
                memcpy(first_bad_base, hb, 32);
                memcpy(first_bad_a1v2, hv, 32);
            }
            mismatch_count++;
        }
    }
    esp_sha_unlock_engine(SHA2_256);

    Serial.printf("[CYCLE PROBE] HOT-LOOP sim (%u double-SHAs, baseline vs A.1 v2+memw):\n",
                  (unsigned)LOOP_N);
    Serial.printf("  mismatches: %u / %u\n", (unsigned)mismatch_count, (unsigned)LOOP_N);
    if (mismatch_count > 0) {
        Serial.printf("  first bad @ n=%u\n", (unsigned)first_bad_n);
        Serial.printf("    baseline: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                      first_bad_base[0], first_bad_base[1], first_bad_base[2], first_bad_base[3],
                      first_bad_base[4], first_bad_base[5], first_bad_base[6], first_bad_base[7]);
        Serial.printf("    a1v2    : %02x%02x%02x%02x%02x%02x%02x%02x\n",
                      first_bad_a1v2[0], first_bad_a1v2[1], first_bad_a1v2[2], first_bad_a1v2[3],
                      first_bad_a1v2[4], first_bad_a1v2[5], first_bad_a1v2[6], first_bad_a1v2[7]);
    }

    // ---- Probe 9: nerd_sha256d_baked per-nonce cycle cost (vs mbedtls ref).
    static uint8_t test_header[80];
    for (int i = 0; i < 80; ++i) test_header[i] = (uint8_t)(0x37 + i * 11);
    uint32_t midstate[8];
    uint32_t bake[16];
    nerd_mids(midstate, test_header);
    nerd_sha256_bake(midstate, test_header + 64, bake);

    uint8_t ref_hash[32], inner_hash[32];
    // mbedtls double SHA256 reference: SHA256(SHA256(test_header[0..79]))
    {
        mbedtls_sha256_context c;
        mbedtls_sha256_init(&c);
        mbedtls_sha256_starts_ret(&c, 0);
        mbedtls_sha256_update_ret(&c, test_header, 80);
        mbedtls_sha256_finish_ret(&c, inner_hash);
        mbedtls_sha256_init(&c);
        mbedtls_sha256_starts_ret(&c, 0);
        mbedtls_sha256_update_ret(&c, inner_hash, 32);
        mbedtls_sha256_finish_ret(&c, ref_hash);
    }

    // ---- Probe 11: TEXT[5..14] persistence test ----
    // Empirically determine if peripheral preserves TEXT[5..14] across
    // START/CONTINUE/LOAD — basis for the persistent-zeros technique.
    {
        const uint32_t SENTINEL = 0xDEADBEEFu;
        volatile uint32_t * const tx = (volatile uint32_t *)SHA_TEXT_BASE;
        volatile uint32_t * const bs = (volatile uint32_t *)SHA_256_BUSY_REG;

        esp_sha_lock_engine(SHA2_256);

        // Phase A: write TEXT[5..14] = SENTINEL, run a single block-1+block-2+LOAD
        // sequence (matching production block-2 path). Use reasonable header data.
        // Then read back TEXT[5..14] and report which slots survived.
        for (int i = 0; i < 16; ++i) tx[i] = (i >= 5 && i <= 14) ? SENTINEL : 0xDEEDC0DEu;
        // Run block-1 (start)
        for (int i = 0; i < 16; ++i) tx[i] = 0x11111111u + i; // overwrite all w/ pattern
        sha_ll_start_block(SHA2_256);
        while (*bs) {}
        // Restore sentinels in TEXT[5..14] after block-1 trigger snapshot
        for (int i = 5; i <= 14; ++i) tx[i] = SENTINEL;
        // Now run continue (block-2)
        sha_ll_continue_block(SHA2_256);
        while (*bs) {}
        // Trigger LOAD
        sha_ll_load(SHA2_256);
        while (*bs) {}
        // Read TEXT[5..14] — did peripheral preserve our sentinels?
        uint32_t after_load[10];
        for (int i = 0; i < 10; ++i) after_load[i] = tx[5 + i];

        // Phase B: separate test — just a START with TEXT[5..14]=SENTINEL, no
        // continue/load. Tests if SHA_START itself touches non-data slots.
        for (int i = 0; i < 16; ++i) tx[i] = (i >= 5 && i <= 14) ? SENTINEL : 0x22222222u + i;
        sha_ll_start_block(SHA2_256);
        while (*bs) {}
        uint32_t after_start[10];
        for (int i = 0; i < 10; ++i) after_start[i] = tx[5 + i];
        sha_ll_load(SHA2_256);
        while (*bs) {}

        // Phase C: just LOAD on its own — write TEXT[5..14]=SENTINEL, trigger
        // LOAD, see if those slots survive.
        for (int i = 0; i < 16; ++i) tx[i] = (i >= 5 && i <= 14) ? SENTINEL : 0x33333333u + i;
        sha_ll_start_block(SHA2_256);
        while (*bs) {}
        // Re-write sentinels (block-1 compute may have touched them)
        for (int i = 5; i <= 14; ++i) tx[i] = SENTINEL;
        sha_ll_load(SHA2_256);
        while (*bs) {}
        uint32_t after_only_load[10];
        for (int i = 0; i < 10; ++i) after_only_load[i] = tx[5 + i];

        esp_sha_unlock_engine(SHA2_256);

        Serial.printf("[CYCLE PROBE] TEXT[5..14] persistence test (SENTINEL=0x%08x):\n", (unsigned)SENTINEL);
        Serial.printf("    slot |     after START     | after CONT+LOAD     | after LOAD only\n");
        for (int i = 0; i < 10; ++i) {
            Serial.printf("    [%2d] | 0x%08x %s | 0x%08x %s | 0x%08x %s\n",
                          5 + i,
                          (unsigned)after_start[i],     after_start[i]     == SENTINEL ? "OK" : "**",
                          (unsigned)after_load[i],      after_load[i]      == SENTINEL ? "OK" : "**",
                          (unsigned)after_only_load[i], after_only_load[i] == SENTINEL ? "OK" : "**");
        }
        bool start_safe = true, contload_safe = true, load_safe = true;
        for (int i = 0; i < 10; ++i) {
            if (after_start[i]     != SENTINEL) start_safe    = false;
            if (after_load[i]      != SENTINEL) contload_safe = false;
            if (after_only_load[i] != SENTINEL) load_safe     = false;
        }
        Serial.printf("[CYCLE PROBE] Persistent-zeros viability:\n");
        Serial.printf("  TEXT[5..14] survives START      : %s\n", start_safe    ? "YES" : "NO");
        Serial.printf("  TEXT[5..14] survives CONT+LOAD  : %s\n", contload_safe ? "YES" : "NO");
        Serial.printf("  TEXT[5..14] survives LOAD only  : %s\n", load_safe     ? "YES" : "NO");
        if (start_safe && contload_safe && load_safe) {
            Serial.printf("[CYCLE PROBE] Persistent-zeros block-3: VIABLE on this peripheral\n");
        } else {
            Serial.printf("[CYCLE PROBE] Persistent-zeros block-3: BLOCKED — peripheral modifies TEXT[5..14]\n");
        }
    }

#ifdef AXEHUB_SW_ASM_PURE
    uint8_t asm_hash[32];
    axehub_sha_sw_asm_classic_double(midstate, test_header + 64, asm_hash);
    bool sw_match = true;
    for (int i = 0; i < 32; ++i) if (ref_hash[i] != asm_hash[i]) { sw_match = false; break; }
    Serial.printf("[CYCLE PROBE] SW-ASM correctness: %s\n", sw_match ? "MATCH" : "DIFFERS");
    if (!sw_match) {
        Serial.printf("  midstate: ");
        for (int i = 0; i < 8; ++i) Serial.printf("%08x ", (unsigned)midstate[i]);
        Serial.printf("\n  tail: ");
        for (int i = 0; i < 16; ++i) Serial.printf("%02x", test_header[64+i]);
        Serial.printf("\n  ref:  ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", ref_hash[i]);
        Serial.printf("\n  asm:  ");
        for (int i = 0; i < 32; ++i) Serial.printf("%02x", asm_hash[i]);
        Serial.printf("\n");
        // Locate first byte that differs
        for (int i = 0; i < 32; ++i) {
            if (ref_hash[i] != asm_hash[i]) {
                Serial.printf("  first diff @ byte %d: ref=%02x asm=%02x\n",
                              i, ref_hash[i], asm_hash[i]);
                break;
            }
        }
    }

#endif // AXEHUB_SW_ASM_PURE

    // ---- Probe 10: nerd_sha256d_baked benchmark.
    const int BENCH_N = 256;
    uint32_t baked_min = 0xFFFFFFFFu;
    uint64_t baked_sum = 0;
    int baked_kept = 0;
    uint8_t bench_hash[32];
    for (int it = 0; it < BENCH_N; ++it) {
        ((uint32_t*)(test_header+64+12))[0] = 0xC0FFEE00u + it;
        uint32_t t0 = rdcc();
        nerd_sha256d_baked(midstate, test_header + 64, bake, bench_hash);
        uint32_t dt = rdcc() - t0;
        if (dt < 50000) {
            if (dt < baked_min) baked_min = dt;
            baked_sum += dt; baked_kept++;
        }
    }
    Serial.printf("[CYCLE PROBE] nerd_sha256d_baked bench (%d iters):\n", BENCH_N);
    Serial.printf("  min %u, avg %u cyc/nonce (kept %d)\n",
                  (unsigned)baked_min, (unsigned)(baked_kept ? baked_sum/baked_kept : 0), baked_kept);
#ifdef AXEHUB_SW_ASM_ROUNDS
    Serial.printf("  build: AXEHUB_SW_ASM_ROUNDS ON (inline asm ROTR)\n");
#else
    Serial.printf("  build: AXEHUB_SW_ASM_ROUNDS OFF (C ROTR baseline)\n");
#endif
    if (baked_min > 0) {
        uint32_t mhz = getCpuFrequencyMhz();
        Serial.printf("  projected SW kH/s @ %u MHz: %u\n",
                      (unsigned)mhz, (unsigned)(mhz*1000/baked_min));
    }

#ifdef AXEHUB_SW_ASM_PURE
    // Companion bench: pure-asm path (axehub_sha_sw_asm_classic_double).
    uint32_t asm_min_b = 0xFFFFFFFFu;
    uint64_t asm_sum_b = 0; int asm_kept_b = 0;
    for (int it = 0; it < BENCH_N; ++it) {
        ((uint32_t*)(test_header+64+12))[0] = 0xC0FFEE00u + it;
        uint32_t t0 = rdcc();
        axehub_sha_sw_asm_classic_double(midstate, test_header + 64, bench_hash);
        uint32_t dt = rdcc() - t0;
        if (dt < 50000) {
            if (dt < asm_min_b) asm_min_b = dt;
            asm_sum_b += dt; asm_kept_b++;
        }
    }
    Serial.printf("[CYCLE PROBE] axehub_sha_sw_asm bench (%d iters):\n", BENCH_N);
    Serial.printf("  min %u, avg %u cyc/nonce (kept %d)\n",
                  (unsigned)asm_min_b, (unsigned)(asm_kept_b ? asm_sum_b/asm_kept_b : 0), asm_kept_b);
#endif
}

// Probe: can iter N+1 skip block-1 by relying on peripheral H state
// preservation? Empirical answer NO (SHA_START overwrites H). Kept for re-test.
void axehub_classic_h_state_probe(void)
{
    Serial.printf("\n[H-PROBE] === Peripheral H state preservation probe ===\n");

    volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
    volatile uint32_t * const busy = (volatile uint32_t *)SHA_256_BUSY_REG;

    // Block-1 message: 64 bytes of arbitrary "header" data, in BE 32-bit words.
    static const uint32_t BLK1[16] = {
        0x01000000, 0xABCDEF12, 0x34567890, 0xABCDEF12,
        0x34567890, 0xABCDEF12, 0x34567890, 0xABCDEF12,
        0x12345678, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0,
        0x12345678, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0,
    };
    // Block-2 messages parameterised by nonce (TEXT[3] = nonce_be).
    // Pre-build the block (rest of header bytes 64..75 + 0x80 padding + length 640 bits).
    auto fill_b2 = [&](uint32_t nonce_be) {
        text[0]  = 0xCAFEBABE;
        text[1]  = 0xDEADBEEF;
        text[2]  = 0xFEEDFACE;
        text[3]  = nonce_be;
        text[4]  = 0x80000000;
        text[5]  = 0;
        text[6]  = 0;
        text[7]  = 0;
        text[8]  = 0;
        text[9]  = 0;
        text[10] = 0;
        text[11] = 0;
        text[12] = 0;
        text[13] = 0;
        text[14] = 0;
        text[15] = 640;  // 80 bytes total = 640 bits
    };
    auto fill_b1 = [&]() {
        for (int i = 0; i < 16; ++i) text[i] = BLK1[i];
    };
    auto fill_b3 = [&](const uint32_t digest1[8]) {
        for (int i = 0; i < 8; ++i) text[i] = digest1[i];
        text[8]  = 0x80000000;
        text[9]  = 0;
        text[10] = 0;
        text[11] = 0;
        text[12] = 0;
        text[13] = 0;
        text[14] = 0;
        text[15] = 256;  // 32-byte digest1 = 256 bits
    };

    auto save_text = [&](uint32_t out[8]) {
        for (int i = 0; i < 8; ++i) out[i] = text[i];
    };
    auto digests_match = [&](const uint32_t a[8], const uint32_t b[8]) {
        for (int i = 0; i < 8; ++i) if (a[i] != b[i]) return false;
        return true;
    };

    esp_sha_lock_engine(SHA2_256);

    // ============================================================
    // Step 1: establish reference H1 = peripheral's view of block-1 midstate
    // ============================================================
    uint32_t h1_ref[8];
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    save_text(h1_ref);
    Serial.printf("[H-PROBE] H1 (block-1 midstate) = %08x %08x %08x %08x %08x %08x %08x %08x\n",
                  h1_ref[0], h1_ref[1], h1_ref[2], h1_ref[3],
                  h1_ref[4], h1_ref[5], h1_ref[6], h1_ref[7]);

    // Step 2: reference digest1 via clean re-execution path.
    const uint32_t NONCE0 = 0x00000000;
    const uint32_t NONCE1 = 0x12345678;

    uint32_t d1_n0_ref[8];
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    fill_b2(NONCE0);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    save_text(d1_n0_ref);

    uint32_t d1_n1_ref[8];
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    fill_b2(NONCE1);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    save_text(d1_n1_ref);

    Serial.printf("[H-PROBE] digest1[nonce=0x%08x] = %08x...%08x\n",
                  NONCE0, d1_n0_ref[0], d1_n0_ref[7]);
    Serial.printf("[H-PROBE] digest1[nonce=0x%08x] = %08x...%08x\n",
                  NONCE1, d1_n1_ref[0], d1_n1_ref[7]);

    // Step 3: compute digest2 for nonce0 — leaves H in the post-mining state.
    uint32_t d2_n0_ref[8];
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    fill_b2(NONCE0);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    // Now TEXT[0..7] = digest1_n0, internal H = digest1_n0
    // Set up block-3 (single block of 32-byte digest1)
    fill_b3(d1_n0_ref);
    sha_ll_start_block(SHA2_256);  // resets H to consts, processes digest1+padding
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    save_text(d2_n0_ref);
    Serial.printf("[H-PROBE] digest2[nonce=0x%08x] = %08x...%08x (peripheral H now = digest2)\n",
                  NONCE0, d2_n0_ref[0], d2_n0_ref[7]);

    // TEST C: try block-2 CONTINUE for nonce1 without re-doing block-1.
    // If H state preserves (long-shot), readback == d1_n1_ref.
    uint32_t d1_n1_skip[8];
    fill_b2(NONCE1);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    save_text(d1_n1_skip);

    bool test_c_pass = digests_match(d1_n1_skip, d1_n1_ref);
    Serial.printf("[H-PROBE] TEST C (skip block-1 between nonces): readback = %08x...%08x\n",
                  d1_n1_skip[0], d1_n1_skip[7]);
    Serial.printf("[H-PROBE] TEST C verdict: %s\n",
                  test_c_pass ? "*** PASS — A.3 VIABLE — peripheral H persists ***"
                              : "FAIL — H got mutated by block-3 START (expected)");

    // TEST D: try NULL CONTINUE (zero-message) before next CONTINUE — long shot.
    // Reset: full re-execute up to digest2 state
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    fill_b2(NONCE0);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    fill_b3(d1_n0_ref);
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}

    // Zero CONTINUE
    for (int i = 0; i < 16; ++i) text[i] = 0;
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}

    // Now try block-2 nonce1
    fill_b2(NONCE1);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    uint32_t d1_n1_test_d[8];
    save_text(d1_n1_test_d);
    bool test_d_pass = digests_match(d1_n1_test_d, d1_n1_ref);
    Serial.printf("[H-PROBE] TEST D (null CONTINUE before): readback = %08x...%08x  %s\n",
                  d1_n1_test_d[0], d1_n1_test_d[7],
                  test_d_pass ? "*** PASS ***" : "FAIL");

    // TEST E: peripheral reset (DPORT clk_en cycle), then block-2 CONTINUE.
    fill_b1();
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    fill_b2(NONCE0);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    fill_b3(d1_n0_ref);
    sha_ll_start_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}

    // Toggle peripheral reset
    DPORT_REG_SET_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA);

    fill_b2(NONCE1);
    sha_ll_continue_block(SHA2_256);
    while (*busy) {}
    sha_ll_load(SHA2_256);
    while (*busy) {}
    uint32_t d1_n1_test_e[8];
    save_text(d1_n1_test_e);
    bool test_e_pass = digests_match(d1_n1_test_e, d1_n1_ref);
    Serial.printf("[H-PROBE] TEST E (DPORT reset cycle): readback = %08x...%08x  %s\n",
                  d1_n1_test_e[0], d1_n1_test_e[7],
                  test_e_pass ? "*** PASS ***" : "FAIL");

    // TEST F: direct write to undocumented MMIO above 0x3FF030C0 — try
    // injecting H state via suspected hidden H register addresses.
    //
    // CAUTION: arbitrary MMIO writes can fault; DPort should suppress
    // unmapped addresses, but worst case is a hang.
    static const uint32_t SHA_PERI_BASE = 0x3FF03000;
    static const uint32_t test_offsets[] = { 0xC0, 0xD0, 0xE0, 0xF0, 0x100, 0x200, 0x300 };
    int test_f_passes = 0;
    for (size_t k = 0; k < sizeof(test_offsets)/sizeof(test_offsets[0]); ++k) {
        uint32_t off = test_offsets[k];

        // Re-establish polluted state (H = digest2_n0)
        fill_b1();
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        fill_b2(NONCE0);
        sha_ll_continue_block(SHA2_256);
        while (*busy) {}
        fill_b3(d1_n0_ref);
        sha_ll_start_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}

        // Write H1_ref to suspected H register slots
        volatile uint32_t * suspect_h = (volatile uint32_t *)(SHA_PERI_BASE + off);
        for (int i = 0; i < 8; ++i) suspect_h[i] = h1_ref[i];

        // Try block-2 CONTINUE
        fill_b2(NONCE1);
        sha_ll_continue_block(SHA2_256);
        while (*busy) {}
        sha_ll_load(SHA2_256);
        while (*busy) {}
        uint32_t d1_n1_test_f[8];
        save_text(d1_n1_test_f);
        bool match = digests_match(d1_n1_test_f, d1_n1_ref);
        if (match) test_f_passes++;
        Serial.printf("[H-PROBE] TEST F off=0x%03x: readback %08x...%08x  %s\n",
                      (unsigned)off, d1_n1_test_f[0], d1_n1_test_f[7],
                      match ? "*** PASS ***" : "fail");
    }

    esp_sha_unlock_engine(SHA2_256);

    // ============================================================
    // SUMMARY
    // ============================================================
    Serial.printf("[H-PROBE] === Summary ===\n");
    Serial.printf("[H-PROBE] TEST C (naive skip)        : %s\n", test_c_pass ? "PASS" : "fail");
    Serial.printf("[H-PROBE] TEST D (null CONTINUE)     : %s\n", test_d_pass ? "PASS" : "fail");
    Serial.printf("[H-PROBE] TEST E (DPORT reset)       : %s\n", test_e_pass ? "PASS" : "fail");
    Serial.printf("[H-PROBE] TEST F (MMIO writes)       : %d/%d passed\n",
                  test_f_passes, (int)(sizeof(test_offsets)/sizeof(test_offsets[0])));
    if (test_c_pass || test_d_pass || test_e_pass || test_f_passes > 0) {
        Serial.printf("[H-PROBE] *** AT LEAST ONE PATH VIABLE — investigate further for A.3 deploy ***\n");
    } else {
        Serial.printf("[H-PROBE] All tests fail — A.3 confirmed impossible on classic ESP32. Pivot to Front C.\n");
    }
}

// -O3 for HW SHA fast path inline helpers + minerWorkerHw below.
#pragma GCC push_options
#pragma GCC optimize("O3")

// DPORT erratum wrappers (DPORT_INTERRUPT_DISABLE/SEQUENCE_REG_READ) target
// ECO V0/V1 silicon. On rev v3+ the erratum is fixed; plain REG_READ is safe.
static inline bool nerd_sha_ll_read_digest_swap_if(void* ptr)
{
  // C.1 — strip DPORT_SEQUENCE_REG_READ + DPORT_INTERRUPT_DISABLE wrappers.
  //
  // DPORT erratum fixed on rev v3+ silicon; plain l16ui reads safe.
  //
  // ~30-50 cyc/nonce saved by skipping the DPORT_INTERRUPT_DISABLE spinlock.
  //
  // Earlier "removed wrapper caused garbled reads on some chip revs"
  // commentary referred to chips older than v3.1 — re-introduce the wrapper
  // ONLY if pool acceptance drops on this silicon.
  volatile uint32_t * const text = (volatile uint32_t *)SHA_TEXT_BASE;
  uint32_t fin = text[7];
  if ((uint32_t)(fin & 0xFFFF) != 0) return false;
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
    const uint32_t *data_words = (const uint32_t *)input_text;
    uint32_t * const reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

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

// Pointer-argument variants: caller pins TEXT_BASE in a register across all
// stores (eliminates 26× per-nonce l32r that GCC emits in the plain helpers).
static inline void nerd_sha_ll_fill_text_block_sha256_upper_p(const void *input_text, uint32_t nonce, uint32_t * const reg_addr_buf)
{
    const uint32_t *data_words = (const uint32_t *)input_text;
    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = __builtin_bswap32(nonce);
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
}

static inline void nerd_sha_ll_fill_text_block_sha256_double_p(uint32_t * const reg_addr_buf)
{
    reg_addr_buf[8]  = 0x80000000;
    reg_addr_buf[15] = 0x00000100;
}

static inline void nerd_sha_ll_fill_text_block_sha256_p(const void *input_text, uint32_t * const reg_addr_buf)
{
    const uint32_t *data_words = (const uint32_t *)input_text;
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

// Block-2 fill: 16 stores. Block-1 fill clobbers TEXT[0..15] each nonce so
// block-2 must restore padding/zero pattern from scratch.
static inline void nerd_sha_ll_fill_text_block_sha256_upper(const void *input_text, uint32_t nonce)
{
    const uint32_t *data_words = (const uint32_t *)input_text;
    uint32_t * const reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = __builtin_bswap32(nonce);
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
}

// Block-3 fill: only TEXT[8]=0x80 and TEXT[15]=0x100 needed (TEXT[0..7] from
// LOAD, TEXT[9..14] persist as 0 from block-2 fill). Saves ~35 cyc/nonce.
static inline void nerd_sha_ll_fill_text_block_sha256_double()
{
    uint32_t * const reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);
    reg_addr_buf[8]  = 0x80000000;
    reg_addr_buf[15] = 0x00000100;
}

// Per-nonce HW-vs-SW digest comparison (debug only, ~5-10% throughput cost).
//#define VALIDATION_CLASSIC

#ifdef AXEHUB_HW_PIPELINED_ASM
extern "C" bool axehub_hw_pipelined_mine_classic(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_swapped_inout,
    volatile uint32_t *hash_count_low,
    volatile bool *mining_flag,
    uint32_t iter_budget);
// Re-init SHA peripheral (DPORT clk_en + reset clr) after a candidate hit
// to flush any sticky H state from race windows in the asm sequence.
extern "C" void axehub_hw_pipelined_reinit(void);
#endif

#ifdef AXEHUB_HW_PIPELINED_FRONT_C
#include "axehub_hw_pipelined_classic_v2.h"
#endif

void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHwEsp32D Task on core %d!\n", miner_id, xPortGetCoreID());

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint8_t sha_buffer[128];
#ifdef VALIDATION_CLASSIC
  uint8_t doubleHash[32];
  uint32_t bug_count = 0;
  uint32_t hit_count = 0;
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
      memcpy(sha_buffer, job->sha_buffer, 80);

      esp_sha_lock_engine(SHA2_256);

      // Pin SHA_TEXT_BASE in a local pointer (threaded into _p helper variants)
      // so GCC keeps it in a single register across the 26 fill stores;
      // saves ~120 cyc/nonce vs the per-store l32r baseline.
      uint32_t * const sha_text  = (uint32_t *)SHA_TEXT_BASE;
      // Pin trigger + busy registers — saves per-trigger l32r; wait_idle
      // becomes a tight l32i+bnez loop on the pinned busy pointer.
      volatile uint32_t * const sha_start = (volatile uint32_t *)SHA_256_START_REG;
      volatile uint32_t * const sha_cont  = (volatile uint32_t *)SHA_256_CONTINUE_REG;
      volatile uint32_t * const sha_loadr = (volatile uint32_t *)SHA_256_LOAD_REG;
      volatile uint32_t * const sha_busy  = (volatile uint32_t *)SHA_256_BUSY_REG;
      auto wait_busy = [sha_busy]() __attribute__((always_inline)) { while (*sha_busy) {} };

#ifdef AXEHUB_HW_PIPELINED_ASM
      // Pipelined inline-asm hot loop. Processes nonces until early-reject
      // hit OR mining flag drops. See src/axehub_hw_pipelined_classic.cpp.

      // sha_buffer is ALREADY pre-bswapped at job preparation; pass through.
      const uint32_t *header_words_pl = (const uint32_t *)sha_buffer;
      uint32_t nonce_swapped_pl = __builtin_bswap32(job->nonce_start);
      uint32_t hash_count_low_pl = 0;
      volatile bool pipelined_active_pl = true;

      // SW reverify setup: nerd_sha256d_baked needs NATIVE-byte-order header
      // + locally-computed midstate + bake (job->midstate is HW-format and
      // can't be shared). One-shot ~6000 cyc, amortised over 16384 nonces.
      uint8_t  native_header_pl[80];
      uint32_t sw_midstate_pl[8];
      uint32_t sw_bake_pl[16];
      for (int i = 0; i < 20; ++i)
        ((uint32_t *)native_header_pl)[i] = __builtin_bswap32(header_words_pl[i]);
      nerd_mids(sw_midstate_pl, native_header_pl);
      nerd_sha256_bake(sw_midstate_pl, native_header_pl + 64, sw_bake_pl);

#ifdef AXEHUB_HW_PIPELINED_FRONT_C
      // Front C SW state: precompute KW[0..63] from the header's first 16
      // words; mirror into KW[64..127] as a placeholder so the second-block
      // phase of the SW double-hash cycle has entries to consume.
      AxehubFrontCState sw_front_c;
      axehub_front_c_init(&sw_front_c);
      uint32_t front_c_msg[16];
      for (int i = 0; i < 16; ++i) front_c_msg[i] = ((const uint32_t *)native_header_pl)[i];
      axehub_front_c_compute_kw(&sw_front_c.KW[0], front_c_msg);
      for (int i = 0; i < 64; ++i) sw_front_c.KW[64 + i] = sw_front_c.KW[i];
#endif

      while (pipelined_active_pl && hash_count_low_pl < job->nonce_count) {
          // Re-check job change (cheap, between hits)
          if (s_working_current_job_id != job_in_work) {
              pipelined_active_pl = false;
              break;
          }
          uint32_t hash_before = hash_count_low_pl;
          // Pass remaining nonce budget so ASM stops within local-job range
          // (otherwise overlapping local jobs converge on the same hit).
          uint32_t budget_remaining = (hash_count_low_pl < job->nonce_count)
              ? (job->nonce_count - hash_count_low_pl)
              : 0;
          if (budget_remaining == 0) break;
#ifdef AXEHUB_HW_PIPELINED_FRONT_C
          // v2 entrypoint — same contract as v1 plus SW state pointer.
          // budget_remaining is ignored by the v2 path (kept for parity with
          // the call signature; v2 exits on hit / mining flag drop only).
          (void)budget_remaining;
          bool hit_pl = axehub_hw_pipelined_mine_classic_frontc(
              (volatile uint32_t *)SHA_TEXT_BASE,
              header_words_pl,
              &nonce_swapped_pl,
              &hash_count_low_pl,
              &pipelined_active_pl,
              &sw_front_c);
#else
          bool hit_pl = axehub_hw_pipelined_mine_classic(
              (volatile uint32_t *)SHA_TEXT_BASE,
              header_words_pl,
              &nonce_swapped_pl,
              &hash_count_low_pl,
              &pipelined_active_pl,
              budget_remaining);
#endif
          uint32_t call_hashes = hash_count_low_pl - hash_before;
          // Report hashes per ASM call (1-Hz sampler needs continuous progress).
          axehub_metrics_record_hw_hashes(call_hashes);
          if (!hit_pl) break;  // mining stopped or flag-down
          // Distinguish real HW hit (TEXT[7] low 16 == 0) from SW double-hash
          // boundary (round_idx == 128); both can co-occur per iter.
          volatile uint32_t *text_pl = (volatile uint32_t *)SHA_TEXT_BASE;
#ifdef AXEHUB_HW_PIPELINED_FRONT_C
          const bool hw_hit_pl = ((text_pl[7] & 0xFFFFu) == 0);
          const bool sw_boundary_pl = (sw_front_c.round_idx >= 128);
          if (sw_boundary_pl) {
              // Discard SW state drift, advance ext_nonce, rewind round_idx
              // so the next asm call starts a fresh SW double-hash cycle.
              axehub_front_c_reset_block(&sw_front_c);
              sw_front_c.sw_ext_nonce++;

              // Throttled boundary-rate log: validates the asm round_idx
              // state machine cycles at the expected rate.
              static uint32_t s_sw_boundary_total = 0;
              static uint32_t s_sw_last_log_ms = 0;
              s_sw_boundary_total++;
              if ((s_sw_boundary_total & 0x1FFFu) == 0) {
                  const uint32_t now_ms = millis();
                  if (s_sw_last_log_ms != 0) {
                      const uint32_t dt = now_ms - s_sw_last_log_ms;
                      const uint32_t rate = (dt > 0) ? (8192u * 1000u / dt) : 0u;
                      Serial.printf("[FrontC v4 E1] sw_total=%u dt=%u ms rate=%u dh/s\n",
                                    s_sw_boundary_total, dt, rate);
                  }
                  s_sw_last_log_ms = now_ms;
              }
          }
          if (!hw_hit_pl) {
              // No HW hit: SW boundary → keep mining; otherwise flag drop.
              if (sw_boundary_pl) continue;
              break;
          }
#else
          if ((text_pl[7] & 0xFFFFu) != 0) break;
#endif

          // HIT path. Asm post-incremented nonce_swapped after writing TEXT[3]
          // and signalled BUSY-done on LOAD2 — the candidate is the value
          // hashed in this iteration, i.e. nonce_swapped - 1 (post-incr).
          uint32_t cand_swapped_pl = nonce_swapped_pl - 1;
          uint32_t cand_native_pl  = __builtin_bswap32(cand_swapped_pl);

          // SW reverify (deterministic, matches pool). Replaces raw HW
          // digest read which produced ~91% duplicate-share rejects from
          // race windows in the asm sequence.
          ((uint32_t *)(native_header_pl + 64 + 12))[0] = cand_native_pl;
          uint8_t sw_hash[32];
          nerd_sha256d_baked(sw_midstate_pl, native_header_pl + 64, sw_bake_pl, sw_hash);

          double diff_hash = diff_from_target(sw_hash);

          // Push each above-pool hit immediately (end-of-loop pushes would
          // arrive after job_pool advances and get dropped by stratum gate).
          if (diff_hash > job->difficulty) {
              if (isSha256Valid(sw_hash)) {
                  std::shared_ptr<JobResult> immediate = std::make_shared<JobResult>();
                  immediate->id = job->id;
                  immediate->nonce = cand_native_pl;
                  immediate->difficulty = diff_hash;
                  immediate->nonce_count = 0;
                  memcpy(immediate->hash, sw_hash, sizeof(sw_hash));

                  std::lock_guard<std::mutex> lock(s_job_mutex);
                  if (s_job_result_list.size() < 16)
                      s_job_result_list.push_back(immediate);
              }
          }

          // Re-init peripheral after every hit. Drops any stuck internal
          // H state so the next call starts from a clean SHA engine.
          axehub_hw_pipelined_reinit();
      }
      // Hashes already recorded per ASM call above; keep nonce_count = total
      // so stratum thread's hashes/elapsedKHs reflect actual HW work.
      result->nonce_count = hash_count_low_pl;
#else
      // Block-2 fill overlapped with block-1 compute (peripheral snapshots
      // TEXT on SHA_START). No memw/volatile — wait_busy is the boundary.
      for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        nerd_sha_ll_fill_text_block_sha256_p(sha_buffer, sha_text);
        *sha_start = 1;

        nerd_sha_ll_fill_text_block_sha256_upper_p(sha_buffer+64, job->nonce_start+n, sha_text);
        wait_busy();
        *sha_cont = 1;

        wait_busy();
        *sha_loadr = 1;

        wait_busy();
        nerd_sha_ll_fill_text_block_sha256_double_p(sha_text);
        *sha_start = 1;

        wait_busy();
        *sha_loadr = 1;
        wait_busy();   // C.1 needs LOAD complete before plain volatile read
        if (nerd_sha_ll_read_digest_swap_if(hash))
        {
#ifdef VALIDATION_CLASSIC
          // SW reference for this nonce; mismatch = corrupt HW output.
          ++hit_count;
          ((uint32_t*)(sha_buffer+64+12))[0] = job->nonce_start+n;
          nerd_sha256d_baked(job->midstate, sha_buffer+64, job->bake, doubleHash);
          bool match = true;
          for (int i = 0; i < 32; ++i) {
            if (hash[i] != doubleHash[i]) { match = false; break; }
          }
          if (!match) {
            ++bug_count;
            Serial.printf("***HW sha256 esp32 bug detected*** nonce=0x%08x (hits=%u bugs=%u)\n",
                          (unsigned)(job->nonce_start+n), (unsigned)hit_count, (unsigned)bug_count);
          } else if (hit_count <= 16) {
            Serial.printf("[VAL] HW=SW match nonce=0x%08x (hit %u)\n",
                          (unsigned)(job->nonce_start+n), (unsigned)hit_count);
          }
#endif
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
        if (
             (uint8_t)(n & 0xFF) == 0 &&
             s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n+1;
          break;
        }
      }
#endif // AXEHUB_HW_PIPELINED_ASM
      esp_sha_unlock_engine(SHA2_256);
#ifndef AXEHUB_HW_PIPELINED_ASM
      // Baseline path reports total at end of mining loop. Pipelined ASM
      // already reports per ASM call above, so this would double-count.
      axehub_metrics_record_hw_hashes(result->nonce_count);
#endif
#ifdef VALIDATION_CLASSIC
      // Per-job summary so user can see hit-rate without flooding serial
      // with per-nonce lines after the first 16.
      Serial.printf("[VAL] job=%u hits=%u bugs=%u acc=%.2f%%\n",
                    (unsigned)job->id, (unsigned)hit_count, (unsigned)bug_count,
                    hit_count ? (100.0 * (hit_count - bug_count) / hit_count) : 0.0);
      hit_count = 0;
      bug_count = 0;
#endif
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
      // Per-worker sample MUST run before sample_khs so the hw_khs/sw_khs
      // values are fresh when we feed their sum to the EMA.
      axehub_metrics_sample_per_worker_khs();
      // EMA from per-worker counters (elapsedKHs inflates on monitor stall).
      axehub_metrics_sample_khs(axehub_metrics_get_hw_khs() + axehub_metrics_get_sw_khs());

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
