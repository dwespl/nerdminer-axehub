
#include <Wire.h>

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_task_wdt.h>
#include <OneButton.h>

#include "mbedtls/md.h"
#include "wManager.h"
#include "mining.h"
#include "monitor.h"
#include "drivers/displays/display.h"
#include "drivers/storage/SDCard.h"
#include "drivers/storage/nvMemory.h"
#include "ShaTests/nerdSHA_HWTest.h"
#include "timeconst.h"
#include "axehub_api.h"
#include "axehub_metrics.h"
#include "axehub_webhook.h"
#include "axehub_sha_fast.h"

#ifdef AXEHUB_OVERCLOCK_MHZ
#include <soc/rtc.h>
#endif

#ifdef AXEHUB_OVERCLOCK_BBPLL_MULT
extern "C" {
  #include "regi2c_ctrl.h"
}
// Replicate the BBPLL register field ids (private_include in IDF, not on default
// search path). These are stable across IDF versions, defined in regi2c_bbpll.h.
#define I2C_BBPLL           0x66
#define I2C_BBPLL_HOSTID    4
#define I2C_BBPLL_OC_DIV_7_0     3
#define I2C_BBPLL_OC_DIV_7_0_MSB 7
#define I2C_BBPLL_OC_DIV_7_0_LSB 0
#endif

#ifdef TOUCH_ENABLE
#include "TouchHandler.h"
#endif

#include <soc/soc_caps.h>
//#define HW_SHA256_TEST

//3 seconds WDT
#define WDT_TIMEOUT 3
//15 minutes WDT for miner task
#define WDT_MINER_TIMEOUT 900

#ifdef PIN_BUTTON_1
  OneButton button1(PIN_BUTTON_1);
#endif

#ifdef PIN_BUTTON_2
  OneButton button2(PIN_BUTTON_2);
#endif

#ifdef TOUCH_ENABLE
extern TouchHandler touchHandler;
#endif

extern monitor_data mMonitor;

#ifdef SD_ID
  SDCard SDCrd = SDCard(SD_ID);
#else  
  SDCard SDCrd = SDCard();
#endif

/**********************⚡ GLOBAL Vars *******************************/

unsigned long start = millis();
const char* ntpServer = "pool.ntp.org";

//void runMonitor(void *name);


/********* INIT *****/
void setup()
{
      //Init pin 15 to eneble 5V external power (LilyGo bug)
  #ifdef PIN_ENABLE5V
      pinMode(PIN_ENABLE5V, OUTPUT);
      digitalWrite(PIN_ENABLE5V, HIGH);
  #endif

#ifdef MONITOR_SPEED
    Serial.begin(MONITOR_SPEED);
#else
    Serial.begin(115200);
#endif //MONITOR_SPEED

  Serial.setTimeout(0);
  delay(SECOND_MS/10);

  {
    static const char* const reset_names[] = {
      "UNKNOWN","POWERON","EXT","SW","PANIC","INT_WDT","TASK_WDT","WDT",
      "DEEPSLEEP","BROWNOUT","SDIO","USB","JTAG","EFUSE","PWR_GLITCH","CPU_LOCKUP"
    };
    esp_reset_reason_t r = esp_reset_reason();
    const char* n = (r < (sizeof(reset_names)/sizeof(*reset_names))) ? reset_names[r] : "?";
    Serial.printf("[BOOT] reset_reason=%d (%s) heap_free=%u min_free=%u\n",
                  (int)r, n,
                  (unsigned)ESP.getFreeHeap(),
                  (unsigned)ESP.getMinFreeHeap());
  }


#ifdef AXEHUB_OVERCLOCK_MHZ
  /******** OVERCLOCK ATTEMPT *****/
  // setCpuFrequencyMhz has a freq whitelist; bypass via direct
  // rtc_clk_cpu_freq_set_config. Hang on unsupported freq → reflash button.
  {
    Serial.printf("[AxeHub] Pre-overclock: %u MHz\n", (unsigned)getCpuFrequencyMhz());
    // Try first the regular API for completeness.
    bool oc_ok = setCpuFrequencyMhz(AXEHUB_OVERCLOCK_MHZ);
    if (!oc_ok) {
      // Full BBPLL reconfig (NOT _fast — _fast skips PLL reprogram and
      // hangs at 480 MHz effective). For CPU=320: BBPLL=320 / div=1.
      rtc_cpu_freq_config_t conf;
      conf.source          = RTC_CPU_FREQ_SRC_PLL;
      conf.source_freq_mhz = AXEHUB_OVERCLOCK_MHZ;
      conf.div             = 1;
      conf.freq_mhz        = AXEHUB_OVERCLOCK_MHZ;
      Serial.println("[AxeHub] Attempting full rtc_clk_cpu_freq_set_config (BBPLL reprogram)...");
      Serial.flush();
      rtc_clk_cpu_freq_set_config(&conf);
    }
    uint32_t oc_actual = getCpuFrequencyMhz();
    Serial.printf("[AxeHub] Post-overclock: actual=%u MHz (api_ok=%d)\n",
                  (unsigned)oc_actual, (int)oc_ok);
  }
#endif

#ifdef AXEHUB_OVERCLOCK_BBPLL_MULT
  /******** OVERCLOCK ATTEMPT 2 — BBPLL multiplier tweak via REGI2C *****/
  // Bypass IDF freq whitelist: bump BBPLL feedback divider via I2C_BBPLL.
  // Stock OC_DIV_7_0=32 → 240 MHz; +8 ≈ +30 MHz. Risk: WiFi/flash timings
  // and silent SHA corruption — validate via pool accept_total ratio.
  Serial.printf("[AxeHub] BBPLL multiplier tweak: writing OC_DIV_7_0=%u (stock=32)\n",
                (unsigned)AXEHUB_OVERCLOCK_BBPLL_MULT);
  Serial.flush();
  REGI2C_WRITE_MASK(I2C_BBPLL, I2C_BBPLL_OC_DIV_7_0, AXEHUB_OVERCLOCK_BBPLL_MULT);
  delay(10);  // let PLL relock
  Serial.printf("[AxeHub] BBPLL multiplier applied. IDF reports CPU=%u MHz (actual is multiplied).\n",
                (unsigned)getCpuFrequencyMhz());
#endif

  /******** AXEHUB METRICS (mutex must exist before stratum/monitor tasks start) *****/
  axehub_metrics_init();

#if defined(CONFIG_IDF_TARGET_ESP32) && defined(HARDWARE_SHA265)
  // One-shot peripheral overlap probe — see mining.h for rationale.
  // Output goes to Serial; verdict gates future overlap optimisations.
  axehub_classic_overlap_canary();
  // axehub_classic_h_state_probe() — A.3 EMPIRICALLY confirmed impossible
  // 2026-04-29 EOD4. Peripheral H register has no MMIO write path (verified
  // 0/7 offsets in 0xC0..0x300 range). Function kept for future re-test.
#endif

  esp_task_wdt_init(WDT_MINER_TIMEOUT, true);
  // Idle task that would reset WDT never runs, because core 0 gets fully utilized
  disableCore0WDT();
  //disableCore1WDT();

#ifdef HW_SHA256_TEST
  while (1) HwShaTest();
#endif

  // Setup the buttons
  #if defined(PIN_BUTTON_1) && !defined(PIN_BUTTON_2) //One button device
    button1.setPressMs(5*SECOND_MS);
    button1.attachClick(switchToNextScreen);
    button1.attachDoubleClick(alternateScreenRotation);
    button1.attachLongPressStart(reset_configuration);
    button1.attachMultiClick(alternateScreenState);
  #endif

  #if defined(PIN_BUTTON_1) && defined(PIN_BUTTON_2) //Button 1 of two button device
    button1.setPressMs(5*SECOND_MS);
    button1.attachClick(alternateScreenState);
    button1.attachDoubleClick(alternateScreenRotation);
  #endif

  #if defined(PIN_BUTTON_2) //Button 2 of two button device
    button2.setPressMs(5*SECOND_MS);
    button2.attachClick(switchToNextScreen);
    button2.attachLongPressStart(reset_configuration);
  #endif

  /******** INIT NERDMINER ************/
  Serial.println("NerdMiner v2 starting......");

  // Load persisted settings BEFORE initDisplay so display init reads the
  // user-saved invertColors value. Without this, axehubCyd_Init runs with
  // the struct default (false) and the WiFi-portal checkbox toggle has no
  // visible effect — Settings only get loaded later inside init_WifiManager
  // which runs after the display has already been configured.
  extern nvMemory nvMem;
  extern TSettings Settings;
  nvMem.loadConfig(&Settings);

  /******** INIT DISPLAY ************/
  initDisplay();
  
  /******** PRINT INIT SCREEN *****/
  drawLoadingScreen();
  delay(2*SECOND_MS);

  /******** SHOW LED INIT STATUS (devices without screen) *****/
  mMonitor.NerdStatus = NM_waitingConfig;
  doLedStuff(0);

#ifdef SDMMC_1BIT_FIX
  SDCrd.initSDcard();
#endif

  /******** INIT WIFI ************/
  init_WifiManager();


// In-setup SHA canary disabled: corrupts lwIP on S3 / triggers POWERON
// resets on classic devkit. Move to deferred task if needed.

  /******** CREATE TASK TO PRINT SCREEN *****/
  //tft.pushImage(0, 0, MinerWidth, MinerHeight, MinerScreen);
  // Higher prio monitor task
  Serial.println("");
  Serial.println("Initiating tasks...");
  static const char monitor_name[] = "(Monitor)";
  #if defined(CONFIG_IDF_TARGET_ESP32)
  // Devkit (no_display path) was hanging the monitor task at ~90s uptime.
  // Bump stack to 12000 to give NVS ops + driver callbacks more headroom.
  BaseType_t res1 = xTaskCreatePinnedToCore(runMonitor, "Monitor", 12000, (void*)monitor_name, 5, NULL,1);
  #else
  BaseType_t res1 = xTaskCreatePinnedToCore(runMonitor, "Monitor", 10000, (void*)monitor_name, 5, NULL,1);
  #endif

  /******** CREATE STRATUM TASK *****/
  static const char stratum_name[] = "(Stratum)";
 #if defined(CONFIG_IDF_TARGET_ESP32) && !defined(ESP32_2432S028R) && !defined(ESP32_2432S028_2USB)
  // Reduced stack for ESP32 classic to save memory
  BaseType_t res2 = xTaskCreatePinnedToCore(runStratumWorker, "Stratum", 12000, (void*)stratum_name, 4, NULL,1);
 #elif defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB)
  // Free a little bit of the heap to the screen
  BaseType_t res2 = xTaskCreatePinnedToCore(runStratumWorker, "Stratum", 13500, (void*)stratum_name, 4, NULL,1);
 #else
  BaseType_t res2 = xTaskCreatePinnedToCore(runStratumWorker, "Stratum", 15000, (void*)stratum_name, 4, NULL,1);
 #endif

  /******** CREATE MINER TASKS *****/
  //for (size_t i = 0; i < THREADS; i++) {
  //  char *name = (char*) malloc(32);
  //  sprintf(name, "(%d)", i);

  // Start mining tasks
  //BaseType_t res = xTaskCreate(runWorker, name, 35000, (void*)name, 1, NULL);
  TaskHandle_t minerTask1, minerTask2 = NULL;
  #ifdef HARDWARE_SHA265
    // HW miner pinned to core 0 (less-contended; Monitor+Stratum on core 1).
    #if defined(CONFIG_IDF_TARGET_ESP32)
    // Was 3584 — too tight on devkit (no_display path), suspected silent
    // stack overflow showed up as POWERON resets every ~30 s with no panic.
    xTaskCreatePinnedToCore(minerWorkerHw, "MinerHw-0", 6000, (void*)0, 10, &minerTask1, 0);
    #else
    xTaskCreatePinnedToCore(minerWorkerHw, "MinerHw-0", 4096, (void*)0, 10, &minerTask1, 0);
    #endif
  #else
    #if defined(CONFIG_IDF_TARGET_ESP32)
    xTaskCreate(minerWorkerSw, "MinerSw-0", 5000, (void*)0, 1, &minerTask1); // Reduced for ESP32 classic
    #else
    xTaskCreate(minerWorkerSw, "MinerSw-0", 6000, (void*)0, 1, &minerTask1);
    #endif
  #endif
  esp_task_wdt_add(minerTask1);

#if (SOC_CPU_CORES_NUM >= 2)
  // SW miner on core 1 alongside Monitor + Stratum.
  #if defined(CONFIG_IDF_TARGET_ESP32)
  xTaskCreatePinnedToCore(minerWorkerSw, "MinerSw-1", 5000, (void*)1, 3, &minerTask2, 1);
  #else
  xTaskCreatePinnedToCore(minerWorkerSw, "MinerSw-1", 6000, (void*)1, 3, &minerTask2, 1);
  #endif
  esp_task_wdt_add(minerTask2);
#endif

  vTaskPrioritySet(NULL, 4);

  /******** MONITOR SETUP *****/
  setup_monitor();

  /******** AXEHUB API (opt-in via AXEHUB_API_ENABLED build flag) *****/
  axehub_webhook_start();
  axehub_api_start();
}

void app_error_fault_handler(void *arg) {
  // Get stack errors
  char *stack = (char *)arg;

  // Print the stack errors in the console
  esp_log_write(ESP_LOG_ERROR, "APP_ERROR", "Error Stack Code:\n%s", stack);

  // restart ESP32
  esp_restart();
}

void loop() {
  // keep watching the push buttons:
  #ifdef PIN_BUTTON_1
    button1.tick();
  #endif

  #ifdef PIN_BUTTON_2
    button2.tick();
  #endif

#ifdef TOUCH_ENABLE
  touchHandler.isTouched();
#endif
  wifiManagerProcess(); // avoid delays() in loop when non-blocking and other long running code

  vTaskDelay(50 / portTICK_PERIOD_MS);
}
