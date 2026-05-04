#define ESP_DRD_USE_SPIFFS true

// Include Libraries
//#include ".h"

#include <WiFi.h>

#include <WiFiManager.h>

#include "wManager.h"
#include "monitor.h"
#include "drivers/displays/display.h"
#include "drivers/storage/SDCard.h"
#include "drivers/storage/nvMemory.h"
#include "drivers/storage/storage.h"
#include "mining.h"
#include "timeconst.h"

#include <ArduinoJson.h>
#include <esp_flash.h>


// Flag for saving data
bool shouldSaveConfig = false;

// Variables to hold data from custom textboxes
TSettings Settings;

// Define WiFiManager Object
WiFiManager wm;
extern monitor_data mMonitor;

nvMemory nvMem;

extern SDCard SDCrd;

// Webflasher provisioning blob at flash offset 0x3F0000 (coredump partition).
// 4KB sector with prefix "WEBFLASHER_CONFIG:" + JSON. Applied on boot and
// erased so it doesn't re-apply.
//
// JSON keys (all optional): apname, wifi_ssid, wifi_pass, pool_url,
// pool_port, pool_pass, wallet, timezone.

#define WEBFLASHER_BLOB_OFFSET   0x3F0000
#define WEBFLASHER_BLOB_SIZE     0x1000   // one 4KB sector (must align to erase block)
#define WEBFLASHER_BLOB_MARKER   "WEBFLASHER_CONFIG:"

static bool s_webflasherApplied = false;
static String s_webflasherAPName = "";

bool applyWebflasherConfig(TSettings* settings_out) {
    uint8_t buffer[WEBFLASHER_BLOB_SIZE];
    memset(buffer, 0xFF, sizeof(buffer));

    esp_err_t r = esp_flash_read(NULL, buffer, WEBFLASHER_BLOB_OFFSET, sizeof(buffer));
    if (r != ESP_OK) {
        Serial.printf("[Webflasher] flash read err 0x%X\n", r);
        return false;
    }

    String data((const char*)buffer);
    if (!data.startsWith(WEBFLASHER_BLOB_MARKER)) {
        Serial.println("[Webflasher] no provisioning blob present");
        return false;
    }

    String jsonPart = data.substring(strlen(WEBFLASHER_BLOB_MARKER));
    DynamicJsonDocument doc(2048);
    DeserializationError err = deserializeJson(doc, jsonPart);
    if (err != DeserializationError::Ok) {
        Serial.printf("[Webflasher] JSON parse err: %s\n", err.c_str());
        return false;
    }

    bool any = false;

    if (doc.containsKey("apname")) {
        String v = doc["apname"].as<String>();
        v.trim();
        if (v.length() > 0 && v.length() < 32) {
            s_webflasherAPName = v;
            Serial.printf("[Webflasher] apname=%s\n", v.c_str());
            any = true;
        }
    }
    if (doc.containsKey("wifi_ssid") && settings_out) {
        String ssid = doc["wifi_ssid"].as<String>();
        String pass = doc.containsKey("wifi_pass") ? doc["wifi_pass"].as<String>() : String("");
        if (ssid.length() > 0) {
            settings_out->WifiSSID = ssid;
            settings_out->WifiPW   = pass;
            // Persist into ESP NVS (nvs.net80211) so WiFiManager.autoConnect()
            // finds them on next attempt without entering the captive portal.
            WiFi.persistent(true);
            WiFi.mode(WIFI_STA);
            WiFi.begin(ssid.c_str(), pass.c_str());
            Serial.printf("[Webflasher] wifi_ssid=%s (creds saved to NVS)\n", ssid.c_str());
            any = true;
        }
    }
    if (doc.containsKey("pool_url") && settings_out) {
        settings_out->PoolAddress = doc["pool_url"].as<String>();
        Serial.printf("[Webflasher] pool_url=%s\n", settings_out->PoolAddress.c_str());
        any = true;
    }
    if (doc.containsKey("pool_port") && settings_out) {
        settings_out->PoolPort = doc["pool_port"].as<int>();
        Serial.printf("[Webflasher] pool_port=%d\n", settings_out->PoolPort);
        any = true;
    }
    if (doc.containsKey("pool_pass") && settings_out) {
        const char* p = doc["pool_pass"].as<const char*>();
        if (p) { strlcpy(settings_out->PoolPassword, p, sizeof(settings_out->PoolPassword)); any = true; }
    }
    if (doc.containsKey("wallet") && settings_out) {
        const char* p = doc["wallet"].as<const char*>();
        if (p) {
            strlcpy(settings_out->BtcWallet, p, sizeof(settings_out->BtcWallet));
            Serial.printf("[Webflasher] wallet=%s\n", settings_out->BtcWallet);
            any = true;
        }
    }
    if (doc.containsKey("timezone") && settings_out) {
        settings_out->Timezone = doc["timezone"].as<int>();
        any = true;
    }

    if (any) {
        // Wipe the sector so a subsequent reboot doesn't re-apply stale provisioning.
        esp_err_t e = esp_flash_erase_region(NULL, WEBFLASHER_BLOB_OFFSET, WEBFLASHER_BLOB_SIZE);
        if (e == ESP_OK)
            Serial.println("[Webflasher] provisioning applied; blob erased.");
        else
            Serial.printf("[Webflasher] applied but erase failed: 0x%X\n", e);
        s_webflasherApplied = true;
    }
    return any;
}

String readCustomAPName() {
    return s_webflasherAPName;
}

void saveConfigCallback()
// Callback notifying us of the need to save configuration
{
    Serial.println("Should save config");
    shouldSaveConfig = true;    
    //wm.setConfigPortalBlocking(false);
}

/* void saveParamsCallback()
// Callback notifying us of the need to save configuration
{
    Serial.println("Should save config");
    shouldSaveConfig = true;
    nvMem.saveConfig(&Settings);
} */

void configModeCallback(WiFiManager* myWiFiManager)
// Called when config mode launched
{
    Serial.println("Entered Configuration Mode");
    drawSetupScreen();
    Serial.print("Config SSID: ");
    Serial.println(myWiFiManager->getConfigPortalSSID());

    Serial.print("Config IP Address: ");
    Serial.println(WiFi.softAPIP());
}

void reset_configuration()
{
    Serial.println("Erasing Config, restarting");
    nvMem.deleteConfig();
    resetStat();
    wm.resetSettings();
    ESP.restart();
}

void init_WifiManager()
{
#ifdef MONITOR_SPEED
    Serial.begin(MONITOR_SPEED);
#else
    Serial.begin(115200);
#endif //MONITOR_SPEED
    //Serial.setTxTimeoutMs(10);
    
    String customAPName;
    const char* apName = DEFAULT_SSID;

    //Init pin 15 to eneble 5V external power (LilyGo bug)
#ifdef PIN_ENABLE5V
    pinMode(PIN_ENABLE5V, OUTPUT);
    digitalWrite(PIN_ENABLE5V, HIGH);
#endif

    // Change to true when testing to force configuration every time we run
    bool forceConfig = false;

#if defined(PIN_BUTTON_2)
    // Check if button2 is pressed to enter configMode with actual configuration
    if (!digitalRead(PIN_BUTTON_2)) {
        Serial.println(F("Button pressed to force start config mode"));
        forceConfig = true;
        wm.setBreakAfterConfig(true); //Set to detect config edition and save
    }
#endif
    // Explicitly set WiFi mode
    WiFi.mode(WIFI_STA);

    bool haveSettings = nvMem.loadConfig(&Settings);

    // Webflasher provisioning blob (0x3F0000) — overlay onto loaded Settings,
    // persist if anything was applied, then erase the blob.
    if (applyWebflasherConfig(&Settings)) {
        nvMem.saveConfig(&Settings);
        haveSettings = true;
    }

    // Re-read AP name (set by applyWebflasherConfig if present in blob)
    customAPName = readCustomAPName();
    if (customAPName.length() > 0) apName = customAPName.c_str();

    if (!haveSettings)
    {
        //No config file on internal flash.
        if (SDCrd.loadConfigFile(&Settings))
        {
            //Config file on SD card.
            SDCrd.SD2nvMemory(&nvMem, &Settings); // reboot on success.
        }
        else
        {
            //No config file on SD card. Starting wifi config server.
            forceConfig = true;
        }
    };
    
    // Free the memory from SDCard class 
    SDCrd.terminate();
    
    // Reset settings (only for development)
    //wm.resetSettings();

    //Set dark theme
    //wm.setClass("invert"); // dark theme

    // Set config save notify callback
    wm.setSaveConfigCallback(saveConfigCallback);
    wm.setSaveParamsCallback(saveConfigCallback);

    // Set callback that gets called when connecting to previous WiFi fails, and enters Access Point mode
    wm.setAPCallback(configModeCallback);    

    //Advanced settings
    wm.setConfigPortalBlocking(false); //Hacemos que el portal no bloquee el firmware
    wm.setConnectTimeout(40); // how long to try to connect for before continuing
    wm.setConfigPortalTimeout(180); // auto close configportal after n seconds
    // wm.setCaptivePortalEnable(false); // disable captive portal redirection
    // wm.setAPClientCheck(true); // avoid timeout if client connected to softap
    //wm.setTimeout(120);
    //wm.setConfigPortalTimeout(120); //seconds

    // Custom elements

    // Text box (String) - 80 characters maximum
    WiFiManagerParameter pool_text_box("Poolurl", "Pool url", Settings.PoolAddress.c_str(), 80);

    // Need to convert numerical input to string to display the default value.
    char convertedValue[6];
    sprintf(convertedValue, "%d", Settings.PoolPort);

    // Text box (Number) - 7 characters maximum
    WiFiManagerParameter port_text_box_num("Poolport", "Pool port", convertedValue, 7);

    // Text box (String) - 80 characters maximum
    //WiFiManagerParameter password_text_box("Poolpassword", "Pool password (Optional)", Settings.PoolPassword, 80);

    // Text box (String) - 80 characters maximum
    WiFiManagerParameter addr_text_box("btcAddress", "Your BTC address", Settings.BtcWallet, 80);

  // Text box (Number) - 2 characters maximum
  char charZone[6];
  sprintf(charZone, "%d", Settings.Timezone);
  WiFiManagerParameter time_text_box_num("TimeZone", "TimeZone fromUTC (-12/+12)", charZone, 3);

  WiFiManagerParameter features_html("<hr><br><label style=\"font-weight: bold;margin-bottom: 25px;display: inline-block;\">Features</label>");

  char checkboxParams[24] = "type=\"checkbox\"";
  if (Settings.saveStats)
  {
    strcat(checkboxParams, " checked");
  }
  WiFiManagerParameter save_stats_to_nvs("SaveStatsToNVS", "Save mining statistics to flash memory.", "T", 2, checkboxParams, WFM_LABEL_AFTER);
  // Text box (String) - 80 characters maximum
  WiFiManagerParameter password_text_box("Poolpassword - Optional", "Pool password", Settings.PoolPassword, 80);

  // Add all defined parameters
  wm.addParameter(&pool_text_box);
  wm.addParameter(&port_text_box_num);
  wm.addParameter(&password_text_box);
  wm.addParameter(&addr_text_box);
  wm.addParameter(&time_text_box_num);
  wm.addParameter(&features_html);
  wm.addParameter(&save_stats_to_nvs);
  #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
  char checkboxParams2[24] = "type=\"checkbox\"";
  if (Settings.invertColors)
  {
    strcat(checkboxParams2, " checked");
  }
  // Default value mirrors the persisted setting. Hard-coding "T" here makes
  // the post-autoConnect read paths overwrite the loaded value with true on
  // every boot — so users with reverse-polarity panels who unchecked the
  // box could never actually disable inversion.
  const char* invertDefaultVal = Settings.invertColors ? "T" : "";
  WiFiManagerParameter invertColors("inverColors", "Invert Display Colors (if the colors looks weird)", invertDefaultVal, 2, checkboxParams2, WFM_LABEL_AFTER);
  wm.addParameter(&invertColors);
  #endif
  #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
    char brightnessConvValue[2];
    sprintf(brightnessConvValue, "%d", Settings.Brightness);
    // Text box (Number) - 3 characters maximum
    WiFiManagerParameter brightness_text_box_num("Brightness", "Screen backlight Duty Cycle (0-255)", brightnessConvValue, 3);
    wm.addParameter(&brightness_text_box_num);
  #endif

    Serial.println("AllDone: ");
    if (forceConfig)    
    {
        // Run if we need a configuration
        //No configuramos timeout al modulo
        wm.setConfigPortalBlocking(true); //Hacemos que el portal SI bloquee el firmware
        drawSetupScreen();
        mMonitor.NerdStatus = NM_Connecting;
        wm.startConfigPortal(apName, DEFAULT_WIFIPW);

        if (shouldSaveConfig)
        {
            //Could be break forced after edditing, so save new config
            Serial.println("failed to connect and hit timeout");
            Settings.PoolAddress = pool_text_box.getValue();
            Settings.PoolPort = atoi(port_text_box_num.getValue());
            strncpy(Settings.PoolPassword, password_text_box.getValue(), sizeof(Settings.PoolPassword));
            strncpy(Settings.BtcWallet, addr_text_box.getValue(), sizeof(Settings.BtcWallet));
            Settings.Timezone = atoi(time_text_box_num.getValue());
            //Serial.println(save_stats_to_nvs.getValue());
            Settings.saveStats = (strncmp(save_stats_to_nvs.getValue(), "T", 1) == 0);
            #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
                Settings.invertColors = (strncmp(invertColors.getValue(), "T", 1) == 0);
            #endif
            #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
                Settings.Brightness = atoi(brightness_text_box_num.getValue());
            #endif
            nvMem.saveConfig(&Settings);
            delay(3*SECOND_MS);
            //reset and try again, or maybe put it to deep sleep
            ESP.restart();            
        };
    }
    else
    {
        //Tratamos de conectar con la configuración inicial ya almacenada
        mMonitor.NerdStatus = NM_Connecting;
        // disable captive portal redirection
        wm.setCaptivePortalEnable(true); 
        wm.setConfigPortalBlocking(true);
        wm.setEnableConfigPortal(true);
        // if (!wm.autoConnect(Settings.WifiSSID.c_str(), Settings.WifiPW.c_str()))
        if (!wm.autoConnect(apName, DEFAULT_WIFIPW))
        {
            Serial.println("Failed to connect to configured WIFI, and hit timeout");
            if (shouldSaveConfig) {
                // Save new config            
                Settings.PoolAddress = pool_text_box.getValue();
                Settings.PoolPort = atoi(port_text_box_num.getValue());
                strncpy(Settings.PoolPassword, password_text_box.getValue(), sizeof(Settings.PoolPassword));
                strncpy(Settings.BtcWallet, addr_text_box.getValue(), sizeof(Settings.BtcWallet));
                Settings.Timezone = atoi(time_text_box_num.getValue());
                // Serial.println(save_stats_to_nvs.getValue());
                Settings.saveStats = (strncmp(save_stats_to_nvs.getValue(), "T", 1) == 0);
                #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
                Settings.invertColors = (strncmp(invertColors.getValue(), "T", 1) == 0);
                #endif
                #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
                Settings.Brightness = atoi(brightness_text_box_num.getValue());
                #endif
                nvMem.saveConfig(&Settings);
                vTaskDelay(2000 / portTICK_PERIOD_MS);      
            }        
            ESP.restart();                            
        } 
    }
    
    //Conectado a la red Wifi
    if (WiFi.status() == WL_CONNECTED) {
        // Reduce TX peak current. Default 19.5 dBm spikes ~250 mA during TX
        // bursts which, combined with two cores at 240 MHz mining, can brown
        // out weaker USB hubs/cables. 11 dBm is enough for any indoor LAN.
        WiFi.setTxPower(WIFI_POWER_11dBm);

        //tft.pushImage(0, 0, MinerWidth, MinerHeight, MinerScreen);
        Serial.println("");
        Serial.println("WiFi connected");
        Serial.print("IP address: ");
        Serial.println(WiFi.localIP());


        // Lets deal with the user config values

        // Copy the string value
        Settings.PoolAddress = pool_text_box.getValue();
        //strncpy(Settings.PoolAddress, pool_text_box.getValue(), sizeof(Settings.PoolAddress));
        Serial.print("PoolString: ");
        Serial.println(Settings.PoolAddress);

        //Convert the number value
        Settings.PoolPort = atoi(port_text_box_num.getValue());
        Serial.print("portNumber: ");
        Serial.println(Settings.PoolPort);

        // Copy the string value
        strncpy(Settings.PoolPassword, password_text_box.getValue(), sizeof(Settings.PoolPassword));
        Serial.print("poolPassword: ");
        Serial.println(Settings.PoolPassword);

        // Copy the string value
        strncpy(Settings.BtcWallet, addr_text_box.getValue(), sizeof(Settings.BtcWallet));
        Serial.print("btcString: ");
        Serial.println(Settings.BtcWallet);

        //Convert the number value
        Settings.Timezone = atoi(time_text_box_num.getValue());
        Serial.print("TimeZone fromUTC: ");
        Serial.println(Settings.Timezone);

        #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
        Settings.invertColors = (strncmp(invertColors.getValue(), "T", 1) == 0);
        Serial.print("Invert Colors: ");
        Serial.println(Settings.invertColors);        
        #endif

        #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
        Settings.Brightness = atoi(brightness_text_box_num.getValue());
        Serial.print("Brightness: ");
        Serial.println(Settings.Brightness);
        #endif

    }

    // Lets deal with the user config values

    // Copy the string value
    Settings.PoolAddress = pool_text_box.getValue();
    //strncpy(Settings.PoolAddress, pool_text_box.getValue(), sizeof(Settings.PoolAddress));
    Serial.print("PoolString: ");
    Serial.println(Settings.PoolAddress);

    //Convert the number value
    Settings.PoolPort = atoi(port_text_box_num.getValue());
    Serial.print("portNumber: ");
    Serial.println(Settings.PoolPort);

    // Copy the string value
    strncpy(Settings.PoolPassword, password_text_box.getValue(), sizeof(Settings.PoolPassword));
    Serial.print("poolPassword: ");
    Serial.println(Settings.PoolPassword);

    // Copy the string value
    strncpy(Settings.BtcWallet, addr_text_box.getValue(), sizeof(Settings.BtcWallet));
    Serial.print("btcString: ");
    Serial.println(Settings.BtcWallet);

    //Convert the number value
    Settings.Timezone = atoi(time_text_box_num.getValue());
    Serial.print("TimeZone fromUTC: ");
    Serial.println(Settings.Timezone);

    #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
    Settings.invertColors = (strncmp(invertColors.getValue(), "T", 1) == 0);
    Serial.print("Invert Colors: ");
    Serial.println(Settings.invertColors);
    #endif

    // Save the custom parameters to FS
    if (shouldSaveConfig)
    {
        nvMem.saveConfig(&Settings);
        #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
         if (Settings.invertColors) ESP.restart();                
        #endif
        #if defined(ESP32_2432S028R) || defined(ESP32_2432S028_2USB) || defined(ESP32_2432S024)
        if (Settings.Brightness != 250) ESP.restart();
        #endif
    }
}

//----------------- MAIN PROCESS WIFI MANAGER --------------
int oldStatus = 0;

void wifiManagerProcess() {

    wm.process(); // avoid delays() in loop when non-blocking and other long running code

    int newStatus = WiFi.status();
    if (newStatus != oldStatus) {
        if (newStatus == WL_CONNECTED) {
            Serial.println("CONNECTED - Current ip: " + WiFi.localIP().toString());
        } else {
            Serial.print("[Error] - current status: ");
            Serial.println(newStatus);
        }
        oldStatus = newStatus;
    }
}
