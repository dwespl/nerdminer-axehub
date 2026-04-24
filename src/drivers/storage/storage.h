#ifndef _STORAGE_H_
#define _STORAGE_H_

#include <Arduino.h>

// config files

// default settings
#ifndef HAN
#define DEFAULT_SSID		"NerdMinerAP"
#else
#define DEFAULT_SSID		"HanSoloAP"
#endif
#define DEFAULT_WIFIPW		"MineYourCoins"
#define DEFAULT_POOLURL		""
#define DEFAULT_POOLPASS	"x"
#define DEFAULT_WALLETID	""
#define DEFAULT_POOLPORT	3333
#define DEFAULT_TIMEZONE	0
#define DEFAULT_SAVESTATS	false
#define DEFAULT_INVERTCOLORS	false
#define DEFAULT_BRIGHTNESS	250

// JSON config files
#define JSON_CONFIG_FILE	"/config.json"

// JSON config file SD card (for user interaction, readme.md)
#define JSON_KEY_SSID		"SSID"
#define JSON_KEY_PASW		"WifiPW"
#define JSON_KEY_POOLURL	"PoolUrl"
#define JSON_KEY_POOLPASS	"PoolPassword"
#define JSON_KEY_WALLETID	"BtcWallet"
#define JSON_KEY_POOLPORT	"PoolPort"
#define JSON_KEY_TIMEZONE	"Timezone"
#define JSON_KEY_STATS2NV	"SaveStats"
#define JSON_KEY_INVCOLOR	"invertColors"
#define JSON_KEY_BRIGHTNESS	"Brightness"

// JSON config file SPIFFS (different for backward compatibility with existing devices)
#define JSON_SPIFFS_KEY_POOLURL		"poolString"
#define JSON_SPIFFS_KEY_POOLPORT	"portNumber"
#define JSON_SPIFFS_KEY_POOLPASS	"poolPassword"
#define JSON_SPIFFS_KEY_WALLETID	"btcString"
#define JSON_SPIFFS_KEY_TIMEZONE	"gmtZone"
#define JSON_SPIFFS_KEY_STATS2NV	"saveStatsToNVS"
#define JSON_SPIFFS_KEY_INVCOLOR	"invertColors"
#define JSON_SPIFFS_KEY_BRIGHTNESS	"Brightness"

// Fallback pool config — written only by the AxeHub API, not by WiFiManager.
#define JSON_SPIFFS_KEY_FB_POOLURL	"fbPoolString"
#define JSON_SPIFFS_KEY_FB_POOLPORT	"fbPortNumber"
#define JSON_SPIFFS_KEY_FB_POOLPASS	"fbPoolPassword"
#define JSON_SPIFFS_KEY_FB_WALLETID	"fbBtcString"

// Webhook config — empty URL disables push events.
#define JSON_SPIFFS_KEY_WH_URL		"axhWebhookUrl"
#define JSON_SPIFFS_KEY_WH_THRESH	"axhShareAboveDiff"

// Pool stats API override — empty means auto-detect from known pools.
// URL gets btcWallet appended ("<url>" + btcWallet).
#define JSON_SPIFFS_KEY_POOL_STATS_URL	"axhPoolStatsUrl"

// Coin selector for network-data display (block height, difficulty, price).
// Values: "BC2" (default), "BTC", "custom" — SHA-256 chains only.
#define JSON_SPIFFS_KEY_COIN_TICKER	"axhCoinTicker"

// Optional per-coin URL overrides (only used when ticker == "custom").
#define JSON_SPIFFS_KEY_COIN_HEIGHT_URL		"axhCoinHeightUrl"
#define JSON_SPIFFS_KEY_COIN_DIFF_URL		"axhCoinDiffUrl"
#define JSON_SPIFFS_KEY_COIN_PRICE_URL		"axhCoinPriceUrl"
#define JSON_SPIFFS_KEY_COIN_HASH_URL		"axhCoinHashUrl"

// settings
struct TSettings
{
	String WifiSSID{ DEFAULT_SSID };
	String WifiPW{ DEFAULT_WIFIPW };
	String PoolAddress{ DEFAULT_POOLURL };
	char BtcWallet[80]{ DEFAULT_WALLETID };
	char PoolPassword[80]{ DEFAULT_POOLPASS };
	int PoolPort{ DEFAULT_POOLPORT };
	int Timezone{ DEFAULT_TIMEZONE };
	bool saveStats{ DEFAULT_SAVESTATS };
	bool invertColors{ DEFAULT_INVERTCOLORS };
	int Brightness{ DEFAULT_BRIGHTNESS };

	// Fallback pool — empty PoolAddress means "no fallback configured".
	String FallbackPoolAddress{ "" };
	char   FallbackBtcWallet[80]{ "" };
	char   FallbackPoolPassword[80]{ "x" };
	int    FallbackPoolPort{ 0 };

	// AxeHub webhook target — empty WebhookUrl disables outbound push.
	String WebhookUrl{ "" };
	double WebhookShareAboveDiffThreshold{ 0.0 };  // 0 disables share_above_diff events

	// Pool stats API override. Empty = fall back to auto-detection based on
	// PoolAddress (known pools only); missing → show local stats. Non-empty =
	// always hit this URL (wallet appended).
	String PoolStatsApiUrl{ "" };

	// Coin selector for block-chain display data. "BC2" (default — uses
	// bc2mempool.com), "BTC" (mempool.space + coingecko), "custom" (uses
	// the URLs below). SHA-256 chains only — scrypt coins like LTC/DOGE
	// are not implemented.
	String CoinTicker{ "BC2" };
	String CoinHeightApiUrl{ "" };
	String CoinDifficultyApiUrl{ "" };
	String CoinPriceApiUrl{ "" };
	String CoinGlobalHashApiUrl{ "" };
};

#endif // _STORAGE_H_