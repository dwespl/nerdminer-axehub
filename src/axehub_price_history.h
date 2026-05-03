#ifndef AXEHUB_PRICE_HISTORY_H
#define AXEHUB_PRICE_HISTORY_H

#include <Arduino.h>

#define AXEHUB_PRICE_HIST_SIZE 48

void axehub_price_history_tick();

void axehub_price_history_reset();

uint8_t axehub_price_history_get(float* out, uint8_t cap,
                                 float* out_min, float* out_max);

const char* axehub_price_history_label();

uint16_t axehub_price_history_version();

#endif
