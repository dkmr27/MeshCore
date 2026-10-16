#pragma once

#include <helpers/ESP32Board.h>
#include <Arduino.h>

// BAYCKRC C3 900/2400 Dual Band 100mW Gemini RX
// ESP32-C3 + 2x LR1121 on a shared SPI bus (ELRS layout "Generic C3 LR1121 True Diversity").
class BayckRCGeminiBoard : public ESP32Board {
public:
  void begin() {
  #ifdef P_LORA2_NSS
    // second LR1121 shares the SPI bus, keep it deselected until it is driven
    pinMode(P_LORA2_NSS, OUTPUT);
    digitalWrite(P_LORA2_NSS, HIGH);
  #endif

    ESP32Board::begin();

    esp_reset_reason_t reason = esp_reset_reason();
    if (reason == ESP_RST_DEEPSLEEP) {
      long wakeup_source = esp_sleep_get_gpio_wakeup_status();
      if (wakeup_source & (1 << P_LORA_DIO_1)) {  // received a LoRa packet (while in deep sleep)
        startup_reason = BD_STARTUP_RX_PACKET;
      }
    }
  }

  uint16_t getBattMilliVolts() override {
    return 0;  // not supported
  }

  const char* getManufacturerName() const override {
    return "BAYCKRC C3 Gemini";
  }
};
