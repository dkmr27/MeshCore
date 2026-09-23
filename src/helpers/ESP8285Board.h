#pragma once

#include <MeshCore.h>
#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
#include <user_interface.h>
}

#ifndef USER_BTN_PRESSED
#define USER_BTN_PRESSED LOW
#endif

#if defined(ESP8266)

#include <sys/time.h>
#include <Wire.h>

class ESP8285Board : public mesh::MainBoard {
protected:
  uint8_t startup_reason;
  bool inhibit_sleep = false;

public:
  void begin() {
    // for future use, sub-classes SHOULD call this from their begin()
    startup_reason = BD_STARTUP_NORMAL;    

    WiFi.mode(WIFI_OFF);
    WiFi.forceSleepBegin();
    delay(1);

  #ifdef P_LORA_TX_LED
    pinMode(P_LORA_TX_LED, OUTPUT);
    digitalWrite(P_LORA_TX_LED, LOW);
  #endif

 
  #if defined(PIN_BOARD_SDA) && defined(PIN_BOARD_SCL)
   #if PIN_BOARD_SDA >= 0 && PIN_BOARD_SCL >= 0
    Wire.begin(PIN_BOARD_SDA, PIN_BOARD_SCL);
   #endif
  #else
    Wire.begin();
  #endif    
  }

  float getMCUTemperature() override {
	return 0; // ESP8285 has no internal sensor
  }

  virtual void powerOff() override;
  void enterDeepSleep(uint32_t secs);

  uint32_t getIRQGpio() override {
    return P_LORA_DIO_1;
  }

  void sleep(uint32_t secs) override {

  } 

  uint8_t getStartupReason() const override { return startup_reason; }

#if defined(P_LORA_TX_LED)
  void onBeforeTransmit() override {
    digitalWrite(P_LORA_TX_LED, HIGH);   // turn TX LED on
  }
  void onAfterTransmit() override {
    digitalWrite(P_LORA_TX_LED, LOW);   // turn TX LED off
  }
#elif defined(P_LORA_TX_NEOPIXEL_LED)
  #define NEOPIXEL_BRIGHTNESS    64  // white brightness (max 255)

  void onBeforeTransmit() override {
    neopixelWrite(P_LORA_TX_NEOPIXEL_LED, NEOPIXEL_BRIGHTNESS, NEOPIXEL_BRIGHTNESS, NEOPIXEL_BRIGHTNESS);   // turn TX neopixel on (White)
  }
  void onAfterTransmit() override {
    neopixelWrite(P_LORA_TX_NEOPIXEL_LED, 0, 0, 0);   // turn TX neopixel off
  }
#endif

  uint16_t getBattMilliVolts() override {
    #ifdef PIN_VBAT_READ
    uint32_t raw = 0; 
    for (int i = 0; i < 4; i++) {
      raw += analogRead(PIN_VBAT_READ); 
    }
    raw = raw / 4;
    // 0-1v input scaled to 0-6v measurement
    uint32_t millivolts = ((uint32_t)rawValue * 6000) / 1023;
    return (uint16_t)milliVolts;
    #else
    return 0;  // not supported
    #endif
  }

  const char* getManufacturerName() const override {
    return "Generic ESP8285";
  }

  void reboot() override {
    ESP.restart();
  }

  bool startOTAUpdate(const char* id, char reply[]) override;

  void setInhibitSleep(bool inhibit) {
    inhibit_sleep = inhibit;
  }

  uint32_t getResetReason() const override {
    rst_info *rstinfo = ESP.getResetInfoPtr();
    return rstinfo->reason;
  }

  const char* getResetReasonString(uint32_t reason) {
    switch (reason) {
      case REASON_DEFAULT_RST:
        return "Power-on reset";
      case REASON_WDT_RST:
        return "Watchdog reset";
      case REASON_EXCEPTION_RST:
        return "Exception reset";
      case REASON_SOFT_WDT_RST:
        return "Software watchdog reset";
      case REASON_SOFT_RESTART:
        return "Software restart";
      case REASON_DEEP_SLEEP_AWAKE:
        return "Wake from deep sleep";
      case REASON_EXT_SYS_RST:
        return "External system reset";
      default:
        static char buf[40];
        snprintf(buf, sizeof(buf), "Unknown reset reason (%d)", reason);
        return buf;
    } 
  }
};
#endif