#include <Arduino.h>
#include "target.h"

BayckRCGeminiBoard board;

static SPIClass spi(FSPI);   // ESP32-C3 only has one SPI bus; the default (HSPI=1) fails to start
RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, spi);

WRAPPER_CLASS radio_driver(radio, board);

ESP32RTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);   // no I2C on this board, so no RTC to discover

SensorManager sensors;

// From ELRS target "dualc3": radio_rfsw_ctrl [31,0,4,8,8,18,0,17]
// bit0..4 = DIO5, DIO6, DIO7, DIO8, DIO10. The WIFI entry is also used by the LR1121 for 2.4GHz RX.
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR11X0_DIO5,
  RADIOLIB_LR11X0_DIO6,
  RADIOLIB_LR11X0_DIO7,
  RADIOLIB_LR11X0_DIO8,
  RADIOLIB_LR11X0_DIO10
};

static const Module::RfSwitchMode_t rfswitch_table[] = {
  // mode                 DIO5  DIO6  DIO7  DIO8  DIO10
  { LR11x0::MODE_STBY,   {LOW,  LOW,  LOW,  LOW,  LOW  }},   // 0
  { LR11x0::MODE_RX,     {LOW,  LOW,  HIGH, LOW,  LOW  }},   // 4
  { LR11x0::MODE_TX,     {LOW,  LOW,  LOW,  HIGH, LOW  }},   // 8
  { LR11x0::MODE_TX_HP,  {LOW,  LOW,  LOW,  HIGH, LOW  }},   // 8
  { LR11x0::MODE_TX_HF,  {LOW,  HIGH, LOW,  LOW,  HIGH }},   // 18
  { LR11x0::MODE_GNSS,   {LOW,  LOW,  LOW,  LOW,  LOW  }},   // 0
  { LR11x0::MODE_WIFI,   {HIGH, LOW,  LOW,  LOW,  HIGH }},   // 17
  END_OF_MODE_TABLE,
};

bool radio_init() {
  fallback_clock.begin();

  if (!radio.std_init(&spi)) return false;

  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);

  return true;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}
