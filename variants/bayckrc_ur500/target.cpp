#include <Arduino.h>
#include "target.h"

XiaoC3Board board;

#if defined(P_LORA_SCLK)
  static SPIClass spi(FSPI);
  RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, spi);
#else
  RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY);
#endif

WRAPPER_CLASS radio_driver(radio, board);

ESP32RTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);

#if ENV_INCLUDE_GPS
  #include <helpers/sensors/MicroNMEALocationProvider.h>
  MicroNMEALocationProvider nmea = MicroNMEALocationProvider(Serial1, &rtc_clock);
  EnvironmentSensorManager sensors = EnvironmentSensorManager(nmea);
#else
  EnvironmentSensorManager sensors;
#endif

#ifndef LORA_CR
  #define LORA_CR 5
#endif

#ifdef RF_SWITCH_TABLE
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR11X0_DIO5,
  RADIOLIB_LR11X0_DIO6,
  RADIOLIB_LR11X0_DIO7,
  RADIOLIB_LR11X0_DIO8,
  RADIOLIB_NC
};

static const Module::RfSwitchMode_t rfswitch_table[] = { //[15, 0, 4, 12, 0, 2, 0, 1]
  // mode                 DIO5  DIO6	DIO7	DIO8
  { LR11x0::MODE_STBY,   {LOW,  LOW,	LOW,	LOW  }},
  { LR11x0::MODE_RX,     {LOW,  LOW,	HIGH,	LOW  }},
  { LR11x0::MODE_TX,     {LOW,	LOW,  HIGH, HIGH }},
  { LR11x0::MODE_TX_HP,  {LOW, 	LOW,	LOW,	LOW  }},
  { LR11x0::MODE_TX_HF,  {LOW,  HIGH,	LOW,	LOW  }},
  { LR11x0::MODE_GNSS,   {LOW,  LOW,	LOW,	LOW  }},
  { LR11x0::MODE_WIFI,   {HIGH,  LOW,	LOW,	LOW  }},
  END_OF_MODE_TABLE,
};
#endif

bool radio_init() {
  fallback_clock.begin();
  rtc_clock.begin(Wire);

  spi.begin(P_LORA_SCLK, P_LORA_MISO, P_LORA_MOSI);
  int status = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR, RADIOLIB_LR11X0_LORA_SYNC_WORD_PRIVATE,
                           LORA_TX_POWER, 16, LR11X0_DIO3_TCXO_VOLTAGE);
  if (status != RADIOLIB_ERR_NONE) {
    Serial.print("ERROR: radio init failed: ");
    Serial.println(status);
    return false;
  }

  radio.setCRC(2);
  radio.explicitHeader();
  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);

  return true;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}
