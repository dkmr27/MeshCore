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

#ifdef RF_SWITCH_TABLE
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR11X0_DIO5,
  RADIOLIB_LR11X0_DIO6,
  RADIOLIB_LR11X0_DIO7,
  RADIOLIB_LR11X0_DIO8,
  RADIOLIB_NC
};

static const Module::RfSwitchMode_t rfswitch_table[] = {
  // mode                 DIO5  DIO6	DIO7	DIO8
  { LR11x0::MODE_STBY,   {LOW,  LOW,	LOW,	LOW  }},
  { LR11x0::MODE_RX,     {LOW,  LOW,	HIGH,	LOW  }},
  { LR11x0::MODE_TX,     {LOW,	LOW,  HIGH, HIGH }},
  { LR11x0::MODE_TX_HP,  {LOW, 	LOW,	LOW,	LOW  }},
  { LR11x0::MODE_TX_HF,  {LOW,  HIGH,	LOW,	LOW  }},
  { LR11x0::MODE_GNSS,   {LOW,  LOW,	LOW,	LOW  }},
  { LR11x0::MODE_WIFI,   {LOW,  LOW,	LOW,	LOW  }},
  END_OF_MODE_TABLE,
};
#endif

bool radio_init() {
  fallback_clock.begin();
  rtc_clock.begin(Wire);

#if defined(P_LORA_SCLK)
  int err = radio.std_init(&spi);
  if (err != 1) return err;
#else
  int err = radio.std_init();
  if (err != 1) return err;
#endif

#ifdef RF_SWITCH_TABLE 
  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);
#endif

  return true;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}
