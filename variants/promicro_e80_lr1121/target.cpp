#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>
#include <RadioLib.h>


PromicroBoard board;

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);

WRAPPER_CLASS radio_driver(radio, board);

VolatileRTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);
#if ENV_INCLUDE_GPS
  #include <helpers/sensors/MicroNMEALocationProvider.h>
  MicroNMEALocationProvider nmea = MicroNMEALocationProvider(Serial1, &rtc_clock);
  EnvironmentSensorManager sensors = EnvironmentSensorManager(nmea);
#else
  EnvironmentSensorManager sensors;
#endif

#ifdef DISPLAY_CLASS
  DISPLAY_CLASS display;
  MomentaryButton user_btn(PIN_USER_BTN, 1000, true, true);
#endif

#ifdef RF_SWITCH_TABLE
static const uint32_t rfswitch_dios[Module::RFSWITCH_MAX_PINS] = {
  RADIOLIB_LR11X0_DIO5,
  RADIOLIB_LR11X0_DIO6,
  RADIOLIB_NC,
  RADIOLIB_NC,
  RADIOLIB_NC
};

static const Module::RfSwitchMode_t rfswitch_table[] = {
  // mode                 DIO5  DIO6
  { LR11x0::MODE_STBY,   {LOW,  LOW  }},
  { LR11x0::MODE_RX,     {LOW,  HIGH  }},
  { LR11x0::MODE_TX,     {HIGH, HIGH }},
  { LR11x0::MODE_TX_HP,  {HIGH, LOW }},
  { LR11x0::MODE_TX_HF,  {LOW,  LOW  }},
  { LR11x0::MODE_GNSS,   {LOW,  LOW  }},
  { LR11x0::MODE_WIFI,   {LOW,  LOW  }},
  END_OF_MODE_TABLE,
};
#endif

bool radio_init() {
  rtc_clock.begin(Wire);

  int err = radio.std_init(&SPI);
  if (err != 1) return err;

#ifdef RF_SWITCH_TABLE 
  radio.setRfSwitchTable(rfswitch_dios, rfswitch_table);
#endif

  return true;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}


