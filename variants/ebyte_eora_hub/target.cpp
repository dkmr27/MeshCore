#include <Arduino.h>
#include "target.h"

EoraHubBoard board;

#if defined(P_LORA_SCLK)
  static SPIClass spi;
  RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, spi);
#else
  RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY);
#endif

WRAPPER_CLASS radio_driver(radio, board);

ESP32RTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);
SensorManager sensors;

#ifdef DISPLAY_CLASS
  DISPLAY_CLASS display;
  MomentaryButton user_btn(PIN_USER_BTN, 1000, true);
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

uint32_t radio_get_rng_seed() {
  return radio.random(0x7FFFFFFF);
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng);  // create new random identity
}
