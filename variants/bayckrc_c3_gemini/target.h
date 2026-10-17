#pragma once

#define RADIOLIB_STATIC_ONLY 1
#include <RadioLib.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include <BayckRCGeminiBoard.h>
#include <helpers/radiolib/CustomLR1121Wrapper.h>
#include <helpers/AutoDiscoverRTCClock.h>
#include <helpers/SensorManager.h>

extern BayckRCGeminiBoard board;
extern WRAPPER_CLASS radio_driver;
extern AutoDiscoverRTCClock rtc_clock;
extern SensorManager sensors;

bool radio_init();
mesh::LocalIdentity radio_new_identity();

#ifdef WITH_LORA_BRIDGE
extern WRAPPER2_CLASS radio2_driver;
bool radio2_init();
#endif
