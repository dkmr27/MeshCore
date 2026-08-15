#pragma once

#include "CustomSX1280.h"
#include "RadioLibWrappers.h"

  
#ifndef USE_SX1280
#define USE_SX1280
#endif

class CustomSX1280Wrapper : public RadioLibWrapper {
public:
  CustomSX1280Wrapper(CustomSX1280& radio, mesh::MainBoard& board) : RadioLibWrapper(radio, board) { }
  
    void setParams(float freq, float bw, uint8_t sf, uint8_t cr) override {
      ((CustomSX1280 *)_radio)->setFrequency(freq);
    ((CustomSX1280 *)_radio)->setSpreadingFactor(sf);
    ((CustomSX1280 *)_radio)->setBandwidth(bw);
    ((CustomSX1280 *)_radio)->setCodingRate(cr);
    updatePreamble(sf);
  
  }
  
  bool isReceivingPacket() override {
    return ((CustomSX1280 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    return ((CustomSX1280 *)_radio)->getRSSI(false);   // instantaneous RSSI
  }
  float getLastRSSI() const override { return ((CustomSX1280 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomSX1280 *)_radio)->getSNR(); }

  virtual void powerOff() override {
    ((CustomSX1280 *)_radio)->sleep();
  }

  // SX128x has no SX126x-style AGC reset register; returning to standby is sufficient.
  void doResetAGC() override { ((CustomSX1280 *)_radio)->standby(); }
};