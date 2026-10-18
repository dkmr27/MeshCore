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
    PacketMillis pm = calcMaxPacketMillis(sf, bw, cr, preambleLengthForSF(sf));
    ((CustomSX1280 *)_radio)->setPreambleMillis(pm.preambleMillis);
    ((CustomSX1280 *)_radio)->setMaxPayloadMillis(pm.payloadMillis);
  }
  
  bool isReceivingPacket() override {
    return ((CustomSX1280 *)_radio)->isReceiving();
  }
  float getCurrentRSSI() override {
    return ((CustomSX1280 *)_radio)->getRSSI(false);
  }
  float getLastRSSI() const override { return ((CustomSX1280 *)_radio)->getRSSI(); }
  float getLastSNR() const override { return ((CustomSX1280 *)_radio)->getSNR(); }

  float packetScore(float snr, int packet_len) override {
    int sf = ((CustomSX1280 *)_radio)->spreadingFactor;
    return packetScoreInt(snr, sf, packet_len);
  }

  uint8_t getSpreadingFactor() const override { return ((CustomSX1280 *)_radio)->spreadingFactor; }

  virtual void powerOff() override {
    ((CustomSX1280 *)_radio)->sleep(false);
  }

  void doResetAGC() override { ((CustomSX1280 *)_radio)->standby(); }
};