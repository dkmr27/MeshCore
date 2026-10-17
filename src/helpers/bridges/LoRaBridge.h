#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_LORA_BRIDGE

#include <helpers/radiolib/RadioLibWrappers.h>

#if !defined(LORA2_FREQ) || !defined(LORA2_BW) || !defined(LORA2_SF) || !defined(LORA2_CR) || !defined(LORA2_TX_POWER)
#error "WITH_LORA_BRIDGE needs LORA2_FREQ, LORA2_BW, LORA2_SF, LORA2_CR and LORA2_TX_POWER"
#endif

/**
 * @brief Bridge implementation using a second LoRa radio (eg. for crossband operation)
 *
 * Packets received on the second radio are passed into the mesh, and every packet the mesh
 * transmits on the main radio is also transmitted on the second radio.
 *
 * The second radio can be any RadioLibWrapper (Custom*Wrapper). The variant must initialise it
 * (chip begin(), TCXO, RF switch etc.) before begin() is called. The bridge then applies the
 * frequency, SF, BW, CR and TX power.
 *
 * Listen before talk, noise floor sampling, CAD and AGC reset follow the same settings as the
 * main radio (int.thresh, cad, agc.reset.interval).
 *
 * Configuration:
 * - Define WITH_LORA_BRIDGE as the wrapper object for the second radio
 * - bridge.source should be left as logTx (the default), so transmitted packets are bridged
 * - bridge.delay is applied to packets received on the second radio before the mesh processes them
 * - LORA2_FREQ, LORA2_BW, LORA2_SF, LORA2_CR, LORA2_TX_POWER are the second radio's settings at boot.
 *   They can be changed at runtime with setRadioParams() / setTxPower(), which are not saved.
 */
class LoRaBridge : public BridgeBase {
public:
  LoRaBridge(NodePrefs *prefs, RadioLibWrapper &radio, mesh::PacketManager *mgr, mesh::RTCClock *rtc);

  void begin() override;
  void end() override;
  void loop() override;
  void sendPacket(mesh::Packet *packet) override;
  void onPacketReceived(mesh::Packet *packet) override;

  // second radio settings, applied on the next loop() (not while transmitting)
  void setRadioParams(float freq, float bw, uint8_t sf, uint8_t cr);
  void setTxPower(int8_t dbm);
  float getFreq() const { return _freq; }
  float getBandwidth() const { return _bw; }
  uint8_t getSpreadFactor() const { return _sf; }
  uint8_t getCodingRate() const { return _cr; }
  int8_t getTxPower() const { return _tx_power; }

  // stats, same meaning as the Dispatcher's for the main radio
  RadioLibWrapper &getRadio() { return *_radio; }
  uint32_t getTotalAirTime() const { return _total_air_time; }
  uint32_t getReceiveAirTime() const { return _rx_air_time; }
  uint32_t getNumSentFlood() const { return _n_sent_flood; }
  uint32_t getNumSentDirect() const { return _n_sent_direct; }
  uint32_t getNumRecvFlood() const { return _n_recv_flood; }
  uint32_t getNumRecvDirect() const { return _n_recv_direct; }
  uint32_t getNumBusyTimeouts() const { return _n_busy_timeouts; }

private:
  static constexpr int TX_QUEUE_SIZE = 4;
  static constexpr unsigned long NOISE_FLOOR_CALIB_MILLIS = 2000;  // as Dispatcher
  static constexpr unsigned long BUSY_MAX_MILLIS = 4000;           // as Dispatcher::getCADFailMaxDuration()

  struct TxSlot {
    uint8_t len;
    bool flood;
    uint8_t data[MAX_TRANS_UNIT];
  };

  RadioLibWrapper *_radio;

  float _freq = LORA2_FREQ;
  float _bw = LORA2_BW;
  uint8_t _sf = LORA2_SF;
  uint8_t _cr = LORA2_CR;
  int8_t _tx_power = LORA2_TX_POWER;
  bool _params_pending = false;

  TxSlot _tx_queue[TX_QUEUE_SIZE];
  uint8_t _tx_head = 0;
  uint8_t _tx_count = 0;

  bool _transmitting = false;
  bool _tx_flood = false;
  uint32_t _tx_air_time = 0;
  unsigned long _tx_expiry = 0;
  unsigned long _next_tx_time = 0;
  unsigned long _busy_start = 0;
  unsigned long _next_floor_calib = 0;
  unsigned long _next_agc_reset = 0;

  uint32_t _total_air_time = 0, _rx_air_time = 0;
  uint32_t _n_sent_flood = 0, _n_sent_direct = 0;
  uint32_t _n_recv_flood = 0, _n_recv_direct = 0;
  uint32_t _n_busy_timeouts = 0;

  void checkSendDone();
  void checkRecv();
  void checkSend();
  void startNextTx();
  void applyRadioParams();
};

#endif
