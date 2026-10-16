#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_LORA_BRIDGE

#include <RadioLib.h>

/**
 * @brief Bridge implementation using a second LoRa radio (eg. for crossband operation)
 *
 * Packets received on the second radio are passed into the mesh, and every packet the mesh
 * transmits on the main radio is also transmitted on the second radio.
 *
 * The second radio must already be initialised and configured (frequency, SF, BW, CR, TX power)
 * by the variant before begin() is called. Only one LoRaBridge instance is supported.
 *
 * Configuration:
 * - Define WITH_LORA_BRIDGE as the RadioLib radio object for the second radio
 * - bridge.source should be left as logTx (the default), so transmitted packets are bridged
 * - bridge.delay is applied to packets received on the second radio before the mesh processes them
 */
class LoRaBridge : public BridgeBase {
public:
  LoRaBridge(NodePrefs *prefs, PhysicalLayer &radio, mesh::PacketManager *mgr, mesh::RTCClock *rtc);

  void begin() override;
  void end() override;
  void loop() override;
  void sendPacket(mesh::Packet *packet) override;
  void onPacketReceived(mesh::Packet *packet) override;

private:
  static constexpr int TX_QUEUE_SIZE = 4;

  struct TxSlot {
    uint8_t len;
    uint8_t data[MAX_TRANS_UNIT];
  };

  PhysicalLayer *_radio;
  TxSlot _tx_queue[TX_QUEUE_SIZE];
  uint8_t _tx_head = 0;
  uint8_t _tx_count = 0;
  bool _transmitting = false;
  unsigned long _tx_expiry = 0;

  static volatile bool _irq_flag;
  static void onIrq();

  void startRecv();
  void startNextTx();
  void checkRecv();
};

#endif
