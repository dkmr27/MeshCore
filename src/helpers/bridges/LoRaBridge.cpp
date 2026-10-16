#include "LoRaBridge.h"

#ifdef WITH_LORA_BRIDGE

volatile bool LoRaBridge::_irq_flag = false;

#if defined(ESP8266) || defined(ESP32)
ICACHE_RAM_ATTR
#endif
void LoRaBridge::onIrq() {
  _irq_flag = true;  // RX done or TX done
}

LoRaBridge::LoRaBridge(NodePrefs *prefs, PhysicalLayer &radio, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc), _radio(&radio) {}

void LoRaBridge::begin() {
  BRIDGE_DEBUG_PRINTLN("Initializing LoRa bridge...\n");

  _tx_head = _tx_count = 0;
  _transmitting = false;
  _irq_flag = false;
  _radio->setPacketReceivedAction(onIrq);  // also the TX done interrupt

  int err = _radio->startReceive();
  if (err != RADIOLIB_ERR_NONE) {
    BRIDGE_DEBUG_PRINTLN("startReceive failed (%d), bridge not started\n", err);
    _radio->clearPacketReceivedAction();
    return;
  }

  _initialized = true;
}

void LoRaBridge::end() {
  BRIDGE_DEBUG_PRINTLN("Stopping...\n");
  _radio->clearPacketReceivedAction();
  _radio->standby();
  _tx_count = 0;
  _transmitting = false;

  _initialized = false;
}

void LoRaBridge::startRecv() {
  int err = _radio->startReceive();
  if (err != RADIOLIB_ERR_NONE) {
    BRIDGE_DEBUG_PRINTLN("startReceive failed (%d)\n", err);
  }
}

void LoRaBridge::startNextTx() {
  TxSlot &slot = _tx_queue[_tx_head];
  _tx_head = (_tx_head + 1) % TX_QUEUE_SIZE;
  _tx_count--;

  int err = _radio->startTransmit(slot.data, slot.len);
  if (err != RADIOLIB_ERR_NONE) {
    BRIDGE_DEBUG_PRINTLN("TX start failed (%d), len=%d\n", err, slot.len);
    startRecv();
    return;
  }
  _transmitting = true;
  // TX done interrupt should arrive well within 2x the air time
  _tx_expiry = millis() + (_radio->getTimeOnAir(slot.len) / 1000) * 2 + 1000;
  BRIDGE_DEBUG_PRINTLN("TX, len=%d\n", slot.len);
}

void LoRaBridge::checkRecv() {
  uint8_t raw[MAX_TRANS_UNIT + 1];
  int len = _radio->getPacketLength();
  if (len <= 0 || len > MAX_TRANS_UNIT) {
    startRecv();
    return;
  }

  int err = _radio->readData(raw, len);
  float snr = _radio->getSNR();
  float rssi = _radio->getRSSI();
  startRecv();  // back to RX before handing the packet on

  if (err != RADIOLIB_ERR_NONE) {
    BRIDGE_DEBUG_PRINTLN("RX error (%d), len=%d\n", err, len);
    return;
  }

  mesh::Packet *pkt = _mgr->allocNew();
  if (!pkt) {
    BRIDGE_DEBUG_PRINTLN("RX failed to allocate packet\n");
    return;
  }
  if (!pkt->readFrom(raw, len) || pkt->getPayloadVer() > PAYLOAD_VER_1) {
    BRIDGE_DEBUG_PRINTLN("RX failed to parse packet, len=%d\n", len);
    _mgr->free(pkt);
    return;
  }
  pkt->_snr = snr * 4.0f;

  BRIDGE_DEBUG_PRINTLN("RX, len=%d SNR=%d RSSI=%d\n", len, (int)snr, (int)rssi);
  onPacketReceived(pkt);
}

void LoRaBridge::loop() {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  if (_irq_flag) {
    _irq_flag = false;
    if (_transmitting) {
      _radio->finishTransmit();
      _transmitting = false;
      if (_tx_count > 0) {
        startNextTx();
      } else {
        startRecv();
      }
    } else {
      checkRecv();
    }
  } else if (_transmitting && (long)(millis() - _tx_expiry) > 0) {
    BRIDGE_DEBUG_PRINTLN("TX timeout\n");
    _radio->finishTransmit();
    _transmitting = false;
    startRecv();
  }

  if (!_transmitting && _tx_count > 0) {
    startNextTx();
  }
}

void LoRaBridge::sendPacket(mesh::Packet *packet) {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }

  // Everything the mesh transmits goes out on this radio too, including repeats of packets
  // received on this radio. The mesh's own seen table stops packets from looping.
  if (_tx_count >= TX_QUEUE_SIZE) {
    BRIDGE_DEBUG_PRINTLN("TX queue full, dropping packet\n");
    return;
  }

  if (packet->getRawLength() > MAX_TRANS_UNIT) {
    BRIDGE_DEBUG_PRINTLN("TX packet too large (len=%d)\n", packet->getRawLength());
    return;
  }

  TxSlot &slot = _tx_queue[(_tx_head + _tx_count) % TX_QUEUE_SIZE];
  slot.len = packet->writeTo(slot.data);
  _tx_count++;
  // sent from loop(), so the caller's packet isn't held onto
}

void LoRaBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

#endif
