#include "LoRaBridge.h"

#include <helpers/TxtDataHelpers.h>

#ifdef WITH_LORA_BRIDGE

static bool millisPassed(unsigned long t) {
  return (long)(millis() - t) >= 0;
}

LoRaBridge::LoRaBridge(NodePrefs *prefs, RadioLibWrapper &radio, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc), _radio(&radio) {}

void LoRaBridge::begin() {
  BRIDGE_DEBUG_PRINTLN("Initializing LoRa bridge...\n");

  _tx_head = _tx_count = 0;
  _transmitting = false;
  _busy_start = 0;
  _next_tx_time = _next_floor_calib = millis();
  _next_agc_reset = millis() + ((unsigned long)_prefs->agc_reset_interval) * 4000;

  _radio->begin();   // attaches this radio's interrupt
  applyRadioParams();

  // starts receive. Full size buffer, as a packet may already be waiting if the bridge was restarted
  uint8_t raw[MAX_TRANS_UNIT + 1];
  _radio->recvRaw(raw, MAX_TRANS_UNIT);
  if (!_radio->isInRecvMode()) {
    BRIDGE_DEBUG_PRINTLN("radio failed to start receive, bridge not started\n");
    return;
  }

  _initialized = true;
}

void LoRaBridge::end() {
  BRIDGE_DEBUG_PRINTLN("Stopping...\n");
  // radio is left in receive, packets are just no longer handled
  _tx_count = 0;
  _transmitting = false;

  _initialized = false;
}

void LoRaBridge::setRadioParams(float freq, float bw, uint8_t sf, uint8_t cr) {
  _freq = freq;
  _bw = bw;
  _sf = sf;
  _cr = cr;
  _params_pending = true;
}

void LoRaBridge::setTxPower(int8_t dbm) {
  _tx_power = dbm;
  _params_pending = true;
}

void LoRaBridge::applyRadioParams() {
  _radio->idle();   // standby while reconfiguring, receive restarts on the next recvRaw()
  _radio->setParams(_freq, _bw, _sf, _cr);
  _radio->setTxPower(_tx_power);
  _params_pending = false;

  char freq[16], bw[16];
  strcpy(freq, StrHelper::ftoa(_freq));
  strcpy(bw, StrHelper::ftoa3(_bw));
  BRIDGE_DEBUG_PRINTLN("radio params %s,%s,%d,%d tx=%d\n", freq, bw, _sf, _cr, _tx_power);
}

void LoRaBridge::checkSendDone() {
  if (_radio->isSendComplete()) {
    _radio->onSendFinished();
    _transmitting = false;
    _total_air_time += _tx_air_time;
    if (_tx_flood) {
      _n_sent_flood++;
    } else {
      _n_sent_direct++;
    }
  } else if (millisPassed(_tx_expiry)) {
    BRIDGE_DEBUG_PRINTLN("TX timeout\n");
    _radio->onSendFinished();
    _transmitting = false;
  }
}

void LoRaBridge::checkRecv() {
  uint8_t raw[MAX_TRANS_UNIT + 1];
  int len = _radio->recvRaw(raw, MAX_TRANS_UNIT);   // also (re)starts receive when needed
  if (len <= 0) return;

  _rx_air_time += _radio->getEstAirtimeFor(len);

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
  pkt->_snr = _radio->getLastSNR() * 4.0f;

  if (pkt->isRouteFlood()) {
    _n_recv_flood++;
  } else {
    _n_recv_direct++;
  }

  BRIDGE_DEBUG_PRINTLN("RX, len=%d SNR=%d RSSI=%d\n", len, (int)_radio->getLastSNR(), (int)_radio->getLastRSSI());
  onPacketReceived(pkt);
}

void LoRaBridge::checkSend() {
  if (_tx_count == 0 || !millisPassed(_next_tx_time)) return;

  // listen before talk, as Dispatcher::checkSend()
  if (_radio->isReceiving()) {
    if (_busy_start == 0) {
      _busy_start = millis();
      BRIDGE_DEBUG_PRINTLN("channel busy, deferring TX (%d queued)\n", _tx_count);
    }
    if (millis() - _busy_start <= BUSY_MAX_MILLIS) {
      _next_tx_time = millis() + random(1, 4) * 120;   // as Mesh::getCADFailRetryDelay()
      return;
    }
    // busy for too long (radio might be in a bad state), send anyway
    BRIDGE_DEBUG_PRINTLN("channel busy max duration reached\n");
    _n_busy_timeouts++;
  }
  _busy_start = 0;

  startNextTx();
}

void LoRaBridge::startNextTx() {
  TxSlot &slot = _tx_queue[_tx_head];
  _tx_head = (_tx_head + 1) % TX_QUEUE_SIZE;
  _tx_count--;

  uint32_t air_time = _radio->getEstAirtimeFor(slot.len);
  if (!_radio->startSendRaw(slot.data, slot.len)) {
    BRIDGE_DEBUG_PRINTLN("TX start failed, len=%d\n", slot.len);
    return;
  }
  _transmitting = true;
  _tx_flood = slot.flood;
  _tx_air_time = air_time;
  _tx_expiry = millis() + air_time * 3 / 2 + 1000;
  BRIDGE_DEBUG_PRINTLN("TX, len=%d\n", slot.len);
}

void LoRaBridge::loop() {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  // per-radio housekeeping, as Dispatcher::loop()
  if (millisPassed(_next_floor_calib)) {
    _radio->triggerNoiseFloorCalibrate(_prefs->interference_threshold);
    _next_floor_calib = millis() + NOISE_FLOOR_CALIB_MILLIS;
  }
  _radio->setCADEnabled(_prefs->cad_enabled);
  _radio->loop();

  if (_transmitting) {
    checkSendDone();
    if (_transmitting) return;   // still sending
  }

  if (_params_pending) {
    applyRadioParams();
  }

  checkRecv();

  if (_prefs->agc_reset_interval > 0 && millisPassed(_next_agc_reset)) {
    _radio->resetAGC();
    _next_agc_reset = millis() + ((unsigned long)_prefs->agc_reset_interval) * 4000;
  }

  checkSend();
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
  slot.flood = packet->isRouteFlood();
  _tx_count++;
  // sent from loop(), so the caller's packet isn't held onto
}

void LoRaBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

#endif
