#pragma once

#include <RadioLib.h>
#include "MeshCore.h"

class CustomSX1280 : public SX1280 {
  uint32_t _preambleMillis = 66;
  uint32_t _maxPayloadMillis = 3934;
  uint32_t _activityAt = 0;
  bool _headerSeen = false;

  public:
    CustomSX1280(Module *mod) : SX1280(mod) { }

  #ifdef RP2040_PLATFORM
    bool std_init(SPIClassRP2040* spi = NULL)
  #else
    bool std_init(SPIClass* spi = NULL)
  #endif
    {
  #ifdef LORA_CR
      uint8_t cr = LORA_CR;
  #else
      uint8_t cr = 5;
  #endif

  #if defined(P_LORA_SCLK)
    #ifdef NRF52_PLATFORM
      if (spi) { spi->setPins(P_LORA_MISO, P_LORA_SCLK, P_LORA_MOSI); spi->begin(); }
    #elif defined(RP2040_PLATFORM)
      if (spi) {
        spi->setMISO(P_LORA_MISO);
        spi->setSCK(P_LORA_SCLK);
        spi->setMOSI(P_LORA_MOSI);
        spi->begin();
      }
    #else
      if (spi) spi->begin(P_LORA_SCLK, P_LORA_MISO, P_LORA_MOSI);
    #endif
  #endif

      int status = begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX128X_SYNC_WORD_PRIVATE, LORA_TX_POWER, 16);
      if (status != RADIOLIB_ERR_NONE) {
        Serial.print("ERROR: radio init failed: ");
        Serial.println(status);
        return false;
      }

      setCRC(1);
      explicitHeader();


  #if defined(SX128X_RXEN) || defined(SX128X_TXEN)
    #ifndef SX128X_RXEN
      #define SX128X_RXEN RADIOLIB_NC
    #endif
    #ifndef SX128X_TXEN
      #define SX128X_TXEN RADIOLIB_NC
    #endif
      setRfSwitchPins(SX128X_RXEN, SX128X_TXEN);
  #endif


    #ifdef SX128X_RX_BOOSTED_GAIN
      setHighSensitivityMode(SX128X_RX_BOOSTED_GAIN);
    #endif

      return true;  // success
    }

    int16_t startReceive() override {
      // include the PREAMBLE_DETECTED irq bit in reported flags
      return SX1280::startReceive(RADIOLIB_SX128X_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS | (1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED), RADIOLIB_IRQ_RX_DEFAULT_MASK, 0);
    }

    bool isReceiving() {
      uint32_t irq = getIrqFlags();
      bool preamble = irq & RADIOLIB_SX128X_IRQ_PREAMBLE_DETECTED; // bit 2
      bool header   = irq & RADIOLIB_SX128X_IRQ_HEADER_VALID;      // bit 4
      bool hdrErr   = irq & RADIOLIB_SX128X_IRQ_HEADER_ERROR;        // bit 5
      uint32_t now  = millis();
      if (hdrErr) {
        clearIrqFlags(RADIOLIB_SX128X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX128X_IRQ_HEADER_VALID | RADIOLIB_SX128X_IRQ_HEADER_ERROR | RADIOLIB_SX128X_IRQ_SYNC_WORD_VALID);
        _activityAt = 0;
        _headerSeen = false;
        return false;
      }
      if (!header && _headerSeen) {
        // something cleared the header flag, reset our state.
        _activityAt = 0; _headerSeen = false;
        return false;
      }

      if (header) {
        if (!_headerSeen) { _headerSeen = true; _activityAt = now; };
        if (now - _activityAt > _maxPayloadMillis) {
          MESH_DEBUG_PRINTLN("Clearing header IRQ after %ums", _maxPayloadMillis);
          clearIrqFlags(RADIOLIB_SX128X_IRQ_PREAMBLE_DETECTED | RADIOLIB_SX128X_IRQ_HEADER_VALID | RADIOLIB_SX128X_IRQ_HEADER_ERROR | RADIOLIB_SX128X_IRQ_SYNC_WORD_VALID);
          _activityAt = 0; _headerSeen = false;
          return false;
        }
        return true;
      }
      if (preamble) {
        if (_activityAt == 0) _activityAt = now;
        if (now - _activityAt > _preambleMillis) {
          clearIrqFlags(RADIOLIB_SX128X_IRQ_PREAMBLE_DETECTED);
          _activityAt = 0;
          MESH_DEBUG_PRINTLN("Clearing preamble IRQ after %ums", _preambleMillis);

          return false;
        }
        return true;
      }
      _activityAt = 0; _headerSeen = false;
      return false;
    }

    void setPreambleMillis(uint32_t preambleMillis) {
      _preambleMillis = preambleMillis;
      MESH_DEBUG_PRINTLN("Set _preambleMillis=%u", _preambleMillis);
    }
    void setMaxPayloadMillis(uint32_t payloadMillis) {
      _maxPayloadMillis = payloadMillis;
      MESH_DEBUG_PRINTLN("Set _maxPayloadMillis=%u", _maxPayloadMillis);
    }

    bool getRxBoostedGainMode() {
      uint8_t rxGain = 0;
      readRegister(RADIOLIB_SX128X_REG_GAIN_MODE, &rxGain, 1);
      return ((rxGain & 0xC0) == 0xC0);
    }
};
