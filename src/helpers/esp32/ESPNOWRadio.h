#pragma once

#include <Mesh.h>
#include "esp_now.h"

  /**
   * @brief Common magic number used by all bridge implementations for packet identification
   *
   * This magic number is placed at the beginning of bridge packets to identify
   * them as mesh bridge packets and provide frame synchronization.
   */
  static constexpr uint16_t BRIDGE_PACKET_MAGIC = 0xC03E;

  /**
   * This magic number differentiates a client packet from a bridge packet.
   * The client packets will not be seen, so will be repeated over ESPNow once.
   */
  static constexpr uint16_t BRIDGE_CLIENT_PACKET_MAGIC = 0xC03F;

  /**
   * @brief Common field sizes used by bridge implementations
   *
   * These constants define the size of common packet fields used across bridges.
   * BRIDGE_MAGIC_SIZE is used by all bridges for packet identification.
   * BRIDGE_LENGTH_SIZE is used by bridges that need explicit length fields (like RS232).
   * BRIDGE_CHECKSUM_SIZE is used by all bridges for Fletcher-16 checksums.
   */
  static constexpr uint16_t BRIDGE_MAGIC_SIZE = sizeof(BRIDGE_PACKET_MAGIC);
  static constexpr uint16_t BRIDGE_LENGTH_SIZE = sizeof(uint16_t);
  static constexpr uint16_t BRIDGE_CHECKSUM_SIZE = sizeof(uint16_t);
  
   /**
   * ESP-NOW Protocol Structure:
   * - ESP-NOW header: 20 bytes (handled by ESP-NOW protocol)
   * - ESP-NOW payload: 250 bytes maximum
   * Total ESP-NOW packet: 270 bytes
   *
   * Our Bridge Packet Structure (must fit in ESP-NOW payload):
   * - Magic header: 2 bytes
   * - Checksum: 2 bytes
   * - Available payload: 246 bytes
   */
  static const size_t MAX_ESPNOW_PACKET_SIZE = 250;

  /**
   * Size constants for packet parsing
   */
  static const size_t MAX_PAYLOAD_SIZE = MAX_ESPNOW_PACKET_SIZE - (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE);
    
  /**
   * Performs XOR encryption/decryption of data
   * Used to isolate different mesh networks
   *
   * Uses _prefs->bridge_secret as the key in a simple XOR operation.
   * The same operation is used for both encryption and decryption.
   * While not cryptographically secure, it provides basic network isolation.
   *
   * @param data Pointer to data to encrypt/decrypt
   * @param len Length of data in bytes
   */
  void xorCrypt(uint8_t *data, size_t len);
  
    /**
   * @brief Validate received checksum against calculated checksum
   *
   * @param data Pointer to data to validate
   * @param len Length of data in bytes
   * @param received_checksum Checksum received with data
   * @return true if checksum is valid, false otherwise
   */
  bool validateChecksum(const uint8_t *data, size_t len, uint16_t received_checksum);
  
      /**
   * @brief Calculate Fletcher-16 checksum
   *
   * Based on: https://en.wikipedia.org/wiki/Fletcher%27s_checksum
   * Used to verify data integrity of received packets
   *
   * @param data Pointer to data to calculate checksum for
   * @param len Length of data in bytes
   * @return Calculated Fletcher-16 checksum
   */
  static uint16_t fletcher16(const uint8_t *data, size_t len);


class ESPNOWRadio : public mesh::Radio {

protected:
  uint32_t n_recv, n_sent;

public:
  ESPNOWRadio() { n_recv = n_sent = 0; }

  void init();
  int recvRaw(uint8_t* bytes, int sz) override;
  uint32_t getEstAirtimeFor(int len_bytes) override;
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override;
  void onSendFinished() override;
  bool isInRecvMode() const override;

  uint32_t getPacketsRecv() const { return n_recv; }
  uint32_t getPacketsSent() const { return n_sent; }
  void resetStats() { n_recv = n_sent = 0; }

  virtual float getLastRSSI() const override;
  virtual float getLastSNR() const override;

  float packetScore(float snr, int packet_len) override { return 0; }
  uint32_t intID();
  void setTxPower(uint8_t dbm);
};

#if ESPNOW_DEBUG_LOGGING && ARDUINO
  #include <Arduino.h>
  #define ESPNOW_DEBUG_PRINT(F, ...) Serial.printf("ESP-Now: " F, ##__VA_ARGS__)
  #define ESPNOW_DEBUG_PRINTLN(F, ...) Serial.printf("ESP-Now: " F "\n", ##__VA_ARGS__)
#else
  #define ESPNOW_DEBUG_PRINT(...) {}
  #define ESPNOW_DEBUG_PRINTLN(...) {}
#endif
