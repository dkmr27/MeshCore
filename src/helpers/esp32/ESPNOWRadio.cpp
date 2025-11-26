#include "ESPNOWRadio.h"
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>

static uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static esp_now_peer_info_t peerInfo;
static volatile bool is_send_complete = false;
static esp_err_t last_send_result;
static uint8_t rx_buf[256];
static uint8_t last_rx_len = 0;

#ifdef ESPNOW_BRIDGE_COMPAT_RADIO
uint16_t fletcher16(const uint8_t *data, size_t len) {
  uint8_t sum1 = 0, sum2 = 0;

  for (size_t i = 0; i < len; i++) {
    sum1 = (sum1 + data[i]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }

  return (sum2 << 8) | sum1;
}

bool validateChecksum(const uint8_t *data, size_t len, uint16_t received_checksum) {
  uint16_t calculated_checksum = fletcher16(data, len);
  return received_checksum == calculated_checksum;
}

void xorCrypt(uint8_t *data, size_t len) {
  const char bridge_secret[] = ESPNOW_SECRET;
  size_t keyLen = strlen(bridge_secret);
  for (size_t i = 0; i < len; i++) {
    data[i] ^= bridge_secret[i % keyLen];
  }
}
#endif

// callback when data is sent
static void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("Send Status: %d", (int)status);
}

static void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len) {
#ifdef ESPNOW_BRIDGE_COMPAT_RADIO	

  // Ignore packets that are too small to contain header + checksum
  if (len < (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE)) {
    ESPNOW_DEBUG_PRINTLN("RX packet too small, len=%d\n", len);
    return;
  }

  // Validate total packet size
  if (len > MAX_ESPNOW_PACKET_SIZE) {
    ESPNOW_DEBUG_PRINTLN("RX packet too large, len=%d\n", len);
    return;
  }

  // Check packet header magic, accept either bridge or client originating packets
  uint16_t received_magic = (data[0] << 8) | data[1];
  if (received_magic != BRIDGE_PACKET_MAGIC && received_magic != BRIDGE_CLIENT_PACKET_MAGIC) {
    ESPNOW_DEBUG_PRINTLN("RX invalid magic 0x%04X\n", received_magic);
    return;
  }

  // Make a copy we can decrypt
  uint8_t decrypted[MAX_ESPNOW_PACKET_SIZE];
  const size_t encryptedDataLen = len - BRIDGE_MAGIC_SIZE;
  memcpy(decrypted, data + BRIDGE_MAGIC_SIZE, encryptedDataLen);

  // Try to decrypt (checksum + payload)
  xorCrypt(decrypted, encryptedDataLen);

  // Validate checksum
  uint16_t received_checksum = (decrypted[0] << 8) | decrypted[1];
  const size_t payloadLen = encryptedDataLen - BRIDGE_CHECKSUM_SIZE;

  if (!validateChecksum(decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen, received_checksum)) {
    // Failed to decrypt - likely from a different network
    ESPNOW_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04X\n", received_checksum);
    return;
  }

  ESPNOW_DEBUG_PRINTLN("RX, payload_len=%d\n", payloadLen);

  memcpy(rx_buf, decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen);
  last_rx_len = payloadLen;
  
#else	
  ESPNOW_DEBUG_PRINTLN("Recv: len = %d", len);
  memcpy(rx_buf, data, len);
  last_rx_len = len;
 #endif
}



void ESPNOWRadio::init() {
  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);
  
#ifdef ESPNOW_BRIDGE_COMPAT_RADIO 
  // Set wifi channel
  uint8_t bridge_channel = ESPNOW_CHANNEL;
  if (esp_wifi_set_channel(bridge_channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) { 
    ESPNOW_DEBUG_PRINTLN("Error setting WIFI channel to %d\n", bridge_channel);
    return;
  }
#else
  // Long Range mode
  esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_LR);
#endif

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("Error initializing ESP-NOW");
    return;
  }

  esp_wifi_set_max_tx_power(80);  // should be 20dBm

  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  is_send_complete = true;

  // Add peer        
  if (esp_now_add_peer(&peerInfo) == ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("init success");
  } else {
   // ESPNOW_DEBUG_PRINTLN("Failed to add peer");
  }
}

void ESPNOWRadio::setTxPower(uint8_t dbm) {
  esp_wifi_set_max_tx_power(dbm * 4);
}

uint32_t ESPNOWRadio::intID() {
  uint8_t mac[8];
  memset(mac, 0, sizeof(mac));
  esp_efuse_mac_get_default(mac);
  uint32_t n, m;
  memcpy(&n, &mac[0], 4);
  memcpy(&m, &mac[4], 4);
  
  return n + m;
}

bool ESPNOWRadio::startSendRaw(const uint8_t* bytes, int len) {
  // Send message via ESP-NOW
  is_send_complete = false;
	
#ifdef ESPNOW_BRIDGE_COMPAT_RADIO
	if (len > MAX_PAYLOAD_SIZE) {
      ESPNOW_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", len, MAX_PAYLOAD_SIZE);
      return false;
    }

	uint8_t buffer[MAX_ESPNOW_PACKET_SIZE];
	
	// Write magic header (2 bytes)
    buffer[0] = (BRIDGE_CLIENT_PACKET_MAGIC >> 8) & 0xFF;
    buffer[1] = BRIDGE_CLIENT_PACKET_MAGIC & 0xFF;

    // Write packet payload starting after magic header and checksum
    const size_t packetOffset = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;
    memcpy(buffer + packetOffset, bytes, len);
	
    // Calculate and add checksum (only of the payload)
    uint16_t checksum = fletcher16(buffer + packetOffset, len);
    buffer[2] = (checksum >> 8) & 0xFF; // High byte
    buffer[3] = checksum & 0xFF;        // Low byte

    // Encrypt payload and checksum (not including magic header)
    xorCrypt(buffer + BRIDGE_MAGIC_SIZE, len + BRIDGE_CHECKSUM_SIZE);

    // Total packet size: magic header + checksum + payload
    const size_t totalPacketSize = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + len;	
	    
	// Broadcast using ESP-NOW
    uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    esp_err_t result = esp_now_send(broadcastAddress, buffer, totalPacketSize);

#else
  esp_err_t result = esp_now_send(broadcastAddress, bytes, len);
#endif 
  if (result == ESP_OK) {
    n_sent++;
    ESPNOW_DEBUG_PRINTLN("Send success");
    return true;
  }
  last_send_result = result;
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("Send failed: %d", result);
  return false;

}

bool ESPNOWRadio::isSendComplete() {
  return is_send_complete;
}
void ESPNOWRadio::onSendFinished() {
  is_send_complete = true;
}

bool ESPNOWRadio::isInRecvMode() const {
  return is_send_complete;    // if NO send in progress, then we're in Rx mode
}

float ESPNOWRadio::getLastRSSI() const { return 0; }
float ESPNOWRadio::getLastSNR() const { return 0; }

int ESPNOWRadio::recvRaw(uint8_t* bytes, int sz) {
  int len = last_rx_len;
  if (last_rx_len > 0) {
    memcpy(bytes, rx_buf, last_rx_len);
    last_rx_len = 0;
    n_recv++;
  }
  return len;
}

uint32_t ESPNOWRadio::getEstAirtimeFor(int len_bytes) {
  return 4;  // Fast AF
}
