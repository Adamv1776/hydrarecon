/**
 * ESP32 Drone Detection Firmware
 * ==============================
 * 
 * Monitors WiFi channels for drone signatures,
 * analyzes probe requests/beacons, and reports
 * detections over serial to HydraRecon.
 * 
 * Hardware Requirements:
 * - ESP32 DevKit (any variant with WiFi)
 * - USB cable for serial communication
 * 
 * Upload Settings:
 * - Board: ESP32 Dev Module
 * - Upload Speed: 115200
 * - Flash Size: 4MB
 * 
 * Protocol:
 * Commands from PC:
 *   CMD:START     - Start scanning
 *   CMD:STOP      - Stop scanning  
 *   CMD:STATUS    - Get status
 *   CMD:CHANNEL:X - Set channel (1-14)
 * 
 * Data to PC:
 *   DRONE:MAC:type:ssid:rssi:channel
 *   PROBE:MAC:rssi:channel
 *   BEACON:MAC:ssid:rssi:channel
 *   STATS:packets:drones:uptime
 */

#include "WiFi.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// Known drone OUI prefixes
const char* DRONE_OUIS[] = {
  "60:60:1F",  // DJI
  "34:D2:62",  // DJI
  "48:1C:B9",  // DJI
  "98:3A:92",  // DJI
  "A0:14:3D",  // DJI
  "C4:62:6B",  // DJI
  "90:03:B7",  // Parrot
  "50:0F:10",  // Autel
  "B8:F0:09",  // Skydio
  "E8:68:E7",  // Holy Stone
  "B4:E6:2D",  // Hubsan
  "00:1A:79",  // Syma
};
const int NUM_OUIS = 12;

// Drone SSID patterns
const char* DRONE_SSID_PATTERNS[] = {
  "DJI",
  "Mavic",
  "PHANTOM",
  "SPARK",
  "MINI",
  "Parrot",
  "ANAFI",
  "AUTEL",
  "Skydio",
  "HolyStone",
  "Hubsan",
  "ZINO",
  "DRONE",
  "FPV",
  "WIFI_FPV",
  "RC_",
  "QUAD",
};
const int NUM_PATTERNS = 17;

// State
volatile bool scanning = false;
volatile int currentChannel = 1;
volatile unsigned long packetCount = 0;
volatile unsigned long droneCount = 0;
unsigned long startTime = 0;
int channelHopInterval = 100;  // ms
unsigned long lastChannelHop = 0;

// Function prototypes
void promiscuous_callback(void* buf, wifi_promiscuous_pkt_type_t type);
bool isKnownDroneOUI(const uint8_t* mac);
bool isDroneSSID(const char* ssid);
void processCommand(String cmd);
void hopChannel();
String macToString(const uint8_t* mac);

// WiFi packet structure
typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  unsigned sequence_ctrl:16;
  uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;


void setup() {
  Serial.begin(115200);
  delay(100);
  
  Serial.println("ESP32 Drone Detection v1.0");
  Serial.println("Ready for commands");
  Serial.println("STATUS:READY");
  
  // Initialize WiFi in promiscuous mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&promiscuous_callback);
}

void loop() {
  // Handle serial commands
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    processCommand(cmd);
  }
  
  // Channel hopping during scanning
  if (scanning) {
    unsigned long now = millis();
    if (now - lastChannelHop >= channelHopInterval) {
      hopChannel();
      lastChannelHop = now;
    }
    
    // Periodic stats
    static unsigned long lastStats = 0;
    if (now - lastStats >= 5000) {
      unsigned long uptime = (now - startTime) / 1000;
      Serial.printf("STATS:%lu:%lu:%lu\n", packetCount, droneCount, uptime);
      lastStats = now;
    }
  }
  
  delay(1);
}

void processCommand(String cmd) {
  cmd.toUpperCase();
  
  if (cmd == "CMD:START") {
    if (!scanning) {
      scanning = true;
      startTime = millis();
      packetCount = 0;
      droneCount = 0;
      esp_wifi_set_promiscuous(true);
      Serial.println("STATUS:SCANNING");
    }
  }
  else if (cmd == "CMD:STOP") {
    scanning = false;
    esp_wifi_set_promiscuous(false);
    Serial.println("STATUS:STOPPED");
  }
  else if (cmd == "CMD:STATUS") {
    Serial.printf("STATUS:%s:CHANNEL:%d:PACKETS:%lu:DRONES:%lu\n",
                  scanning ? "SCANNING" : "IDLE", 
                  currentChannel, packetCount, droneCount);
  }
  else if (cmd.startsWith("CMD:CHANNEL:")) {
    int ch = cmd.substring(12).toInt();
    if (ch >= 1 && ch <= 14) {
      currentChannel = ch;
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      Serial.printf("STATUS:CHANNEL:%d\n", currentChannel);
    }
  }
  else if (cmd == "CMD:PING") {
    Serial.println("PONG:ESP32_DRONE_DETECTOR");
  }
}

void hopChannel() {
  currentChannel++;
  if (currentChannel > 13) {
    currentChannel = 1;
  }
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

void promiscuous_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!scanning) return;
  
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t* hdr = &ipkt->hdr;
  
  packetCount++;
  
  // Get frame type
  uint16_t frameControl = hdr->frame_ctrl;
  uint8_t frameType = (frameControl >> 2) & 0x3;
  uint8_t frameSubtype = (frameControl >> 4) & 0xF;
  
  // Management frames
  if (frameType == 0) {
    // Probe request (subtype 4)
    if (frameSubtype == 4) {
      int rssi = pkt->rx_ctrl.rssi;
      String mac = macToString(hdr->addr2);
      
      bool isDrone = isKnownDroneOUI(hdr->addr2);
      
      // Check for SSID in payload
      if (pkt->rx_ctrl.sig_len > sizeof(wifi_ieee80211_mac_hdr_t) + 2) {
        uint8_t ssidLen = ipkt->payload[1];
        if (ssidLen > 0 && ssidLen < 33) {
          char ssid[33] = {0};
          memcpy(ssid, &ipkt->payload[2], ssidLen);
          
          if (isDroneSSID(ssid)) {
            isDrone = true;
          }
          
          if (isDrone) {
            droneCount++;
            Serial.printf("DRONE:%s:PROBE:%s:%d:%d\n", 
                         mac.c_str(), ssid, rssi, currentChannel);
          }
        }
      }
      
      // Report known OUI even without SSID
      if (isDrone && packetCount % 10 == 0) {
        Serial.printf("PROBE:%s:%d:%d\n", mac.c_str(), rssi, currentChannel);
      }
    }
    
    // Beacon frame (subtype 8)
    else if (frameSubtype == 8) {
      int rssi = pkt->rx_ctrl.rssi;
      String mac = macToString(hdr->addr2);
      
      bool isDrone = isKnownDroneOUI(hdr->addr2);
      
      // Extract SSID from beacon
      if (pkt->rx_ctrl.sig_len > sizeof(wifi_ieee80211_mac_hdr_t) + 38) {
        uint8_t* payload = (uint8_t*)&ipkt->payload[36];  // Skip fixed fields
        
        // Find SSID IE (tag 0)
        for (int i = 0; i < 100 && i < pkt->rx_ctrl.sig_len - 38; ) {
          uint8_t tag = payload[i];
          uint8_t len = payload[i+1];
          
          if (tag == 0 && len > 0 && len < 33) {  // SSID
            char ssid[33] = {0};
            memcpy(ssid, &payload[i+2], len);
            
            if (isDroneSSID(ssid)) {
              isDrone = true;
            }
            
            if (isDrone) {
              droneCount++;
              Serial.printf("DRONE:%s:BEACON:%s:%d:%d\n", 
                           mac.c_str(), ssid, rssi, currentChannel);
            }
            break;
          }
          
          i += 2 + len;
          if (len == 0) break;
        }
      }
    }
  }
}

bool isKnownDroneOUI(const uint8_t* mac) {
  char oui[9];
  snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
  
  for (int i = 0; i < NUM_OUIS; i++) {
    if (strcasecmp(oui, DRONE_OUIS[i]) == 0) {
      return true;
    }
  }
  return false;
}

bool isDroneSSID(const char* ssid) {
  if (ssid == NULL || strlen(ssid) == 0) return false;
  
  String s = String(ssid);
  s.toUpperCase();
  
  for (int i = 0; i < NUM_PATTERNS; i++) {
    if (s.indexOf(DRONE_SSID_PATTERNS[i]) >= 0) {
      return true;
    }
  }
  return false;
}

String macToString(const uint8_t* mac) {
  char str[18];
  snprintf(str, sizeof(str), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(str);
}
