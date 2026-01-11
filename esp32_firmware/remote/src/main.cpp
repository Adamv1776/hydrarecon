/**
 * ESP32-S3 WiFi Sensing Firmware - Remote Triangulation Node
 * ===========================================================
 * This device connects wirelessly to the primary sensing node
 * and provides additional RSSI/detection data from a different
 * physical location (~15 feet away) to enable triangulation-based
 * environment reconstruction.
 * 
 * Features:
 * - Automatic connection to primary HydraSense AP
 * - Promiscuous packet capture with full metadata
 * - Channel-synchronized scanning with primary
 * - High-frequency RSSI reporting
 * - OTA firmware updates from primary node
 * - Time synchronization with primary
 * - Unique node identification
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_mac.h>
#include <esp_task_wdt.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

// ============== Configuration ==============
char AP_SSID[33] = "HydraSense";
char AP_PASS[65] = "hydra2026!";
char PRIMARY_HOST[64] = "http://192.168.4.1";
const uint32_t REPORT_INTERVAL_MS = 500;  // Send data every 500ms
const uint32_t OTA_CHECK_INTERVAL_MS = 60000;  // Check for updates every 60s
const uint32_t RECONNECT_BASE_MS = 2000;  // Base reconnect interval
const uint32_t RECONNECT_MAX_MS = 60000;  // Max reconnect interval (exponential backoff)
const uint32_t WDT_TIMEOUT_S = 45;  // Watchdog timeout (longer for remote due to reconnects)
const uint32_t TIME_SYNC_INTERVAL_MS = 10000;  // Sync time with primary every 10s

// NVS Preferences
Preferences preferences;

// CSI Configuration
bool csi_enabled = false;
int8_t last_csi_data[128];
int last_csi_len = 0;
uint64_t last_csi_ts = 0;
uint8_t last_csi_mac[6] = {0};
SemaphoreHandle_t csi_mux = NULL;

// Reconnection state
uint32_t reconnect_interval = RECONNECT_BASE_MS;
uint8_t reconnect_attempts = 0;

// Health monitoring
struct HealthStats {
  uint32_t uptime_s;
  uint32_t total_reconnects;
  uint32_t failed_reports;
  uint32_t successful_reports;
  int8_t min_rssi;
  int8_t max_rssi;
  uint32_t heap_min;
  float cpu_temp;
} health = {0, 0, 0, 0, 0, -100, UINT32_MAX, 0.0f};

// Time synchronization
int64_t time_offset_us = 0;  // Offset from primary's clock
uint64_t last_time_sync = 0;

// Data structures
#define MAX_DETECTIONS 250
#define MAX_TRACKED_MACS 50
#define RSSI_HISTORY_SIZE 32

// ============== Data Structures ==============

// Enhanced signal tracker with rate-of-change and CSI metadata
struct MACTracker {
  uint8_t mac[6];
  int8_t rssi_history[RSSI_HISTORY_SIZE];  // Rolling window
  uint64_t time_history[RSSI_HISTORY_SIZE]; // Timestamps for rate calculation
  uint8_t history_idx;
  uint8_t sample_count;
  int32_t rssi_sum;
  int32_t rssi_sq_sum;
  uint64_t first_seen;
  uint64_t last_seen;
  uint16_t detection_count;
  bool is_moving;           // Derived from variance
  float rssi_velocity;      // dB/s rate of change (pseudo-Doppler)
  int8_t direction_hint;    // -1=approaching, 0=static, 1=receding
  int8_t peak_rssi;         // Strongest seen
  int8_t min_rssi;          // Weakest seen
  uint8_t channel_diversity; // Number of channels seen on
  uint8_t channels_seen[4]; // Last 4 channels
  uint8_t channel_idx;
  
  // Enhanced classification fields
  uint8_t device_type;      // 0=unknown, 1=phone, 2=laptop, 3=iot, 4=infrastructure
  float micro_variance;     // Sub-threshold variance for breathing detection
  uint16_t frame_types_seen; // Bitmap of frame types
  float signal_quality;     // 0-1 quality metric based on consistency
  uint8_t burst_count;      // Number of packet bursts (indicates active use)
  uint64_t last_burst_time;
  int8_t rssi_gradient;     // Short-term slope
  float presence_confidence; // How confident we are this is a real device
};

// Device classification constants
#define DEV_UNKNOWN       0
#define DEV_SMARTPHONE    1
#define DEV_LAPTOP        2
#define DEV_IOT           3
#define DEV_INFRASTRUCTURE 4
#define DEV_WEARABLE      5

struct __attribute__((packed)) WiFiDetection {
  uint64_t timestamp_us;
  uint8_t mac[6];
  uint8_t bssid[6];
  int8_t rssi;
  uint8_t channel;
  uint16_t frame_type;
  uint16_t seq_num;
  int8_t noise_floor;
};

// ============== Global State ==============

static WiFiDetection detections[MAX_DETECTIONS];
static uint16_t detection_head = 0;
static uint16_t detection_count_val = 0;
static portMUX_TYPE detection_mux = portMUX_INITIALIZER_UNLOCKED;

static String node_id;
static uint64_t time_offset = 0;  // Offset to sync with primary
static int8_t rssi_to_primary = 0;
static uint32_t total_packets = 0;
static bool connected_to_primary = false;

// Signal variance tracking for motion detection
static MACTracker mac_trackers[MAX_TRACKED_MACS];
static uint8_t tracker_count = 0;
static portMUX_TYPE tracker_mux = portMUX_INITIALIZER_UNLOCKED;

// Environmental metrics
static float avg_noise_floor = -90.0f;
static uint16_t unique_macs_seen = 0;
static uint16_t moving_entities = 0;
static uint16_t approaching_entities = 0;
static uint16_t receding_entities = 0;
static int8_t strongest_signal = -100;
static uint8_t active_channels[14] = {0};  // Activity per channel

// Environment presence sensing
static float room_occupancy_score = 0.0f;  // 0-1 occupancy estimate
static uint8_t breathing_detected = 0;     // Count of devices with micro-variance
static float ambient_activity = 0.0f;      // Overall activity level
static uint32_t total_frame_count = 0;
static float signal_density = 0.0f;        // Signals per second

// Adaptive thresholds - learn from environment
static float adaptive_motion_threshold = 12.0f;  // Adjusts based on noise
static float baseline_variance = 2.0f;           // Learned baseline
static uint32_t baseline_samples = 0;
static float environment_noise_level = 0.0f;     // RF environment noise

// Multi-path / reflection detection
#define MAX_REFLECTION_PAIRS 16
struct ReflectionPair {
  uint8_t mac[6];
  int8_t direct_rssi;      // Assumed direct path
  int8_t reflected_rssi;   // Suspected reflection
  uint8_t direct_ch;
  uint8_t reflected_ch;
  uint64_t timestamp;
  float path_diff_db;      // dB difference suggests reflection
};
static ReflectionPair reflection_pairs[MAX_REFLECTION_PAIRS];
static uint8_t reflection_count = 0;
static portMUX_TYPE reflection_mux = portMUX_INITIALIZER_UNLOCKED;

static TaskHandle_t sniff_task = NULL;
static TaskHandle_t report_task = NULL;

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

String generateNodeId() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char id[16];
  snprintf(id, sizeof(id), "RN-%02X%02X%02X", mac[3], mac[4], mac[5]);
  return String(id);
}

// Find or create MAC tracker
MACTracker* getOrCreateTracker(const uint8_t* mac) {
  portENTER_CRITICAL(&tracker_mux);
  
  // Find existing
  for (int i = 0; i < tracker_count; i++) {
    if (memcmp(mac_trackers[i].mac, mac, 6) == 0) {
      portEXIT_CRITICAL(&tracker_mux);
      return &mac_trackers[i];
    }
  }
  
  // Create new if space available
  if (tracker_count < MAX_TRACKED_MACS) {
    MACTracker* t = &mac_trackers[tracker_count++];
    memset(t, 0, sizeof(MACTracker));
    memcpy(t->mac, mac, 6);
    t->first_seen = getMicros64();
    unique_macs_seen++;
    portEXIT_CRITICAL(&tracker_mux);
    return t;
  }
  
  // Replace oldest tracker
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

// Update tracker with new RSSI reading
void updateTracker(MACTracker* t, int8_t rssi, uint8_t channel) {
  uint64_t now = getMicros64();
  
  // Store in rolling window with timestamp
  t->rssi_history[t->history_idx] = rssi;
  t->time_history[t->history_idx] = now;
  t->history_idx = (t->history_idx + 1) % RSSI_HISTORY_SIZE;
  if (t->sample_count < RSSI_HISTORY_SIZE) t->sample_count++;
  
  t->rssi_sum += rssi;
  t->rssi_sq_sum += (int32_t)rssi * rssi;
  t->last_seen = now;
  t->detection_count++;
  
  // Track min/max RSSI
  if (rssi > t->peak_rssi || t->peak_rssi == 0) t->peak_rssi = rssi;
  if (rssi < t->min_rssi || t->min_rssi == 0) t->min_rssi = rssi;
  
  // Track channel diversity
  bool channel_found = false;
  for (int i = 0; i < 4; i++) {
    if (t->channels_seen[i] == channel) {
      channel_found = true;
      break;
    }
  }
  if (!channel_found) {
    t->channels_seen[t->channel_idx] = channel;
    t->channel_idx = (t->channel_idx + 1) % 4;
    // Count unique channels
    uint8_t unique = 0;
    for (int i = 0; i < 4; i++) {
      if (t->channels_seen[i] != 0) unique++;
    }
    t->channel_diversity = unique;
  }
  
  // Calculate variance for motion detection (need at least 8 samples)
  if (t->sample_count >= 8) {
    float mean = (float)t->rssi_sum / t->sample_count;
    float variance = ((float)t->rssi_sq_sum / t->sample_count) - (mean * mean);
    
    // Use adaptive threshold that learns from environment
    t->is_moving = (variance > adaptive_motion_threshold);
    
    // Calculate RSSI velocity (rate of change) using linear regression
    // This gives us pseudo-Doppler direction information
    if (t->sample_count >= 12) {
      // Use last 12 samples for velocity calculation
      float sum_t = 0, sum_r = 0, sum_tr = 0, sum_t2 = 0;
      int n = 0;
      uint64_t t0 = 0;
      
      // Find start time
      int oldest_idx = (t->history_idx - t->sample_count + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
      t0 = t->time_history[oldest_idx];
      
      for (int i = 0; i < 12; i++) {
        int idx = (t->history_idx - 12 + i + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
        float time_s = (float)(t->time_history[idx] - t0) / 1000000.0f;  // Seconds
        float r = (float)t->rssi_history[idx];
        
        sum_t += time_s;
        sum_r += r;
        sum_tr += time_s * r;
        sum_t2 += time_s * time_s;
        n++;
      }
      
      // Linear regression slope = (n*sum_tr - sum_t*sum_r) / (n*sum_t2 - sum_t*sum_t)
      float denom = n * sum_t2 - sum_t * sum_t;
      if (denom > 0.001f) {
        t->rssi_velocity = (n * sum_tr - sum_t * sum_r) / denom;
        
        // Direction hint: negative velocity = getting stronger = approaching
        if (t->rssi_velocity < -1.5f) {
          t->direction_hint = -1;  // Approaching
        } else if (t->rssi_velocity > 1.5f) {
          t->direction_hint = 1;   // Receding
        } else {
          t->direction_hint = 0;   // Static
        }
        
        // Short-term gradient (last 4 samples)
        if (t->sample_count >= 4) {
          int idx_old = (t->history_idx - 4 + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
          int idx_new = (t->history_idx - 1 + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
          t->rssi_gradient = t->rssi_history[idx_new] - t->rssi_history[idx_old];
        }
      }
      
      // Micro-variance for breathing/presence detection (very small movements)
      // Use only recent samples for micro-variance
      if (t->sample_count >= 16) {
        float micro_sum = 0, micro_sq_sum = 0;
        int micro_n = 0;
        for (int i = 0; i < 8; i++) {
          int idx = (t->history_idx - 8 + i + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
          float r = (float)t->rssi_history[idx];
          micro_sum += r;
          micro_sq_sum += r * r;
          micro_n++;
        }
        float micro_mean = micro_sum / micro_n;
        t->micro_variance = (micro_sq_sum / micro_n) - (micro_mean * micro_mean);
        
        // Breathing typically shows 0.5-3 dB variance at ~12-20 breaths/min
        // This is detectable as micro-variance between 0.5 and 4.0
      }
      
      // Signal quality: based on consistency of readings
      float range = (float)(t->peak_rssi - t->min_rssi);
      if (range < 1.0f) range = 1.0f;
      t->signal_quality = 1.0f - (variance / (range * range + 10.0f));
      if (t->signal_quality < 0) t->signal_quality = 0;
      if (t->signal_quality > 1) t->signal_quality = 1;
      
      // Presence confidence
      float age_factor = 1.0f;
      float duration = (float)(now - t->first_seen) / 1000000.0f;
      if (duration > 10.0f) age_factor = 1.0f;
      else age_factor = duration / 10.0f;
      
      t->presence_confidence = age_factor * (0.5f + 0.5f * t->signal_quality);
    }
  }
}

// Classify device based on behavior patterns
void classifyDevice(MACTracker* t, uint16_t frame_type) {
  // Track frame types seen
  t->frame_types_seen |= (1 << (frame_type & 0x0F));
  
  // Burst detection (multiple packets in short time)
  uint64_t now = getMicros64();
  if (now - t->last_burst_time < 100000) {  // 100ms
    t->burst_count++;
  } else {
    t->burst_count = 1;
  }
  t->last_burst_time = now;
  
  // Classification heuristics
  if (t->detection_count < 10) return;  // Need more data
  
  float rate = (float)t->detection_count / ((float)(now - t->first_seen) / 1000000.0f);
  
  // Infrastructure: very stable signal, always present, low variance
  if (t->signal_quality > 0.8f && !t->is_moving && t->micro_variance < 1.0f) {
    t->device_type = DEV_INFRASTRUCTURE;
  }
  // Smartphone: moderate activity bursts, moves around
  else if (t->is_moving && t->burst_count > 3 && rate > 1.0f) {
    t->device_type = DEV_SMARTPHONE;
  }
  // Laptop: high packet rate, may have data frames, less movement
  else if (rate > 5.0f && t->channel_diversity <= 2) {
    t->device_type = DEV_LAPTOP;
  }
  // IoT: low packet rate, stable, specific channels
  else if (rate < 0.5f && t->channel_diversity == 1 && !t->is_moving) {
    t->device_type = DEV_IOT;
  }
  // Wearable: follows person, intermittent
  else if (t->is_moving && rate < 2.0f && t->micro_variance > 0.5f) {
    t->device_type = DEV_WEARABLE;
  }
}

// Update adaptive thresholds based on environment
void updateAdaptiveThresholds() {
  // Calculate average variance across stable devices
  float total_var = 0;
  int stable_count = 0;
  
  portENTER_CRITICAL(&tracker_mux);
  for (int i = 0; i < tracker_count; i++) {
    MACTracker& t = mac_trackers[i];
    if (t.device_type == DEV_INFRASTRUCTURE && t.sample_count >= 16) {
      // Infrastructure devices give us baseline
      float var = (float)t.rssi_sq_sum / t.sample_count - 
                  ((float)t.rssi_sum / t.sample_count) * ((float)t.rssi_sum / t.sample_count);
      if (var > 0 && var < 20) {
        total_var += var;
        stable_count++;
      }
    }
  }
  portEXIT_CRITICAL(&tracker_mux);
  
  if (stable_count > 0) {
    baseline_variance = total_var / stable_count;
    baseline_samples++;
    
    // Adaptive motion threshold: baseline + margin
    // Higher noise = higher threshold needed
    adaptive_motion_threshold = baseline_variance * 3.0f + 6.0f;
    if (adaptive_motion_threshold < 8.0f) adaptive_motion_threshold = 8.0f;
    if (adaptive_motion_threshold > 25.0f) adaptive_motion_threshold = 25.0f;
  }
  
  // Update environment noise from noise floor
  environment_noise_level = environment_noise_level * 0.95f + (avg_noise_floor + 95) * 0.05f;
}

// Detect multi-path reflections (indicates walls/obstacles)
void detectReflection(const uint8_t* mac, int8_t rssi, uint8_t channel) {
  uint64_t now = getMicros64();
  
  // Find recent detections of same MAC on different channels
  portENTER_CRITICAL(&tracker_mux);
  MACTracker* t = nullptr;
  for (int i = 0; i < tracker_count; i++) {
    if (memcmp(mac_trackers[i].mac, mac, 6) == 0) {
      t = &mac_trackers[i];
      break;
    }
  }
  portEXIT_CRITICAL(&tracker_mux);
  
  if (!t || t->sample_count < 4) return;
  
  // Check for significant RSSI difference in short time (multi-path)
  int recent_count = 0;
  int8_t recent_max = -127, recent_min = 127;
  
  for (int i = 0; i < min((int)t->sample_count, RSSI_HISTORY_SIZE); i++) {
    int idx = (t->history_idx - 1 - i + RSSI_HISTORY_SIZE) % RSSI_HISTORY_SIZE;
    uint64_t age = now - t->time_history[idx];
    if (age < 500000) {  // 500ms window
      if (t->rssi_history[idx] > recent_max) recent_max = t->rssi_history[idx];
      if (t->rssi_history[idx] < recent_min) recent_min = t->rssi_history[idx];
      recent_count++;
    }
  }
  
  // Large RSSI swing in short time suggests multi-path
  if (recent_count >= 3 && (recent_max - recent_min) > 10) {
    portENTER_CRITICAL(&reflection_mux);
    
    // Find or create reflection pair entry
    int slot = -1;
    for (int i = 0; i < reflection_count; i++) {
      if (memcmp(reflection_pairs[i].mac, mac, 6) == 0) {
        slot = i;
        break;
      }
    }
    
    if (slot < 0 && reflection_count < MAX_REFLECTION_PAIRS) {
      slot = reflection_count++;
      memcpy(reflection_pairs[slot].mac, mac, 6);
    }
    
    if (slot >= 0) {
      reflection_pairs[slot].direct_rssi = recent_max;
      reflection_pairs[slot].reflected_rssi = recent_min;
      reflection_pairs[slot].direct_ch = channel;
      reflection_pairs[slot].timestamp = now;
      reflection_pairs[slot].path_diff_db = recent_max - recent_min;
    }
    
    portEXIT_CRITICAL(&reflection_mux);
  }
}

// Count moving entities and direction stats
void updateMovingCount() {
  portENTER_CRITICAL(&tracker_mux);
  moving_entities = 0;
  approaching_entities = 0;
  receding_entities = 0;
  strongest_signal = -100;
  
  uint64_t cutoff = getMicros64() - 5000000;  // Last 5 seconds
  
  float occupancy_sum = 0;
  int breathing_candidates = 0;
  float activity_sum = 0;
  int active_devices = 0;
  
  for (int i = 0; i < tracker_count; i++) {
    MACTracker& t = mac_trackers[i];
    if (t.last_seen > cutoff) {
      active_devices++;
      
      if (t.is_moving) moving_entities++;
      if (t.direction_hint < 0) approaching_entities++;
      else if (t.direction_hint > 0) receding_entities++;
      
      // Track strongest signal
      if (t.sample_count > 0) {
        int8_t avg = t.rssi_sum / t.sample_count;
        if (avg > strongest_signal) strongest_signal = avg;
      }
      
      // Occupancy scoring - weight by presence confidence and signal strength
      float strength_factor = (100.0f + t.rssi_sum / max(1, (int)t.sample_count)) / 100.0f;
      occupancy_sum += t.presence_confidence * strength_factor;
      
      // Breathing detection: look for micro-variance in 0.5-4.0 range
      // while overall variance is low (person is stationary)
      if (!t.is_moving && t.micro_variance > 0.3f && t.micro_variance < 5.0f) {
        // Could be breathing - check signal quality
        if (t.signal_quality > 0.6f && t.presence_confidence > 0.5f) {
          breathing_candidates++;
        }
      }
      
      // Activity contribution
      if (t.is_moving) {
        activity_sum += abs(t.rssi_velocity);
      }
    }
  }
  
  // Calculate environment metrics
  room_occupancy_score = min(1.0f, occupancy_sum / 3.0f);  // Normalize to 0-1
  breathing_detected = breathing_candidates > 0;
  ambient_activity = activity_sum / max(1, active_devices);
  signal_density = (float)active_devices / 20.0f;  // Normalize by expected max devices
  
  portEXIT_CRITICAL(&tracker_mux);
}

// ============== CSI Callback ==============

void csiCallback(void* ctx, wifi_csi_info_t* info) {
  if (!info || !info->buf || info->len <= 0) return;
  
  xSemaphoreTake(csi_mux, portMAX_DELAY);
  
  last_csi_ts = getMicros64() + time_offset_us;
  last_csi_len = min((int)info->len, 128);
  memcpy(last_csi_data, info->buf, last_csi_len);
  memcpy(last_csi_mac, info->mac, 6);
  csi_enabled = true;
  
  xSemaphoreGive(csi_mux);
}

void enableCSI() {
  wifi_csi_config_t csi_config = {
    .lltf_en = true,
    .htltf_en = true,
    .stbc_htltf2_en = true,
    .ltf_merge_en = true,
    .channel_filter_en = false,
    .manu_scale = false,
    .shift = 0
  };
  
  esp_err_t ret = esp_wifi_set_csi_config(&csi_config);
  if (ret == ESP_OK) {
    ret = esp_wifi_set_csi_rx_cb(csiCallback, NULL);
    if (ret == ESP_OK) {
      esp_wifi_set_csi(true);
      Serial.println("✓ CSI extraction enabled");
    }
  }
  if (ret != ESP_OK) {
    Serial.printf("⚠ CSI setup failed: %d\n", ret);
  }
}

// ============== Time Synchronization ==============

bool syncTimeWithPrimary() {
  HTTPClient http;
  http.setTimeout(3000);
  
  uint64_t local_before = getMicros64();
  http.begin(String(PRIMARY_HOST) + "/status");
  int code = http.GET();
  uint64_t local_after = getMicros64();
  
  if (code == 200) {
    String response = http.getString();
    http.end();
    
    // Parse primary's timestamp
    int ts_idx = response.indexOf("\"uptime_us\":");
    if (ts_idx > 0) {
      String ts_str = response.substring(ts_idx + 12);
      int end_idx = ts_str.indexOf(',');
      if (end_idx < 0) end_idx = ts_str.indexOf('}');
      uint64_t primary_ts = strtoull(ts_str.substring(0, end_idx).c_str(), NULL, 10);
      
      // Estimate network latency and compute offset
      uint64_t rtt = local_after - local_before;
      uint64_t local_mid = local_before + rtt / 2;
      time_offset_us = (int64_t)primary_ts - (int64_t)local_mid;
      
      last_time_sync = millis();
      Serial.printf("✓ Time sync: offset=%lldus, RTT=%lluus\n", time_offset_us, rtt);
      return true;
    }
  }
  http.end();
  return false;
}

// ============== Health Monitoring ==============

void updateHealthStats() {
  health.uptime_s = millis() / 1000;
  
  uint32_t heap = ESP.getFreeHeap();
  if (heap < health.heap_min) health.heap_min = heap;
  
  if (rssi_to_primary < health.min_rssi) health.min_rssi = rssi_to_primary;
  if (rssi_to_primary > health.max_rssi) health.max_rssi = rssi_to_primary;
  
  // Read CPU temperature if available (ESP32-S3)
  #ifdef CONFIG_IDF_TARGET_ESP32S3
  extern float temperatureRead();
  health.cpu_temp = temperatureRead();
  #endif
}

// ============== Promiscuous Sniffer Callback ==============

void IRAM_ATTR promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!buf) return;
  
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t* rx_ctrl = &pkt->rx_ctrl;
  
  // Skip invalid packets
  if (rx_ctrl->sig_len < 24) return;
  
  total_packets++;
  
  uint8_t* payload = pkt->payload;
  uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
  uint8_t frame_type = (frame_ctrl >> 2) & 0x03;
  uint8_t frame_subtype = (frame_ctrl >> 4) & 0x0F;
  
  WiFiDetection det;
  memset(&det, 0, sizeof(det));
  
  det.timestamp_us = getMicros64() + time_offset;
  det.rssi = rx_ctrl->rssi;
  det.channel = rx_ctrl->channel;
  det.frame_type = (frame_type << 8) | frame_subtype;
  det.noise_floor = rx_ctrl->noise_floor;
  
  if (rx_ctrl->sig_len >= 24) {
    det.seq_num = (payload[22] | (payload[23] << 8)) >> 4;
  }
  
  memcpy(det.mac, &payload[10], 6);
  memcpy(det.bssid, &payload[16], 6);
  
  portENTER_CRITICAL(&detection_mux);
  uint16_t idx = detection_head;
  detection_head = (detection_head + 1) % MAX_DETECTIONS;
  if (detection_count_val < MAX_DETECTIONS) detection_count_val++;
  detections[idx] = det;
  portEXIT_CRITICAL(&detection_mux);
  
  // Update MAC tracker for variance analysis
  MACTracker* tracker = getOrCreateTracker(det.mac);
  if (tracker) {
    updateTracker(tracker, det.rssi, det.channel);
    classifyDevice(tracker, det.frame_type);
    detectReflection(det.mac, det.rssi, det.channel);
  }
  
  total_frame_count++;
  
  // Track channel activity
  if (det.channel > 0 && det.channel <= 14) {
    active_channels[det.channel - 1]++;
  }
  
  // Update average noise floor
  avg_noise_floor = avg_noise_floor * 0.99f + (float)det.noise_floor * 0.01f;
}

// ============== WiFi Connection ==============

bool connectToAP() {
  Serial.printf("Connecting to %s...\n", AP_SSID);
  
  WiFi.mode(WIFI_MODE_STA);
  WiFi.begin(AP_SSID, AP_PASS);
  
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();
  
  if (WiFi.status() == WL_CONNECTED) {
    connected_to_primary = true;
    rssi_to_primary = WiFi.RSSI();
    
    // Reset exponential backoff on success
    reconnect_interval = RECONNECT_BASE_MS;
    reconnect_attempts = 0;
    
    Serial.printf("✓ Connected! IP: %s, RSSI: %d dBm\n", 
                  WiFi.localIP().toString().c_str(), rssi_to_primary);
    
    // Enable CSI after connection
    enableCSI();
    
    // Initial time sync
    syncTimeWithPrimary();
    
    return true;
  }
  
  // Exponential backoff on failure
  reconnect_attempts++;
  health.total_reconnects++;
  reconnect_interval = min(reconnect_interval * 2, RECONNECT_MAX_MS);
  Serial.printf("✗ Connection failed (attempt %d, next retry in %lums)\n", 
                reconnect_attempts, reconnect_interval);
  return false;
}

// ============== OTA Update ==============

void checkAndPerformOTA() {
  Serial.println("Checking for OTA update...");
  
  HTTPClient http;
  http.begin(String(PRIMARY_HOST) + "/firmware.bin");
  http.addHeader("X-Node-ID", node_id);
  
  int code = http.GET();
  
  if (code == 200) {
    int len = http.getSize();
    if (len <= 0) {
      Serial.println("No firmware available or unknown size");
      http.end();
      return;
    }
    
    Serial.printf("Firmware available: %d bytes\n", len);
    
    WiFiClient* stream = http.getStreamPtr();
    if (!Update.begin(len)) {
      Serial.println("Update.begin failed");
      http.end();
      return;
    }
    
    Serial.println("Starting OTA...");
    size_t written = Update.writeStream(*stream);
    
    if (written == (size_t)len) {
      Serial.printf("Written: %d bytes\n", written);
    } else {
      Serial.printf("Written only %d / %d bytes\n", written, len);
    }
    
    if (Update.end()) {
      if (Update.isFinished()) {
        Serial.println("OTA successful! Rebooting...");
        http.end();
        delay(1000);
        ESP.restart();
      }
    } else {
      Serial.printf("OTA failed: %d\n", Update.getError());
    }
  } else if (code == 404) {
    Serial.println("No firmware update available");
  } else {
    Serial.printf("OTA check failed: %d\n", code);
  }
  
  http.end();
}

// ============== Data Reporting ==============

void sendDataToPrimary() {
  if (WiFi.status() != WL_CONNECTED) {
    connected_to_primary = false;
    return;
  }
  
  // Update RSSI to primary
  rssi_to_primary = WiFi.RSSI();
  
  // Build JSON payload
  JsonDocument doc;
  // Update moving entity count
  updateMovingCount();
  // Update adaptive thresholds
  updateAdaptiveThresholds();
  
  doc["node_id"] = node_id;
  doc["rssi_to_primary"] = rssi_to_primary;
  doc["local_ts"] = getMicros64();
  doc["total_packets"] = total_packets;
  doc["heap_free"] = ESP.getFreeHeap();
  doc["unique_macs"] = unique_macs_seen;
  doc["moving_entities"] = moving_entities;
  doc["approaching"] = approaching_entities;
  doc["receding"] = receding_entities;
  doc["avg_noise"] = (int8_t)avg_noise_floor;
  doc["tracked_macs"] = tracker_count;
  doc["strongest"] = strongest_signal;
  
  // New environment sensing fields
  doc["occupancy"] = (int)(room_occupancy_score * 100) / 100.0f;
  doc["breathing"] = breathing_detected ? 1 : 0;
  doc["activity"] = (int)(ambient_activity * 100) / 100.0f;
  doc["density"] = (int)(signal_density * 100) / 100.0f;
  doc["total_frames"] = total_frame_count;
  
  // Adaptive sensing parameters
  doc["motion_thresh"] = (int)(adaptive_motion_threshold * 10) / 10.0f;
  doc["baseline_var"] = (int)(baseline_variance * 10) / 10.0f;
  doc["env_noise"] = (int)(environment_noise_level * 10) / 10.0f;
  
  // Reflection/multipath data (indicates walls)
  if (reflection_count > 0) {
    JsonArray reflections = doc["reflections"].to<JsonArray>();
    portENTER_CRITICAL(&reflection_mux);
    uint64_t cutoff = getMicros64() - 5000000;  // Last 5 seconds
    for (int i = 0; i < reflection_count; i++) {
      if (reflection_pairs[i].timestamp > cutoff && reflection_pairs[i].path_diff_db > 8) {
        JsonObject ref = reflections.add<JsonObject>();
        ref["mac"] = macToString(reflection_pairs[i].mac);
        ref["direct"] = reflection_pairs[i].direct_rssi;
        ref["reflected"] = reflection_pairs[i].reflected_rssi;
        ref["diff"] = (int)reflection_pairs[i].path_diff_db;
      }
    }
    portEXIT_CRITICAL(&reflection_mux);
  }
  
  // Channel activity summary (find busiest channels)
  JsonArray channels = doc["ch_activity"].to<JsonArray>();
  uint8_t sorted_ch[3] = {0, 0, 0};
  uint8_t sorted_cnt[3] = {0, 0, 0};
  for (int i = 0; i < 14; i++) {
    if (active_channels[i] > sorted_cnt[0]) {
      sorted_cnt[2] = sorted_cnt[1]; sorted_ch[2] = sorted_ch[1];
      sorted_cnt[1] = sorted_cnt[0]; sorted_ch[1] = sorted_ch[0];
      sorted_cnt[0] = active_channels[i]; sorted_ch[0] = i + 1;
    } else if (active_channels[i] > sorted_cnt[1]) {
      sorted_cnt[2] = sorted_cnt[1]; sorted_ch[2] = sorted_ch[1];
      sorted_cnt[1] = active_channels[i]; sorted_ch[1] = i + 1;
    } else if (active_channels[i] > sorted_cnt[2]) {
      sorted_cnt[2] = active_channels[i]; sorted_ch[2] = i + 1;
    }
    active_channels[i] = 0;  // Reset for next period
  }
  for (int i = 0; i < 3 && sorted_ch[i] > 0; i++) {
    JsonObject ch = channels.add<JsonObject>();
    ch["ch"] = sorted_ch[i];
    ch["cnt"] = sorted_cnt[i];
  }
  
  JsonArray scans = doc["scans"].to<JsonArray>();
  
  portENTER_CRITICAL(&detection_mux);
  uint16_t count = (detection_count_val < 50) ? detection_count_val : 50;  // Send up to 50 per report
  uint16_t start = (detection_head - count + MAX_DETECTIONS) % MAX_DETECTIONS;
  
  for (uint16_t i = 0; i < count; i++) {
    uint16_t idx = (start + i) % MAX_DETECTIONS;
    WiFiDetection& d = detections[idx];
    
    JsonObject scan = scans.add<JsonObject>();
    scan["ts"] = d.timestamp_us;
    scan["mac"] = macToString(d.mac);
    scan["bssid"] = macToString(d.bssid);
    scan["rssi"] = d.rssi;
    scan["ch"] = d.channel;
    scan["f"] = d.frame_type;
    scan["n"] = d.noise_floor;
    scan["s"] = d.seq_num;
    
    // Add motion hint if we're tracking this MAC
    MACTracker* t = getOrCreateTracker(d.mac);
    if (t && t->sample_count >= 8) {
      scan["mv"] = t->is_moving ? 1 : 0;
      scan["dir"] = t->direction_hint;
      scan["cnt"] = t->detection_count;
      if (t->sample_count >= 12) {
        scan["vel"] = (int)(t->rssi_velocity * 10) / 10.0f;
      }
    }
  }
  
  // Add summary of tracked MACs with motion status
  JsonArray tracked = doc["tracked"].to<JsonArray>();
  portENTER_CRITICAL(&tracker_mux);
  uint64_t cutoff = getMicros64() - 10000000;  // Last 10 seconds
  int tracked_added = 0;
  for (int i = 0; i < tracker_count && tracked_added < 20; i++) {
    MACTracker& t = mac_trackers[i];
    if (t.last_seen > cutoff && t.sample_count >= 4) {
      JsonObject tr = tracked.add<JsonObject>();
      tr["mac"] = macToString(t.mac);
      tr["cnt"] = t.detection_count;
      tr["mv"] = t.is_moving ? 1 : 0;
      tr["dir"] = t.direction_hint;  // -1=approaching, 0=static, 1=receding
      
      // Calculate current average RSSI
      if (t.sample_count > 0) {
        int sum = 0;
        for (int j = 0; j < t.sample_count && j < RSSI_HISTORY_SIZE; j++) {
          sum += t.rssi_history[j];
        }
        tr["rssi"] = sum / t.sample_count;
      }
      
      // Add RSSI velocity (dB/s)
      if (t.sample_count >= 12) {
        tr["vel"] = (int)(t.rssi_velocity * 10) / 10.0f;  // 1 decimal place
      }
      
      // Add peak/min RSSI for range info
      tr["peak"] = t.peak_rssi;
      tr["min"] = t.min_rssi;
      
      // Channel diversity indicates mobility (moving devices appear on multiple channels)
      tr["ch_div"] = t.channel_diversity;
      
      // New fields for device classification
      tr["dev_type"] = t.device_type;
      tr["quality"] = (int)(t.signal_quality * 100);  // 0-100
      tr["conf"] = (int)(t.presence_confidence * 100);  // 0-100
      tr["micro_var"] = (int)(t.micro_variance * 10) / 10.0f;
      tr["gradient"] = t.rssi_gradient;
      
      tracked_added++;
    }
  }
  portEXIT_CRITICAL(&tracker_mux);
  
  // Clear processed detections
  detection_count_val = 0;
  detection_head = 0;
  portEXIT_CRITICAL(&detection_mux);
  
  String payload;
  serializeJson(doc, payload);
  
  // Send to primary
  HTTPClient http;
  http.begin(String(PRIMARY_HOST) + "/remote_data");
  http.addHeader("Content-Type", "application/json");
  
  int code = http.POST(payload);
  
  if (code == 200) {
    String response = http.getString();
    
    // Parse sync response
    JsonDocument resp;
    if (deserializeJson(resp, response) == DeserializationError::Ok) {
      uint64_t server_ts = resp["server_ts"] | 0;
      if (server_ts > 0) {
        // Rough time sync (could be improved with NTP-like algorithm)
        uint64_t local_ts = getMicros64();
        time_offset = server_ts - local_ts;
      }
    }
  } else {
    Serial.printf("Report failed: %d\n", code);
  }
  
  http.end();
}

// ============== Sniffing Task ==============

void sniffTask(void* param) {
  // Configure promiscuous mode
  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
  };
  
  while (true) {
    if (connected_to_primary) {
      // Enable promiscuous mode while connected
      esp_wifi_set_promiscuous(true);
      esp_wifi_set_promiscuous_filter(&filter);
      esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
      
      // Sniff for a period then yield
      vTaskDelay(pdMS_TO_TICKS(100));
    } else {
      esp_wifi_set_promiscuous(false);
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
  }
}

// ============== Report Task ==============

void reportTask(void* param) {
  uint32_t last_report = 0;
  uint32_t last_ota_check = 0;
  uint32_t last_reconnect = 0;
  uint32_t last_time_sync_check = 0;
  uint32_t last_health_update = 0;
  
  while (true) {
    uint32_t now = millis();
    
    // Handle reconnection with exponential backoff
    if (!connected_to_primary || WiFi.status() != WL_CONNECTED) {
      if (now - last_reconnect > reconnect_interval) {
        last_reconnect = now;
        esp_wifi_set_promiscuous(false);
        connectToAP();
      }
    }
    
    // Send detection data
    if (connected_to_primary && now - last_report > REPORT_INTERVAL_MS) {
      last_report = now;
      sendDataToPrimary();
    }
    
    // Periodic time sync
    if (connected_to_primary && now - last_time_sync_check > TIME_SYNC_INTERVAL_MS) {
      last_time_sync_check = now;
      syncTimeWithPrimary();
    }
    
    // Periodic OTA check
    if (connected_to_primary && now - last_ota_check > OTA_CHECK_INTERVAL_MS) {
      last_ota_check = now;
      checkAndPerformOTA();
    }
    
    // Update health stats
    if (now - last_health_update > 5000) {
      last_health_update = now;
      updateHealthStats();
    }
    
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

// ============== Channel Scanning ==============

void performActiveScan() {
  // Perform active AP scan for additional environmental data
  int n = WiFi.scanNetworks(false, true, false, 100);  // Active scan, hidden SSIDs, 100ms per channel
  
  if (n > 0) {
    portENTER_CRITICAL(&detection_mux);
    for (int i = 0; i < n && detection_count_val < MAX_DETECTIONS; i++) {
      WiFiDetection det;
      memset(&det, 0, sizeof(det));
      
      det.timestamp_us = getMicros64() + time_offset;
      det.rssi = WiFi.RSSI(i);
      det.channel = WiFi.channel(i);
      det.frame_type = 0x0080;  // Beacon frame type
      
      // Get BSSID
      uint8_t* bssid = WiFi.BSSID(i);
      if (bssid) {
        memcpy(det.mac, bssid, 6);
        memcpy(det.bssid, bssid, 6);
      }
      
      uint16_t idx = detection_head;
      detection_head = (detection_head + 1) % MAX_DETECTIONS;
      if (detection_count_val < MAX_DETECTIONS) detection_count_val++;
      detections[idx] = det;
    }
    portEXIT_CRITICAL(&detection_mux);
    
    WiFi.scanDelete();
  }
}

// ============== Setup ==============

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n\n");
  Serial.println("╔══════════════════════════════════════════════════════════╗");
  Serial.println("║     HydraSense WiFi Environment Reconstruction          ║");
  Serial.println("║           Remote Triangulation Node v3.1                 ║");
  Serial.println("╚══════════════════════════════════════════════════════════╝");
  
  // Initialize CSI mutex
  csi_mux = xSemaphoreCreateMutex();
  
  // Initialize NVS preferences
  preferences.begin("hydra_remote", false);
  String saved_ssid = preferences.getString("ap_ssid", "");
  String saved_pass = preferences.getString("ap_pass", "");
  String saved_host = preferences.getString("primary_host", "");
  if (saved_ssid.length() > 0) {
    strncpy(AP_SSID, saved_ssid.c_str(), 32);
    AP_SSID[32] = '\0';
    Serial.printf("✓ Loaded AP SSID from NVS: %s\n", AP_SSID);
  }
  if (saved_pass.length() > 0) {
    strncpy(AP_PASS, saved_pass.c_str(), 64);
    AP_PASS[64] = '\0';
    Serial.println("✓ Loaded AP password from NVS");
  }
  if (saved_host.length() > 0) {
    strncpy(PRIMARY_HOST, saved_host.c_str(), 63);
    PRIMARY_HOST[63] = '\0';
    Serial.printf("✓ Loaded primary host from NVS: %s\n", PRIMARY_HOST);
  }
  
  // Initialize watchdog
  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = WDT_TIMEOUT_S * 1000,
    .idle_core_mask = (1 << 0) | (1 << 1),
    .trigger_panic = true
  };
  esp_task_wdt_init(&wdt_config);
  esp_task_wdt_add(NULL);
  Serial.printf("✓ Watchdog initialized (%ds timeout)\n", WDT_TIMEOUT_S);
  
  // Generate unique node ID from MAC
  node_id = generateNodeId();
  Serial.printf("Node ID: %s\n", node_id.c_str());
  
  // Initial connection (also enables CSI and syncs time)
  if (!connectToAP()) {
    Serial.println("Initial connection failed, will retry with exponential backoff...");
  }
  
  // Check for OTA on startup
  if (connected_to_primary) {
    checkAndPerformOTA();
  }
  
  // Start tasks
  xTaskCreatePinnedToCore(sniffTask, "Sniff", 4096, NULL, 2, &sniff_task, 0);
  xTaskCreatePinnedToCore(reportTask, "Report", 8192, NULL, 1, &report_task, 1);
  
  Serial.println("✓ Tasks started");
  Serial.println("\n📡 Remote node ready!");
  Serial.printf("   Node ID: %s\n", node_id.c_str());
  Serial.printf("   Primary: %s\n\n", PRIMARY_HOST);
}

// ============== Main Loop ==============

void loop() {
  // Periodic active scan for additional coverage
  static uint32_t last_scan = 0;
  if (millis() - last_scan > 10000) {  // Every 10 seconds
    last_scan = millis();
    if (connected_to_primary) {
      performActiveScan();
    }
  }
  
  // Status output
  static uint32_t last_status = 0;
  static uint8_t status_cycle = 0;
  if (millis() - last_status > 5000) {
    last_status = millis();
    
    // Alternate between normal status and health status
    if (status_cycle++ % 3 == 0) {
      Serial.printf("🏥 [HEALTH] Up:%lus Reconn:%lu OK:%lu Fail:%lu RSSI:[%d,%d] HeapMin:%lu CSI:%s\n",
                    health.uptime_s,
                    health.total_reconnects,
                    health.successful_reports,
                    health.failed_reports,
                    health.min_rssi,
                    health.max_rssi,
                    health.heap_min,
                    csi_enabled ? "Y" : "N");
    } else {
      Serial.printf("📊 [%s] Conn:%s RSSI:%d Pkts:%lu Buf:%d Mov:%d App:%d Rec:%d Tracked:%d Peak:%d Heap:%lu TimeOff:%lldus\n",
                    node_id.c_str(),
                    connected_to_primary ? "Y" : "N",
                    rssi_to_primary,
                    total_packets,
                    detection_count_val,
                    moving_entities,
                    approaching_entities,
                    receding_entities,
                    tracker_count,
                    strongest_signal,
                    ESP.getFreeHeap(),
                    time_offset_us);
    }
  }
  
  // Feed watchdog
  esp_task_wdt_reset();
  
  delay(100);
}
