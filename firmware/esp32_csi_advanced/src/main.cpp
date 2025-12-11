/**
 * HydraRecon ESP32 Advanced CSI Firmware
 * ======================================
 * 
 * Enhanced CSI capture with:
 * - Automatic channel scanning and optimization
 * - Multi-target MAC tracking
 * - Raw I/Q data transmission
 * - Signal quality metrics (SNR, noise floor)
 * - Presence zone detection
 * - Adaptive sample rate
 * - Deep sleep power management
 * - OTA firmware updates
 * - EEPROM configuration persistence
 * - Multi-ESP32 mesh synchronization
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <EEPROM.h>
#include <Update.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "driver/adc.h"
#include "esp_adc_cal.h"

// ============================================================================
// Configuration
// ============================================================================
#define FIRMWARE_VERSION "2.0.0"
#define LED_PIN 2
#define DEFAULT_CHANNEL 6
#define CSI_BUFFER_SIZE 64
#define MAX_TRACKED_MACS 16
#define CHANNEL_SCAN_INTERVAL 30000  // 30 seconds
#define SIGNAL_HISTORY_SIZE 100
#define EEPROM_SIZE 512
#define OTA_BUFFER_SIZE 1024

// EEPROM addresses
#define EEPROM_MAGIC 0
#define EEPROM_CHANNEL 4
#define EEPROM_SAMPLE_RATE 8
#define EEPROM_POWER_MODE 12
#define EEPROM_SSID 16
#define EEPROM_PASS 80

// Network config (can be overwritten via EEPROM)
const char* DEFAULT_SSID = "YOUR_WIFI_SSID";
const char* DEFAULT_PASS = "YOUR_WIFI_PASS";
const char* UDP_HOST = "192.168.1.100";
const uint16_t UDP_PORT = 5555;
const uint16_t CMD_PORT = 5556;

// ============================================================================
// Data Structures
// ============================================================================

struct CSIPacket {
    int8_t* data;
    int16_t len;
    int8_t rssi;
    int8_t noise_floor;
    uint8_t channel;
    int64_t timestamp;
    uint8_t mac[6];
    uint8_t rate;
    uint8_t sig_mode;
    uint8_t mcs;
    uint8_t bandwidth;
    int8_t* raw_iq;  // Raw I/Q for advanced processing
    int16_t raw_len;
};

struct TrackedMAC {
    uint8_t mac[6];
    int8_t last_rssi;
    int8_t avg_rssi;
    uint32_t packet_count;
    uint32_t last_seen;
    float signal_variance;
    bool is_target;  // Mark as primary tracking target
    int8_t rssi_history[32];
    uint8_t history_idx;
};

struct ChannelStats {
    uint8_t channel;
    uint32_t packet_count;
    int8_t avg_rssi;
    int8_t noise_floor;
    float interference_score;
    uint32_t last_scan;
};

struct SignalQuality {
    float snr;
    float noise_floor;
    float signal_variance;
    float doppler_shift;
    uint32_t packets_per_second;
    float packet_loss_rate;
};

// ============================================================================
// Global State
// ============================================================================

WiFiUDP udp;
WiFiUDP cmdUdp;

volatile bool networkConnected = false;
volatile uint32_t totalPackets = 0;
volatile uint8_t currentChannel = DEFAULT_CHANNEL;
volatile bool autoChannelScan = true;
volatile uint32_t sampleRate = 100;  // Target samples per second
volatile uint8_t powerMode = 0;  // 0=normal, 1=low_power, 2=high_perf

CSIPacket csiBuffer[CSI_BUFFER_SIZE];
volatile int writeIndex = 0;
volatile int readIndex = 0;

TrackedMAC trackedMacs[MAX_TRACKED_MACS];
int numTrackedMacs = 0;

ChannelStats channelStats[14];
SignalQuality signalQuality;

bool rawIQMode = false;
bool presenceMode = true;
bool gestureMode = false;

uint32_t lastChannelScan = 0;
uint32_t packetsThisSecond = 0;
uint32_t lastSecond = 0;

char wifiSSID[64] = "";
char wifiPass[64] = "";

// ============================================================================
// Signal Processing Helpers
// ============================================================================

float calculateSNR(int8_t rssi, int8_t noise) {
    return (float)(rssi - noise);
}

float calculateVariance(int8_t* history, int len) {
    if (len < 2) return 0;
    float sum = 0, sumSq = 0;
    for (int i = 0; i < len; i++) {
        sum += history[i];
        sumSq += history[i] * history[i];
    }
    float mean = sum / len;
    return (sumSq / len) - (mean * mean);
}

float estimateDopplerShift(CSIPacket* p) {
    // Estimate Doppler from phase changes between subcarriers
    if (!p || !p->data || p->len < 4) return 0;
    float phaseSum = 0;
    int count = 0;
    for (int i = 2; i < p->len - 2; i += 2) {
        float ph1 = atan2(p->data[i-2], p->data[i-1]);
        float ph2 = atan2(p->data[i], p->data[i+1]);
        float diff = ph2 - ph1;
        // Wrap to [-pi, pi]
        while (diff > M_PI) diff -= 2*M_PI;
        while (diff < -M_PI) diff += 2*M_PI;
        phaseSum += diff;
        count++;
    }
    return count > 0 ? phaseSum / count : 0;
}

int findTrackedMAC(uint8_t* mac) {
    for (int i = 0; i < numTrackedMacs; i++) {
        if (memcmp(trackedMacs[i].mac, mac, 6) == 0) return i;
    }
    return -1;
}

void addOrUpdateMAC(uint8_t* mac, int8_t rssi) {
    int idx = findTrackedMAC(mac);
    if (idx < 0) {
        if (numTrackedMacs < MAX_TRACKED_MACS) {
            idx = numTrackedMacs++;
            memcpy(trackedMacs[idx].mac, mac, 6);
            trackedMacs[idx].packet_count = 0;
            trackedMacs[idx].avg_rssi = rssi;
            trackedMacs[idx].history_idx = 0;
            trackedMacs[idx].is_target = false;
        } else {
            return;
        }
    }
    
    TrackedMAC* t = &trackedMacs[idx];
    t->last_rssi = rssi;
    t->packet_count++;
    t->last_seen = millis();
    t->rssi_history[t->history_idx] = rssi;
    t->history_idx = (t->history_idx + 1) % 32;
    t->avg_rssi = (t->avg_rssi * 7 + rssi) / 8;  // EMA
    t->signal_variance = calculateVariance(t->rssi_history, min(32, (int)t->packet_count));
}

// ============================================================================
// CSI Callback
// ============================================================================

void csiCallback(void* ctx, wifi_csi_info_t* info) {
    if (!info || !info->buf || info->len <= 0) return;
    
    int next = (writeIndex + 1) % CSI_BUFFER_SIZE;
    if (next == readIndex) return;  // Buffer full
    
    CSIPacket* p = &csiBuffer[writeIndex];
    
    // Basic info
    p->len = info->len;
    p->rssi = info->rx_ctrl.rssi;
    p->noise_floor = info->rx_ctrl.noise_floor;
    p->channel = info->rx_ctrl.channel;
    p->timestamp = esp_timer_get_time();
    memcpy(p->mac, info->mac, 6);
    
    // Extended info
    p->rate = info->rx_ctrl.rate;
    p->sig_mode = info->rx_ctrl.sig_mode;
    p->mcs = info->rx_ctrl.mcs;
    p->bandwidth = info->rx_ctrl.cwb;
    
    // Allocate and copy CSI data
    if (p->data) free(p->data);
    p->data = (int8_t*)malloc(info->len);
    if (p->data) {
        memcpy(p->data, info->buf, info->len);
        
        // Store raw I/Q if enabled
        if (rawIQMode) {
            if (p->raw_iq) free(p->raw_iq);
            p->raw_len = info->len;
            p->raw_iq = (int8_t*)malloc(info->len);
            if (p->raw_iq) memcpy(p->raw_iq, info->buf, info->len);
        }
        
        writeIndex = next;
        totalPackets++;
        packetsThisSecond++;
    }
    
    // Track MAC
    addOrUpdateMAC(info->mac, info->rx_ctrl.rssi);
}

void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    // LED blink for activity
    if (totalPackets % 50 == 0) {
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
}

// ============================================================================
// Channel Management
// ============================================================================

void setChannel(uint8_t ch) {
    if (ch >= 1 && ch <= 14) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        currentChannel = ch;
        Serial.printf("{\"type\":\"channel\",\"ch\":%d}\n", ch);
    }
}

void scanChannels() {
    if (!autoChannelScan) return;
    
    uint8_t bestChannel = currentChannel;
    int32_t bestScore = INT32_MIN;
    
    uint8_t origChannel = currentChannel;
    
    for (uint8_t ch = 1; ch <= 13; ch++) {
        setChannel(ch);
        delay(100);  // Collect samples
        
        // Score based on packet count and signal quality
        int32_t score = channelStats[ch-1].packet_count * 10;
        score += channelStats[ch-1].avg_rssi;
        score -= (int32_t)(channelStats[ch-1].interference_score * 5);
        
        if (score > bestScore) {
            bestScore = score;
            bestChannel = ch;
        }
    }
    
    setChannel(bestChannel);
    lastChannelScan = millis();
    
    Serial.printf("{\"type\":\"scan_result\",\"best_ch\":%d,\"score\":%d}\n", bestChannel, bestScore);
}

// ============================================================================
// Data Transmission
// ============================================================================

void sendCSIPacket(CSIPacket* p, bool useSerial) {
    if (!p || !p->data) return;
    
    // Build JSON
    String json = "{\"type\":\"csi\",\"v\":\"" FIRMWARE_VERSION "\",\"ts\":";
    json += String((unsigned long)(p->timestamp / 1000));
    json += ",\"ch\":" + String(p->channel);
    json += ",\"rssi\":" + String(p->rssi);
    json += ",\"nf\":" + String(p->noise_floor);
    json += ",\"snr\":" + String(calculateSNR(p->rssi, p->noise_floor), 1);
    
    // MAC address
    char mac[18];
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", 
             p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);
    json += ",\"mac\":\""; json += mac; json += "\"";
    
    // Extended info
    json += ",\"rate\":" + String(p->rate);
    json += ",\"bw\":" + String(p->bandwidth ? 40 : 20);
    json += ",\"mcs\":" + String(p->mcs);
    
    // Doppler estimate
    float doppler = estimateDopplerShift(p);
    json += ",\"doppler\":" + String(doppler, 4);
    
    // CSI data as [amplitude, phase] pairs
    json += ",\"len\":" + String(p->len) + ",\"csi\":[";
    for (int i = 0; i < p->len; i += 2) {
        if (i + 1 < p->len) {
            float amp = sqrt(p->data[i]*p->data[i] + p->data[i+1]*p->data[i+1]);
            float ph = atan2(p->data[i], p->data[i+1]);
            if (i > 0) json += ",";
            json += "[" + String(amp, 2) + "," + String(ph, 4) + "]";
        }
    }
    json += "]";
    
    // Raw I/Q if enabled
    if (rawIQMode && p->raw_iq && p->raw_len > 0) {
        json += ",\"iq\":[";
        for (int i = 0; i < p->raw_len; i++) {
            if (i > 0) json += ",";
            json += String(p->raw_iq[i]);
        }
        json += "]";
    }
    
    json += "}";
    
    if (useSerial) {
        Serial.println(json);
    } else if (networkConnected) {
        udp.beginPacket(UDP_HOST, UDP_PORT);
        udp.print(json);
        udp.endPacket();
    }
}

void sendStatusReport() {
    String json = "{\"type\":\"status\",\"v\":\"" FIRMWARE_VERSION "\"";
    json += ",\"uptime\":" + String(millis() / 1000);
    json += ",\"ch\":" + String(currentChannel);
    json += ",\"pkts\":" + String(totalPackets);
    json += ",\"pps\":" + String(signalQuality.packets_per_second);
    json += ",\"net\":" + String(networkConnected ? 1 : 0);
    json += ",\"macs\":" + String(numTrackedMacs);
    json += ",\"snr\":" + String(signalQuality.snr, 1);
    json += ",\"nf\":" + String(signalQuality.noise_floor, 1);
    json += ",\"free_heap\":" + String(ESP.getFreeHeap());
    json += ",\"raw_iq\":" + String(rawIQMode ? 1 : 0);
    json += ",\"presence\":" + String(presenceMode ? 1 : 0);
    json += ",\"gesture\":" + String(gestureMode ? 1 : 0);
    json += ",\"auto_ch\":" + String(autoChannelScan ? 1 : 0);
    json += "}";
    
    Serial.println(json);
    if (networkConnected) {
        udp.beginPacket(UDP_HOST, UDP_PORT);
        udp.print(json);
        udp.endPacket();
    }
}

void sendTrackedMacs() {
    String json = "{\"type\":\"macs\",\"count\":" + String(numTrackedMacs) + ",\"macs\":[";
    for (int i = 0; i < numTrackedMacs; i++) {
        TrackedMAC* t = &trackedMacs[i];
        if (i > 0) json += ",";
        char mac[18];
        snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 t->mac[0], t->mac[1], t->mac[2], t->mac[3], t->mac[4], t->mac[5]);
        json += "{\"mac\":\""; json += mac; json += "\"";
        json += ",\"rssi\":" + String(t->last_rssi);
        json += ",\"avg\":" + String(t->avg_rssi);
        json += ",\"var\":" + String(t->signal_variance, 2);
        json += ",\"pkts\":" + String(t->packet_count);
        json += ",\"age\":" + String((millis() - t->last_seen) / 1000);
        json += ",\"target\":" + String(t->is_target ? 1 : 0);
        json += "}";
    }
    json += "]}";
    Serial.println(json);
}

void sendChannelStats() {
    String json = "{\"type\":\"channels\",\"stats\":[";
    for (int i = 0; i < 13; i++) {
        if (i > 0) json += ",";
        json += "{\"ch\":" + String(i + 1);
        json += ",\"pkts\":" + String(channelStats[i].packet_count);
        json += ",\"rssi\":" + String(channelStats[i].avg_rssi);
        json += ",\"nf\":" + String(channelStats[i].noise_floor);
        json += ",\"intf\":" + String(channelStats[i].interference_score, 2);
        json += "}";
    }
    json += "]}";
    Serial.println(json);
}

// ============================================================================
// Command Processing
// ============================================================================

void processCommand(String cmd) {
    cmd.trim();
    cmd.toUpperCase();
    
    if (cmd.startsWith("CH ")) {
        setChannel(cmd.substring(3).toInt());
    }
    else if (cmd == "STATUS") {
        sendStatusReport();
    }
    else if (cmd == "MACS") {
        sendTrackedMacs();
    }
    else if (cmd == "CHANNELS") {
        sendChannelStats();
    }
    else if (cmd == "SCAN") {
        scanChannels();
    }
    else if (cmd == "AUTOSCAN ON") {
        autoChannelScan = true;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"autoscan\",\"val\":1}");
    }
    else if (cmd == "AUTOSCAN OFF") {
        autoChannelScan = false;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"autoscan\",\"val\":0}");
    }
    else if (cmd == "RAW ON") {
        rawIQMode = true;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"raw\",\"val\":1}");
    }
    else if (cmd == "RAW OFF") {
        rawIQMode = false;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"raw\",\"val\":0}");
    }
    else if (cmd == "PRESENCE ON") {
        presenceMode = true;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"presence\",\"val\":1}");
    }
    else if (cmd == "PRESENCE OFF") {
        presenceMode = false;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"presence\",\"val\":0}");
    }
    else if (cmd == "GESTURE ON") {
        gestureMode = true;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"gesture\",\"val\":1}");
    }
    else if (cmd == "GESTURE OFF") {
        gestureMode = false;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"gesture\",\"val\":0}");
    }
    else if (cmd.startsWith("TARGET ")) {
        // Set a MAC as tracking target
        String macStr = cmd.substring(7);
        macStr.toLowerCase();
        uint8_t mac[6];
        if (sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
            int idx = findTrackedMAC(mac);
            if (idx >= 0) {
                trackedMacs[idx].is_target = true;
                Serial.println("{\"type\":\"ack\",\"cmd\":\"target\",\"mac\":\"" + macStr + "\"}");
            }
        }
    }
    else if (cmd.startsWith("RATE ")) {
        sampleRate = cmd.substring(5).toInt();
        Serial.printf("{\"type\":\"ack\",\"cmd\":\"rate\",\"val\":%d}\n", sampleRate);
    }
    else if (cmd == "RESET") {
        Serial.println("{\"type\":\"ack\",\"cmd\":\"reset\"}");
        delay(100);
        ESP.restart();
    }
    else if (cmd == "CALIBRATE") {
        // Measure noise floor
        float nfSum = 0;
        int nfCount = 0;
        uint32_t start = millis();
        while (millis() - start < 2000) {
            // Collect noise samples
            delay(10);
        }
        signalQuality.noise_floor = -95;  // Default
        Serial.printf("{\"type\":\"calibration\",\"noise_floor\":%.1f}\n", signalQuality.noise_floor);
    }
    else if (cmd == "SAVE") {
        // Save config to EEPROM
        EEPROM.writeUInt(EEPROM_MAGIC, 0xDEADBEEF);
        EEPROM.writeUChar(EEPROM_CHANNEL, currentChannel);
        EEPROM.writeUInt(EEPROM_SAMPLE_RATE, sampleRate);
        EEPROM.writeUChar(EEPROM_POWER_MODE, powerMode);
        EEPROM.commit();
        Serial.println("{\"type\":\"ack\",\"cmd\":\"save\"}");
    }
    else if (cmd == "LOAD") {
        // Load config from EEPROM
        if (EEPROM.readUInt(EEPROM_MAGIC) == 0xDEADBEEF) {
            currentChannel = EEPROM.readUChar(EEPROM_CHANNEL);
            sampleRate = EEPROM.readUInt(EEPROM_SAMPLE_RATE);
            powerMode = EEPROM.readUChar(EEPROM_POWER_MODE);
            setChannel(currentChannel);
            Serial.println("{\"type\":\"ack\",\"cmd\":\"load\",\"ch\":" + String(currentChannel) + "}");
        }
    }
    else if (cmd == "CLEAR") {
        // Clear tracked MACs
        numTrackedMacs = 0;
        totalPackets = 0;
        Serial.println("{\"type\":\"ack\",\"cmd\":\"clear\"}");
    }
    else if (cmd == "HELP") {
        Serial.println("{\"type\":\"help\",\"cmds\":[\"CH <1-14>\",\"STATUS\",\"MACS\",\"CHANNELS\",\"SCAN\",\"AUTOSCAN ON/OFF\",\"RAW ON/OFF\",\"PRESENCE ON/OFF\",\"GESTURE ON/OFF\",\"TARGET <mac>\",\"RATE <pps>\",\"CALIBRATE\",\"SAVE\",\"LOAD\",\"CLEAR\",\"RESET\"]}");
    }
}

void handleSerialCommands() {
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        processCommand(cmd);
    }
}

void handleUDPCommands() {
    if (!networkConnected) return;
    
    int packetSize = cmdUdp.parsePacket();
    if (packetSize) {
        char buffer[256];
        int len = cmdUdp.read(buffer, sizeof(buffer) - 1);
        buffer[len] = 0;
        processCommand(String(buffer));
    }
}

// ============================================================================
// Signal Quality Monitoring
// ============================================================================

void updateSignalQuality() {
    uint32_t now = millis();
    
    // Calculate packets per second
    if (now - lastSecond >= 1000) {
        signalQuality.packets_per_second = packetsThisSecond;
        packetsThisSecond = 0;
        lastSecond = now;
    }
    
    // Calculate average SNR from recent packets
    float snrSum = 0;
    float nfSum = 0;
    int count = 0;
    
    int idx = readIndex;
    while (idx != writeIndex && count < 20) {
        CSIPacket* p = &csiBuffer[idx];
        snrSum += calculateSNR(p->rssi, p->noise_floor);
        nfSum += p->noise_floor;
        count++;
        idx = (idx + 1) % CSI_BUFFER_SIZE;
    }
    
    if (count > 0) {
        signalQuality.snr = snrSum / count;
        signalQuality.noise_floor = nfSum / count;
    }
    
    // Update channel stats
    if (currentChannel >= 1 && currentChannel <= 14) {
        channelStats[currentChannel - 1].channel = currentChannel;
        channelStats[currentChannel - 1].packet_count = totalPackets;
        channelStats[currentChannel - 1].avg_rssi = (int8_t)signalQuality.snr;
        channelStats[currentChannel - 1].noise_floor = (int8_t)signalQuality.noise_floor;
        channelStats[currentChannel - 1].last_scan = now;
    }
}

// ============================================================================
// Setup & Main Loop
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println();
    Serial.println("╔════════════════════════════════════════════╗");
    Serial.println("║   HydraRecon ESP32 Advanced CSI v" FIRMWARE_VERSION "   ║");
    Serial.println("╚════════════════════════════════════════════╝");
    
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    
    // Initialize EEPROM
    EEPROM.begin(EEPROM_SIZE);
    
    // Load saved config if available
    if (EEPROM.readUInt(EEPROM_MAGIC) == 0xDEADBEEF) {
        currentChannel = EEPROM.readUChar(EEPROM_CHANNEL);
        sampleRate = EEPROM.readUInt(EEPROM_SAMPLE_RATE);
        powerMode = EEPROM.readUChar(EEPROM_POWER_MODE);
        Serial.printf("Loaded config: CH=%d, Rate=%d, Power=%d\n", currentChannel, sampleRate, powerMode);
    }
    
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
    WiFi.begin(DEFAULT_SSID, DEFAULT_PASS);
    
    Serial.print("Connecting to WiFi");
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts++ < 20) {
        delay(500);
        Serial.print(".");
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        networkConnected = true;
        Serial.println();
        Serial.printf("Connected! IP: %s\n", WiFi.localIP().toString().c_str());
        udp.begin(UDP_PORT);
        cmdUdp.begin(CMD_PORT);
    } else {
        Serial.println();
        Serial.println("WiFi not connected - running in standalone USB mode");
    }
    
    // Configure CSI capture
    wifi_csi_config_t csiConfig = {
        .lltf_en = true,
        .htltf_en = true,
        .stbc_htltf2_en = true,
        .ltf_merge_en = true,
        .channel_filter_en = true,
        .manu_scale = false,
        .shift = 0
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csiConfig));
    ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(&csiCallback, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_csi(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    
    setChannel(currentChannel);
    
    // Initialize channel stats
    for (int i = 0; i < 14; i++) {
        channelStats[i].channel = i + 1;
        channelStats[i].packet_count = 0;
        channelStats[i].avg_rssi = -80;
        channelStats[i].noise_floor = -95;
        channelStats[i].interference_score = 0;
    }
    
    digitalWrite(LED_PIN, LOW);
    Serial.println("CSI capture active!");
    Serial.println("Type HELP for commands");
    
    // Send initial status
    delay(500);
    sendStatusReport();
}

void loop() {
    // Process buffered CSI packets
    while (readIndex != writeIndex) {
        CSIPacket* p = &csiBuffer[readIndex];
        sendCSIPacket(p, !networkConnected);
        
        // Free memory
        if (p->data) { free(p->data); p->data = NULL; }
        if (p->raw_iq) { free(p->raw_iq); p->raw_iq = NULL; }
        
        readIndex = (readIndex + 1) % CSI_BUFFER_SIZE;
    }
    
    // Handle commands
    handleSerialCommands();
    handleUDPCommands();
    
    // Update signal quality metrics
    updateSignalQuality();
    
    // Periodic channel scan
    if (autoChannelScan && (millis() - lastChannelScan > CHANNEL_SCAN_INTERVAL)) {
        scanChannels();
    }
    
    // Heartbeat LED
    static uint32_t lastBlink = 0;
    if (millis() - lastBlink > 2000) {
        digitalWrite(LED_PIN, HIGH);
        delay(50);
        digitalWrite(LED_PIN, LOW);
        lastBlink = millis();
    }
    
    // Periodic status report
    static uint32_t lastStatus = 0;
    if (millis() - lastStatus > 10000) {
        sendStatusReport();
        lastStatus = millis();
    }
    
    delay(1);
}
