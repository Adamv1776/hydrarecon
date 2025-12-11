#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include "esp_wifi.h"

// Configuration
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASS = "YOUR_WIFI_PASS";
const char* UDP_HOST = "192.168.1.100";
const uint16_t UDP_PORT = 5555;
#define LED_PIN 2
#define DEFAULT_CHANNEL 6
#define CSI_BUFFER_SIZE 32

struct csi_pkt {
    int8_t* data;
    int16_t len;
    int8_t rssi;
    uint8_t channel;
    int64_t ts;
    uint8_t mac[6];
};

WiFiUDP udp;
volatile bool netConnected = false;
volatile uint32_t pktCount = 0;
volatile uint8_t curChannel = DEFAULT_CHANNEL;
csi_pkt csiBuffer[CSI_BUFFER_SIZE];
volatile int writeIdx = 0;
volatile int readIdx = 0;

void csiCallback(void* ctx, wifi_csi_info_t* info) {
    if (!info || !info->buf || info->len <= 0) return;
    int next = (writeIdx + 1) % CSI_BUFFER_SIZE;
    if (next != readIdx) {
        csi_pkt* p = &csiBuffer[writeIdx];
        p->len = info->len;
        p->rssi = info->rx_ctrl.rssi;
        p->channel = info->rx_ctrl.channel;
        p->ts = esp_timer_get_time();
        memcpy(p->mac, info->mac, 6);
        if (p->data) free(p->data);
        p->data = (int8_t*)malloc(info->len);
        if (p->data) {
            memcpy(p->data, info->buf, info->len);
            writeIdx = next;
            pktCount++;
        }
    }
}

void promiscCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (pktCount % 100 == 0) digitalWrite(LED_PIN, !digitalRead(LED_PIN));
}

void sendCSI(csi_pkt* p) {
    if (!netConnected || !p || !p->data) return;
    String json = "{\"type\":\"csi\",\"ts\":";
    json += String((unsigned long)(p->ts/1000));
    json += ",\"ch\":" + String(p->channel);
    json += ",\"rssi\":" + String(p->rssi);
    char mac[18];
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);
    json += ",\"mac\":\""; json += mac; json += "\"";
    json += ",\"len\":" + String(p->len) + ",\"csi\":[";
    for (int i = 0; i < p->len; i += 2) {
        if (i+1 < p->len) {
            float amp = sqrt(p->data[i]*p->data[i] + p->data[i+1]*p->data[i+1]);
            float ph = atan2(p->data[i], p->data[i+1]);
            if (i > 0) json += ",";
            json += "[" + String(amp,2) + "," + String(ph,4) + "]";
        }
    }
    json += "]}";
    udp.beginPacket(UDP_HOST, UDP_PORT);
    udp.print(json);
    udp.endPacket();
}

void sendCSISerial(csi_pkt* p) {
    // Send JSON via serial for USB mode (same format as UDP)
    if (!p || !p->data) return;
    String json = "{\"type\":\"csi\",\"ts\":";
    json += String((unsigned long)(p->ts/1000));
    json += ",\"ch\":" + String(p->channel);
    json += ",\"rssi\":" + String(p->rssi);
    char mac[18];
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);
    json += ",\"mac\":\""; json += mac; json += "\"";
    json += ",\"len\":" + String(p->len) + ",\"csi\":[";
    for (int i = 0; i < p->len; i += 2) {
        if (i+1 < p->len) {
            float amp = sqrt(p->data[i]*p->data[i] + p->data[i+1]*p->data[i+1]);
            float ph = atan2(p->data[i], p->data[i+1]);
            if (i > 0) json += ",";
            json += "[" + String(amp,2) + "," + String(ph,4) + "]";
        }
    }
    json += "]}";
    Serial.println(json);
}

void setChannel(uint8_t ch) {
    if (ch >= 1 && ch <= 14) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        curChannel = ch;
        Serial.println("CH=" + String(ch));
    }
}

void handleSerial() {
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd.startsWith("CH ")) setChannel(cmd.substring(3).toInt());
        else if (cmd == "STATUS") {
            Serial.println("PKT:" + String(pktCount) + " CH:" + String(curChannel) + " NET:" + (netConnected?"Y":"N"));
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n=== HydraRecon ESP32 CSI ===");
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    int att = 0;
    while (WiFi.status() != WL_CONNECTED && att++ < 20) { delay(500); Serial.print("."); }
    
    if (WiFi.status() == WL_CONNECTED) {
        netConnected = true;
        Serial.println("\nIP:" + WiFi.localIP().toString());
        udp.begin(UDP_PORT);
    } else {
        Serial.println("\nNo WiFi - standalone mode");
    }
    
    wifi_csi_config_t cfg = { .lltf_en=true, .htltf_en=true, .stbc_htltf2_en=true, .ltf_merge_en=true, .channel_filter_en=true, .manu_scale=false, .shift=0 };
    esp_wifi_set_csi_config(&cfg);
    esp_wifi_set_csi_rx_cb(&csiCallback, NULL);
    esp_wifi_set_csi(true);
    esp_wifi_set_promiscuous_rx_cb(&promiscCb);
    esp_wifi_set_promiscuous(true);
    setChannel(DEFAULT_CHANNEL);
    digitalWrite(LED_PIN, LOW);
    Serial.println("Ready!");
}

void loop() {
    while (readIdx != writeIdx) {
        csi_pkt* p = &csiBuffer[readIdx];
        if (netConnected) {
            sendCSI(p);  // UDP mode
        } else {
            sendCSISerial(p);  // USB serial mode - send JSON
        }
        if (p->data) { free(p->data); p->data = NULL; }
        readIdx = (readIdx + 1) % CSI_BUFFER_SIZE;
    }
    handleSerial();
    static uint32_t lastB = 0;
    if (millis() - lastB > 2000) { digitalWrite(LED_PIN, HIGH); delay(50); digitalWrite(LED_PIN, LOW); lastB = millis(); }
    delay(1);
}
