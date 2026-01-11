ESP32 WiFi Sensing Firmware
===========================

Overview
--------
This folder contains two Arduino/PlatformIO projects for ESP32-S3:

- `sensing` — the primary device (connected to the PC). Runs WiFi promiscuous sniffing, hosts a simple HTTP server and serves a firmware binary for OTA to the remote device.
- `remote` — the secondary device (placed ~15ft away). Connects to the sensing device AP, sends RSSI/scan data back, and can perform HTTP OTA to update itself when a new binary is available.

Quick steps
-----------
1. Install PlatformIO (VS Code PlatformIO extension or `pip install platformio`).
2. Build the `remote` firmware to produce `firmware.bin`:

```bash
cd esp32_firmware/remote
platformio run
# produced binary in .pio/build/<board>/firmware.bin
```

3. Copy `firmware.bin` into the `sensing/data/` directory (so it will be available from the sensing device SPIFFS):

```bash
cp .pio/build/esp32-s3-devkitc-1/firmware.bin ../sensing/data/firmware.bin
cd ../sensing
platformio run --target buildfs
platformio run --target upload
```

4. Flash the `sensing` firmware (the device connected to this computer):

```bash
cd esp32_firmware/sensing
platformio run --target upload
```

5. Power the `remote` device. It will connect to the sensing AP and check `http://192.168.4.1/firmware.bin`. If present, it will perform OTA and reboot.

Notes
-----
- The provided code is a prototype: it demonstrates packet sniffing (MAC + RSSI), a simple HTTP file server for OTA, and an OTA client on the remote device. It is not a production-ready sensing stack or precise 3D reconstruction engine.
- For advanced CSI-based sensing you will need firmware that exposes CSI (ESP-IDF CSI APIs) and a backend to process CSI samples into spatial reconstructions.

Security / Ethics
-----------------
Use these tools only for authorized research and with consent. Do not deploy for covert surveillance.
