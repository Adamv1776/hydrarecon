# HydraRecon ESP32 CSI WiFi Sensing Firmware

This firmware turns an ESP32 into a WiFi Channel State Information (CSI) sensor for the HydraRecon WiFi Sensing module.

## Features

- **WiFi CSI Capture**: Captures detailed Channel State Information including amplitude and phase
- **Promiscuous Mode**: Monitors all WiFi traffic on the configured channel
- **UDP Streaming**: Sends CSI data as JSON to the HydraRecon host
- **Serial Commands**: Configure channel, view status, toggle modes
- **Multi-Channel Support**: Switch between WiFi channels 1-14

## Hardware Requirements

- ESP32 development board (ESP32-WROOM, ESP32-DevKitC, etc.)
- USB cable for flashing and power
- Optional: External antenna for better range

## Building & Flashing

### Prerequisites

```bash
pip install platformio
```

### Build

```bash
# Copy to a path without spaces (ESP-IDF limitation)
cp -r firmware/esp32_csi_udp /tmp/esp32_csi_build
cd /tmp/esp32_csi_build
pio run
```

### Flash

```bash
pio run --target upload
```

### Monitor Serial Output

```bash
pio device monitor
```

## Configuration

Edit `src/main.cpp` to configure:

```cpp
const char* WIFI_SSID = "YOUR_WIFI_SSID";  // Your WiFi network
const char* WIFI_PASS = "YOUR_WIFI_PASS";  // WiFi password
const char* UDP_HOST = "192.168.1.100";    // HydraRecon host IP
const uint16_t UDP_PORT = 5555;            // UDP port (match WifiSensingEngine)
```

## Serial Commands

Connect at 115200 baud and use these commands:

| Command | Description |
|---------|-------------|
| `CH <1-14>` | Set WiFi channel |
| `STATUS` | Show packet count, channel, network status |
| `HELP` | Show available commands |

## UDP JSON Format

CSI packets are sent as JSON:

```json
{
    "type": "csi",
    "ts": 1234567890,
    "ch": 6,
    "rssi": -45,
    "mac": "aa:bb:cc:dd:ee:ff",
    "len": 128,
    "csi": [[12.5, 0.785], [10.2, -1.234], ...]
}
```

Each CSI subcarrier is represented as `[amplitude, phase]`.

## Integration with HydraRecon

1. Flash this firmware to your ESP32
2. Configure WiFi credentials and host IP
3. Start HydraRecon WiFi Sensing with ESP32 mode:

```python
from core.wifi_sensing import WifiSensingEngine

engine = WifiSensingEngine(esp32_udp_port=5555)
engine.start()
```

The engine will automatically receive and process CSI data from the ESP32.

## LED Status

- **Blinking**: CSI capture active
- **Solid**: Connecting to WiFi
- **Off**: Error or sleep

## Troubleshooting

### No CSI Data
- Ensure ESP32 is on the same network as the host
- Check firewall allows UDP port 5555
- Verify `UDP_HOST` IP is correct

### Flash Errors
- Erase flash first: `pio run -t erase`
- Use a shorter/better USB cable
- Hold BOOT button during flash on some boards

### Build Errors (Whitespace in Path)
ESP-IDF doesn't support paths with spaces. Copy to `/tmp/` or rename directories.

## License

Part of HydraRecon - Advanced Security Framework
