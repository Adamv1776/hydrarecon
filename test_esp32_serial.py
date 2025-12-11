#!/usr/bin/env python3
"""
Test ESP32 Serial CSI Integration

This script verifies that CSI data flows correctly from the ESP32 via USB serial
into the WiFi Sensing module.
"""

import sys
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ESP32Test")

# Add core to path
sys.path.insert(0, '/home/adam/hydra 1/hydrarecon')

try:
    from core.wifi_sensing import ESP32SerialReceiver, CSIData
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Make sure you're running from the hydrarecon directory")
    sys.exit(1)

def main():
    """Test ESP32 serial receiver."""
    
    # Check for pyserial
    try:
        import serial
        logger.info("pyserial is installed ✓")
    except ImportError:
        logger.error("pyserial not installed. Run: pip install pyserial")
        return 1
    
    # Statistics
    packets_received = 0
    last_print = time.time()
    rssi_values = []
    
    def on_csi(csi: CSIData):
        nonlocal packets_received, last_print, rssi_values
        packets_received += 1
        rssi_values.append(csi.rssi)
        
        # Print status every 2 seconds
        if time.time() - last_print >= 2.0:
            avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else 0
            logger.info(
                f"Received {packets_received} packets | "
                f"Last: CH{csi.channel} RSSI:{csi.rssi:.0f}dBm | "
                f"Avg RSSI: {avg_rssi:.1f}dBm | "
                f"Subcarriers: {len(csi.amplitude)}"
            )
            last_print = time.time()
            rssi_values = rssi_values[-100:]  # Keep last 100
    
    # Create receiver
    receiver = ESP32SerialReceiver(
        port="/dev/ttyUSB0",
        baudrate=115200
    )
    
    logger.info("=" * 60)
    logger.info("ESP32 CSI Serial Receiver Test")
    logger.info("=" * 60)
    logger.info("Connecting to /dev/ttyUSB0 at 115200 baud...")
    
    if not receiver.start(on_csi):
        logger.error("Failed to start receiver")
        return 1
    
    logger.info("Receiver started! Waiting for CSI packets...")
    logger.info("Press Ctrl+C to stop\n")
    
    try:
        # Test channel switching
        time.sleep(3)
        if packets_received > 0:
            logger.info(f"✓ CSI data flowing! ({packets_received} packets)")
            
            # Try changing channel
            logger.info("Switching to channel 1...")
            receiver.set_channel(1)
            time.sleep(2)
            
            logger.info("Switching to channel 6...")
            receiver.set_channel(6)
            time.sleep(2)
            
            logger.info("Switching to channel 11...")
            receiver.set_channel(11)
            time.sleep(2)
            
            # Request status
            logger.info("Requesting device status...")
            receiver.get_status()
            time.sleep(1)
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("\nStopping...")
    finally:
        receiver.stop()
        logger.info(f"\nTotal packets received: {receiver.packets_received}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
