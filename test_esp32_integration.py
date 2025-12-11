#!/usr/bin/env python3
"""
Full ESP32 WiFi Sensing Integration Test

This script verifies the complete data pipeline from ESP32 USB serial
through all sensing algorithms.
"""

import sys
import time
import logging
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IntegrationTest")

sys.path.insert(0, '/home/adam/hydra 1/hydrarecon')

try:
    from core.wifi_sensing import (
        WifiSensingEngine,
        ESP32SerialReceiver,
        CSIData
    )
except ImportError as e:
    logger.error(f"Import error: {e}")
    sys.exit(1)


async def test_engine():
    """Test full integration with WifiSensingEngine asynchronously."""
    
    logger.info("=" * 70)
    logger.info("ESP32 WiFi Sensing Full Integration Test")
    logger.info("=" * 70)
    
    # Create sensing engine with ESP32 serial port
    logger.info("Creating WifiSensingEngine with ESP32 serial mode...")
    engine = WifiSensingEngine(esp32_serial_port="/dev/ttyUSB0")
    
    # Define detection callback
    detections = []
    def on_detection(det_type, data):
        detections.append((det_type, data))
        logger.info(f"Detection: {det_type.name} - {data}")
    
    engine.on_detection = on_detection
    
    # Start engine (this will start the ESP32 serial receiver)
    logger.info("\nStarting sensing engine...")
    
    # Run the async start but only for a limited time
    async def run_with_timeout():
        task = asyncio.create_task(engine.start())
        await asyncio.sleep(12)  # Run for 12 seconds
        await engine.stop()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    
    await run_with_timeout()
    
    # Get results
    status = engine.get_esp32_status()
    logger.info("\n" + "=" * 70)
    logger.info("Results after 12 seconds:")
    logger.info("=" * 70)
    
    logger.info(f"ESP32 UDP enabled: {status.get('udp_enabled', False)}")
    logger.info(f"ESP32 Serial enabled: {status.get('serial_enabled', False)}")
    logger.info(f"ESP32 Serial packets received: {status.get('serial_packets', 0)}")
    logger.info(f"ESP32 UDP packets received: {status.get('udp_packets', 0)}")
    logger.info(f"Detection events: {len(detections)}")
    
    # Check CSI history
    csi_count = len(engine.csi_history) if hasattr(engine, 'csi_history') else 0
    logger.info(f"CSI samples in history: {csi_count}")
    
    logger.info("\nIntegration test complete!")
    
    # Final verdict
    total_packets = status.get('serial_packets', 0) + status.get('udp_packets', 0)
    if total_packets > 0:
        logger.info("\n✅ SUCCESS: ESP32 USB data is properly integrated!")
        logger.info(f"   Total CSI packets processed: {total_packets}")
        return 0
    else:
        logger.error("\n❌ FAILED: No CSI data received from ESP32")
        return 1


def main():
    """Entry point."""
    return asyncio.run(test_engine())


if __name__ == "__main__":
    sys.exit(main())
