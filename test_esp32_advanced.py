#!/usr/bin/env python3
"""
Test ESP32 Advanced Features

This script tests all the new ESP32-specific features:
- Advanced signal quality monitoring
- Doppler velocity estimation
- Automatic channel scanning
- MAC tracking
- Presence detection
- Gesture recognition
"""

import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ESP32AdvTest")

sys.path.insert(0, '/home/adam/hydra 1/hydrarecon')

from core.wifi_sensing import (
    ESP32SerialReceiver,
    ESP32AdvancedController,
    ESP32SignalAnalyzer,
    ESP32GestureRecognizer,
    ESP32PresenceZoneManager,
    CSIData,
)


def main():
    logger.info("=" * 70)
    logger.info("ESP32 Advanced Features Test")
    logger.info("=" * 70)
    
    # Create receiver
    receiver = ESP32SerialReceiver(port="/dev/ttyUSB0", baudrate=115200)
    
    # Create advanced controller
    controller = ESP32AdvancedController(receiver)
    
    # Create signal analyzer
    analyzer = ESP32SignalAnalyzer()
    
    # Create gesture recognizer
    gestures = ESP32GestureRecognizer(window_size=30)
    
    # Create presence zone manager
    zones = ESP32PresenceZoneManager()
    zones.add_zone("living_room", "Living Room", (0, 0), 3.0)
    zones.add_zone("kitchen", "Kitchen", (5, 0), 2.5)
    zones.set_esp32_position("esp32_main", (2.5, 2.5))
    
    # Stats
    stats = {
        "csi_packets": 0,
        "status_updates": 0,
        "mac_updates": 0,
        "doppler_samples": [],
        "snr_samples": [],
        "activities": [],
        "gestures_detected": [],
    }
    
    def on_csi(csi: CSIData):
        stats["csi_packets"] += 1
        
        # Run signal analysis
        analysis = analyzer.update(csi)
        
        if analysis.get("doppler"):
            stats["doppler_samples"].append(analysis["doppler"])
        
        # Check for gestures
        doppler = analysis.get("doppler", 0)
        gesture = gestures.update(csi, doppler)
        if gesture:
            stats["gestures_detected"].append(gesture)
            logger.info(f"🎯 Gesture detected: {gesture[0]} (confidence: {gesture[1]:.2f})")
        
        # Update presence zones
        zones.update("esp32_main", csi, float(csi.rssi))
    
    def on_message(msg):
        msg_type = msg.get("type", "")
        
        if msg_type == "status":
            stats["status_updates"] += 1
            snr = msg.get("snr", 0)
            if snr:
                stats["snr_samples"].append(snr)
            
            logger.info(
                f"📡 Status: uptime={msg.get('uptime')}s, ch={msg.get('ch')}, "
                f"pkts={msg.get('pkts')}, pps={msg.get('pps')}, "
                f"macs={msg.get('macs')}, heap={msg.get('free_heap')}"
            )
        
        elif msg_type == "macs":
            stats["mac_updates"] += 1
            macs = msg.get("macs", [])
            logger.info(f"📱 Tracking {len(macs)} MAC addresses")
            for m in macs[:3]:  # Show first 3
                logger.info(f"   - {m.get('mac')}: RSSI={m.get('rssi')}dBm, pkts={m.get('pkts')}")
        
        elif msg_type == "channels":
            chans = msg.get("stats", [])
            logger.info(f"📶 Channel stats for {len(chans)} channels")
            for ch in chans:
                if ch.get("pkts", 0) > 0:
                    logger.info(f"   - CH{ch.get('ch')}: {ch.get('pkts')} pkts, RSSI={ch.get('rssi')}dBm")
        
        elif msg_type == "scan_result":
            logger.info(f"🔍 Channel scan complete: best={msg.get('best_ch')}, score={msg.get('score')}")
        
        elif msg_type == "ack":
            logger.debug(f"ACK: {msg.get('cmd')}={msg.get('val')}")
    
    # Register callbacks
    receiver.on_message = on_message
    
    # Start receiver
    logger.info("\nStarting ESP32 receiver...")
    if not receiver.start(on_csi):
        logger.error("Failed to start receiver!")
        return 1
    
    logger.info("Receiver started! Running tests...\n")
    
    try:
        # Wait for initial data
        time.sleep(3)
        
        # Request status
        logger.info("--- Requesting Status ---")
        controller.get_status()
        time.sleep(1)
        
        # Request tracked MACs
        logger.info("\n--- Requesting Tracked MACs ---")
        controller.get_tracked_macs()
        time.sleep(1)
        
        # Request channel stats
        logger.info("\n--- Requesting Channel Stats ---")
        controller.get_channel_stats()
        time.sleep(1)
        
        # Test channel switching
        logger.info("\n--- Testing Channel Control ---")
        controller.set_channel(1)
        time.sleep(2)
        controller.set_channel(6)
        time.sleep(2)
        controller.set_channel(11)
        time.sleep(2)
        
        # Enable auto channel scan
        logger.info("\n--- Enabling Auto Channel Scan ---")
        controller.enable_auto_channel_scan(True)
        time.sleep(3)
        
        # Collect more data
        logger.info("\n--- Collecting Signal Data ---")
        time.sleep(5)
        
        # Get signal quality
        sig_quality = controller.get_signal_quality()
        logger.info(f"\n📊 Signal Quality:")
        logger.info(f"   SNR: {sig_quality.get('snr', 0):.1f} dB")
        logger.info(f"   Avg SNR: {sig_quality.get('avg_snr', 0):.1f} dB")
        logger.info(f"   Noise Floor: {sig_quality.get('noise_floor', 0):.1f} dBm")
        logger.info(f"   Avg PPS: {sig_quality.get('avg_pps', 0):.1f}")
        
        # Get velocity estimate
        velocity = analyzer.get_velocity_estimate()
        logger.info(f"\n🏃 Velocity Estimate: {velocity:.4f} m/s")
        
        # Get breathing rate
        breathing = analyzer.get_breathing_rate()
        if breathing:
            logger.info(f"💨 Breathing Rate: {breathing:.1f} breaths/min")
        else:
            logger.info("💨 Breathing Rate: Not enough data")
        
        # Check presence zones
        active_zones = zones.get_active_zones()
        logger.info(f"\n🏠 Active Zones: {len(active_zones)}")
        for zone_id, conf in active_zones:
            logger.info(f"   - {zone_id}: confidence={conf:.2f}")
        
    except KeyboardInterrupt:
        logger.info("\nStopping...")
    finally:
        receiver.stop()
    
    # Print summary
    logger.info("\n" + "=" * 70)
    logger.info("Test Summary")
    logger.info("=" * 70)
    logger.info(f"CSI Packets Received: {stats['csi_packets']}")
    logger.info(f"Status Updates: {stats['status_updates']}")
    logger.info(f"MAC Updates: {stats['mac_updates']}")
    logger.info(f"Gestures Detected: {len(stats['gestures_detected'])}")
    
    if stats['doppler_samples']:
        avg_doppler = sum(abs(d) for d in stats['doppler_samples']) / len(stats['doppler_samples'])
        logger.info(f"Avg Doppler Shift: {avg_doppler:.4f}")
    
    if stats['snr_samples']:
        avg_snr = sum(stats['snr_samples']) / len(stats['snr_samples'])
        logger.info(f"Avg SNR: {avg_snr:.1f} dB")
    
    logger.info("\n✅ ESP32 Advanced Features Test Complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
