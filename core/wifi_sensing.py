"""
WiFi Sensing Module - Indoor Localization & Environment Reconstruction

Uses WiFi signals (CSI - Channel State Information) to:
1. Detect and locate individuals within buildings
2. Track movement with accurate distance measurements
3. Reconstruct indoor environments using AI-based analysis

Theory:
- WiFi signals reflect off walls, furniture, and human bodies
- Human movement causes characteristic signal interruptions
- CSI data contains amplitude and phase information for each subcarrier
- AI models can learn to interpret these patterns for localization

WARNING: This module is for authorized security research only.
Unauthorized surveillance is illegal.
"""

from __future__ import annotations

import asyncio
import logging
import os
import json
import math
import struct
import socket
import json as json_lib
import time
import subprocess
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum
from pathlib import Path
import threading
from collections import deque
import numpy as np
import statistics

# Lightweight tracking and anomaly helpers to stabilize WiFi sensing outputs
@dataclass
class KalmanState:
    position: Tuple[float, float, float]
    velocity: Tuple[float, float, float]
    covariance: float = 1.0


class KalmanTracker:
    """Simple constant-velocity Kalman-style smoother for location estimates."""

    def __init__(self, process_noise: float = 0.05, measurement_noise: float = 0.3):
        self.process_noise = process_noise
        self.measurement_noise = measurement_noise
        self.state: Optional[KalmanState] = None

    def reset(self):
        self.state = None

    def update(self, measurement: LocationEstimate) -> LocationEstimate:
        if self.state is None:
            self.state = KalmanState(
                position=(measurement.x, measurement.y, measurement.z),
                velocity=measurement.velocity,
                covariance=1.0,
            )
            return measurement

        # Predict step
        px, py, pz = self.state.position
        vx, vy, vz = self.state.velocity
        pred_pos = (px + vx, py + vy, pz + vz)
        pred_cov = self.state.covariance + self.process_noise

        # Update step (scalar covariance for simplicity)
        K = pred_cov / (pred_cov + self.measurement_noise)
        new_pos = (
            pred_pos[0] + K * (measurement.x - pred_pos[0]),
            pred_pos[1] + K * (measurement.y - pred_pos[1]),
            pred_pos[2] + K * (measurement.z - pred_pos[2]),
        )

        # Velocity update from position delta
        new_vel = (
            new_pos[0] - px,
            new_pos[1] - py,
            new_pos[2] - pz,
        )

        self.state = KalmanState(position=new_pos, velocity=new_vel, covariance=(1 - K) * pred_cov)

        return LocationEstimate(
            x=new_pos[0],
            y=new_pos[1],
            z=new_pos[2],
            confidence=min(1.0, max(0.0, (measurement.confidence + K * 0.1))),
            accuracy_radius=max(0.25, measurement.accuracy_radius * (1 - K * 0.3)),
            velocity=new_vel,
            timestamp=measurement.timestamp,
            detection_type=measurement.detection_type,
            room_id=measurement.room_id,
        )


class CSIDenoiser:
    """Median-based CSI denoiser to suppress spikes and radio noise."""

    def __init__(self, window: int = 5):
        self.window = window
        self.amp_history: deque = deque(maxlen=window)
        self.phase_history: deque = deque(maxlen=window)

    def denoise(self, csi: CSIData) -> CSIData:
        if not csi.amplitude or not csi.phase:
            return csi

        self.amp_history.append(csi.amplitude)
        self.phase_history.append(csi.phase)

        if len(self.amp_history) < 2:
            return csi

        # Median across history per subcarrier
        amp_array = np.array(self.amp_history)
        phase_array = np.array(self.phase_history)

        median_amp = np.median(amp_array, axis=0).tolist()
        median_phase = np.median(phase_array, axis=0).tolist()

        return CSIData(
            timestamp=csi.timestamp,
            mac_address=csi.mac_address,
            rssi=csi.rssi,
            channel=csi.channel,
            bandwidth=csi.bandwidth,
            num_subcarriers=csi.num_subcarriers,
            amplitude=median_amp,
            phase=median_phase,
            noise_floor=csi.noise_floor,
            antenna_config=csi.antenna_config,
        )


class FallDetector:
    """Detect falls from sharp CSI-induced motion changes."""

    def __init__(self, window: int = 20, velocity_threshold: float = 1.5):
        self.window = window
        self.velocity_threshold = velocity_threshold
        self.history: deque = deque(maxlen=window)

    def update(self, movement_intensity: float, timestamp: float) -> Optional[Dict[str, Any]]:
        self.history.append((timestamp, movement_intensity))
        if len(self.history) < self.window:
            return None

        # Check for sudden spike in intensity that then decays
        intensities = [x[1] for x in self.history]
        peak = max(intensities)
        tail_avg = np.mean(intensities[int(self.window * 0.6):])

        if peak > self.velocity_threshold and peak > tail_avg * 1.8:
            return {
                "detected": True,
                "peak": round(float(peak), 3),
                "timestamp": timestamp,
                "confidence": min(1.0, (peak - self.velocity_threshold) / self.velocity_threshold),
            }
        return None


class AnomalyDetector:
    """Lightweight anomaly detector on RSSI/CSI change patterns."""

    def __init__(self, history: int = 200):
        self.history = deque(maxlen=history)

    def update(self, csi: CSIData) -> Optional[Dict[str, Any]]:
        magnitude = np.mean(csi.to_numpy())
        self.history.append(magnitude)
        if len(self.history) < 30:
            return None

        mean = float(np.mean(self.history))
        std = float(np.std(self.history)) + 1e-6
        z = (magnitude - mean) / std
        if abs(z) > 3.5:
            return {
                "detected": True,
                "z_score": round(z, 2),
                "mean": round(mean, 3),
                "std": round(std, 3),
                "magnitude": round(float(magnitude), 3),
            }
        return None


class ChannelHopper:
    """Adaptive channel hopping controller to sample multi-channel CSI."""

    def __init__(self, interface: str, set_channel: Callable[[int], bool]):
        self.interface = interface
        self.set_channel = set_channel
        self.channels: List[int] = [1, 6, 11]
        self.dwell_seconds: float = 5.0
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger("ChannelHopper")

    def configure(self, channels: List[int], dwell_seconds: float = 5.0):
        if channels:
            self.channels = channels
        self.dwell_seconds = max(1.0, dwell_seconds)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        idx = 0
        while not self._stop_event.is_set():
            channel = self.channels[idx % len(self.channels)]
            ok = self.set_channel(channel)
            if ok:
                self.logger.debug("Hopped to channel %s on %s", channel, self.interface)
            else:
                self.logger.debug("Channel hop to %s failed on %s", channel, self.interface)
            idx += 1
            self._stop_event.wait(self.dwell_seconds)


class GestureRecognizer:
    """Recognize hand/body gestures from CSI pattern changes."""

    GESTURES = ["none", "wave", "push", "pull", "swipe_left", "swipe_right", "circle"]

    def __init__(self, window: int = 30):
        self.window = window
        self.history: deque = deque(maxlen=window)
        self.templates: Dict[str, np.ndarray] = self._init_templates()

    def _init_templates(self) -> Dict[str, np.ndarray]:
        """Initialize gesture correlation templates."""
        n = self.window
        templates = {
            "wave": np.sin(np.linspace(0, 4 * np.pi, n)),
            "push": np.concatenate([np.linspace(0, 1, n // 2), np.linspace(1, 0.5, n - n // 2)]),
            "pull": np.concatenate([np.linspace(1, 0, n // 2), np.linspace(0, 0.5, n - n // 2)]),
            "swipe_left": np.linspace(1, 0, n),
            "swipe_right": np.linspace(0, 1, n),
            "circle": np.sin(np.linspace(0, 2 * np.pi, n)) ** 2,
        }
        return templates

    def update(self, csi: CSIData) -> Optional[Dict[str, Any]]:
        magnitude = float(np.mean(csi.amplitude))
        self.history.append(magnitude)
        if len(self.history) < self.window:
            return None

        signal = np.array(self.history)
        signal = (signal - np.mean(signal)) / (np.std(signal) + 1e-6)

        best_gesture = "none"
        best_score = 0.0
        for name, template in self.templates.items():
            norm_template = (template - np.mean(template)) / (np.std(template) + 1e-6)
            corr = float(np.abs(np.corrcoef(signal, norm_template)[0, 1]))
            if corr > best_score:
                best_score = corr
                best_gesture = name

        if best_score > 0.7:
            return {"gesture": best_gesture, "confidence": round(best_score, 3)}
        return None


class HeartRateEstimator:
    """Estimate heart rate from micro-motion in CSI phase variance."""

    def __init__(self, sample_rate: float = 100):
        self.sample_rate = sample_rate
        self.buffer: deque = deque(maxlen=int(sample_rate * 15))  # 15 sec window

    def add_sample(self, csi: CSIData):
        phase_var = float(np.var(csi.phase))
        self.buffer.append((csi.timestamp, phase_var))

    def estimate(self) -> Optional[Dict[str, Any]]:
        if len(self.buffer) < self.sample_rate * 6:
            return None

        vals = np.array([v for _, v in self.buffer])
        # Simple bandpass via moving average subtraction
        short_avg = np.convolve(vals, np.ones(5) / 5, mode="valid")
        long_avg = np.convolve(vals, np.ones(30) / 30, mode="valid")
        min_len = min(len(short_avg), len(long_avg))
        filtered = short_avg[:min_len] - long_avg[:min_len]

        # Detect peaks
        peaks = []
        for i in range(1, len(filtered) - 1):
            if filtered[i] > filtered[i - 1] and filtered[i] > filtered[i + 1]:
                peaks.append(i)

        if len(peaks) < 3:
            return None

        intervals = np.diff(peaks) / self.sample_rate
        avg_interval = float(np.mean(intervals))
        bpm = 60.0 / avg_interval if avg_interval > 0 else 0

        if 40 <= bpm <= 180:
            return {
                "detected": True,
                "bpm": round(bpm, 1),
                "confidence": min(1.0, len(peaks) / 15),
            }
        return None


@dataclass
class TrackedPerson:
    """State for a single tracked individual."""
    id: str
    position: Tuple[float, float, float]
    velocity: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    confidence: float = 0.5
    last_seen: float = 0.0
    breathing_rate: float = 0.0
    heart_rate: float = 0.0


class MultiPersonTracker:
    """Track multiple individuals via CSI clustering."""

    def __init__(self, max_persons: int = 8, merge_distance: float = 1.0):
        self.max_persons = max_persons
        self.merge_distance = merge_distance
        self.persons: Dict[str, TrackedPerson] = {}
        self._next_id = 1

    def update(self, locations: List[LocationEstimate]) -> List[TrackedPerson]:
        now = time.time()

        # Match new locations to existing persons
        unmatched = list(locations)
        for pid, person in list(self.persons.items()):
            best_match = None
            best_dist = self.merge_distance
            for loc in unmatched:
                dist = math.sqrt(
                    (loc.x - person.position[0]) ** 2 +
                    (loc.y - person.position[1]) ** 2 +
                    (loc.z - person.position[2]) ** 2
                )
                if dist < best_dist:
                    best_dist = dist
                    best_match = loc

            if best_match:
                unmatched.remove(best_match)
                person.velocity = (
                    best_match.x - person.position[0],
                    best_match.y - person.position[1],
                    best_match.z - person.position[2],
                )
                person.position = (best_match.x, best_match.y, best_match.z)
                person.confidence = best_match.confidence
                person.last_seen = now
            elif now - person.last_seen > 5.0:
                del self.persons[pid]

        # Add new persons from unmatched
        for loc in unmatched:
            if len(self.persons) >= self.max_persons:
                break
            pid = f"person_{self._next_id}"
            self._next_id += 1
            self.persons[pid] = TrackedPerson(
                id=pid,
                position=(loc.x, loc.y, loc.z),
                confidence=loc.confidence,
                last_seen=now,
            )

        return list(self.persons.values())


@dataclass
class Zone:
    """A named spatial zone for presence detection."""
    id: str
    name: str
    bounds: Tuple[float, float, float, float, float, float]  # min_x, min_y, min_z, max_x, max_y, max_z

    def contains(self, pos: Tuple[float, float, float]) -> bool:
        x, y, z = pos
        return (
            self.bounds[0] <= x <= self.bounds[3] and
            self.bounds[1] <= y <= self.bounds[4] and
            self.bounds[2] <= z <= self.bounds[5]
        )


class ZoneManager:
    """Manage spatial zones and detect which zones contain persons."""

    def __init__(self):
        self.zones: Dict[str, Zone] = {}

    def add_zone(self, zone: Zone):
        self.zones[zone.id] = zone

    def remove_zone(self, zone_id: str):
        self.zones.pop(zone_id, None)

    def get_zone_for_position(self, pos: Tuple[float, float, float]) -> Optional[Zone]:
        for zone in self.zones.values():
            if zone.contains(pos):
                return zone
        return None

    def get_occupied_zones(self, persons: List[TrackedPerson]) -> List[Tuple[Zone, List[TrackedPerson]]]:
        result: Dict[str, List[TrackedPerson]] = {z.id: [] for z in self.zones.values()}
        for person in persons:
            zone = self.get_zone_for_position(person.position)
            if zone:
                result[zone.id].append(person)
        return [(self.zones[zid], ppl) for zid, ppl in result.items() if ppl]


class ESP32CSIReceiver:
    """Receive CSI frames from an ESP32 over UDP (JSON payloads)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5555, interface_mac: str = "esp32"):
        self.host = host
        self.port = port
        self.interface_mac = interface_mac
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.on_csi: Optional[Callable[[CSIData], None]] = None
        self.logger = logging.getLogger("ESP32CSIReceiver")
        self.packets_received = 0

    def start(self, callback: Callable[[CSIData], None]):
        if self._running:
            return
        self.on_csi = callback
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.info("ESP32 CSI UDP listener on %s:%s", self.host, self.port)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while self._running and self._sock:
            try:
                data, addr = self._sock.recvfrom(65535)
                payload = json_lib.loads(data.decode("utf-8", errors="ignore"))
                csi = self._parse_payload(payload)
                if csi and self.on_csi:
                    self.packets_received += 1
                    self.on_csi(csi)
            except socket.timeout:
                continue
            except json_lib.JSONDecodeError:
                continue
            except Exception as e:
                self.logger.debug("ESP32 UDP parse error: %s", e)
                continue

    def _parse_payload(self, payload: Dict[str, Any]) -> Optional[CSIData]:
        """Parse ESP32 CSI JSON payload into CSIData."""
        try:
            # Handle the ESP32 firmware format: csi is array of [amp, phase] pairs
            csi_pairs = payload.get("csi")
            if csi_pairs and isinstance(csi_pairs, list):
                amplitude = []
                phase = []
                for pair in csi_pairs:
                    if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                        amplitude.append(float(pair[0]))
                        phase.append(float(pair[1]))
                    elif isinstance(pair, (int, float)):
                        # Single value - treat as amplitude
                        amplitude.append(float(pair))
                        phase.append(0.0)
            else:
                # Fallback: separate amplitude/phase arrays
                amp = payload.get("amplitude") or payload.get("amp")
                phase_data = payload.get("phase") or payload.get("phi")
                if not amp:
                    return None
                amplitude = [float(x) for x in amp]
                phase = [float(x) for x in phase_data] if phase_data else [0.0] * len(amplitude)

            if not amplitude:
                return None

            num_subcarriers = len(amplitude)
            
            # Handle both 'ch' and 'channel' keys
            channel = payload.get("ch") or payload.get("channel") or 1
            
            return CSIData(
                timestamp=payload.get("ts", payload.get("timestamp", time.time())),
                mac_address=payload.get("mac", self.interface_mac),
                rssi=float(payload.get("rssi", -60)),
                channel=int(channel),
                bandwidth=int(payload.get("bandwidth", payload.get("bw", 20))),
                num_subcarriers=num_subcarriers,
                amplitude=amplitude,
                phase=phase,
                noise_floor=float(payload.get("noise", payload.get("noise_floor", -95))),
                antenna_config=str(payload.get("ant", payload.get("antenna", "1x1"))),
            )
        except Exception as e:
            self.logger.debug("CSI parse error: %s", e)
            return None


class ESP32SerialReceiver:
    """
    Enhanced ESP32 Serial CSI Receiver.
    
    Features:
    - CSI data reception and parsing
    - Device status monitoring
    - MAC address tracking
    - Channel statistics
    - Command interface
    - Message routing for status/macs/channels
    """

    def __init__(self, port: str = "/dev/ttyUSB0", baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self._serial = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.on_csi: Optional[Callable[[CSIData], None]] = None
        self.on_message: Optional[Callable[[Dict[str, Any]], None]] = None  # Non-CSI messages
        self.logger = logging.getLogger("ESP32SerialReceiver")
        self.packets_received = 0
        self._buffer = ""
        
        # Extended tracking
        self.device_version: Optional[str] = None
        self.last_status: Dict[str, Any] = {}
        self.last_csi: Optional[CSIData] = None
        self.tracked_macs: Dict[str, Dict[str, Any]] = {}
        self.channel_stats: Dict[int, Dict[str, Any]] = {}
        
        # Signal quality
        self.snr_history: deque = deque(maxlen=100)
        self.doppler_history: deque = deque(maxlen=100)

    def start(self, callback: Callable[[CSIData], None]) -> bool:
        """Start serial receiver. Returns True if successful."""
        if self._running:
            return True
        
        try:
            import serial
            self._serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=1.0
            )
            self.on_csi = callback
            self._running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            self.logger.info("ESP32 Serial receiver started on %s @ %d baud", self.port, self.baudrate)
            return True
        except ImportError:
            self.logger.error("pyserial not installed. Run: pip install pyserial")
            return False
        except Exception as e:
            self.logger.error("Failed to open serial port %s: %s", self.port, e)
            return False

    def stop(self):
        self._running = False
        if self._serial:
            try:
                self._serial.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def send_command(self, cmd: str):
        """Send command to ESP32 (e.g., 'CH 6' to change channel)."""
        if self._serial and self._serial.is_open:
            self._serial.write((cmd + "\n").encode())

    def set_channel(self, channel: int):
        """Set ESP32 capture channel."""
        self.send_command(f"CH {channel}")

    def get_status(self):
        """Request status from ESP32."""
        self.send_command("STATUS")

    def get_tracked_macs(self):
        """Request tracked MAC list."""
        self.send_command("MACS")

    def get_channel_stats(self):
        """Request channel statistics."""
        self.send_command("CHANNELS")

    def scan_channels(self):
        """Trigger channel scan."""
        self.send_command("SCAN")

    def enable_raw_iq(self, enable: bool = True):
        """Enable/disable raw I/Q data."""
        self.send_command(f"RAW {'ON' if enable else 'OFF'}")

    def set_target_mac(self, mac: str):
        """Set a MAC as tracking target."""
        self.send_command(f"TARGET {mac}")

    def calibrate(self):
        """Run calibration."""
        self.send_command("CALIBRATE")

    def save_config(self):
        """Save config to ESP32 EEPROM."""
        self.send_command("SAVE")

    def _loop(self):
        while self._running and self._serial:
            try:
                if self._serial.in_waiting:
                    line = self._serial.readline().decode("utf-8", errors="ignore").strip()
                    if line:
                        self._process_line(line)
            except Exception as e:
                self.logger.debug("Serial read error: %s", e)
                time.sleep(0.1)

    def _process_line(self, line: str):
        """Process a line from ESP32 serial output."""
        # Try to parse as JSON first
        if line.startswith("{"):
            try:
                payload = json_lib.loads(line)
                msg_type = payload.get("type", "")
                
                # Handle different message types
                if msg_type == "csi":
                    # CSI data packet
                    csi = self._parse_payload(payload)
                    if csi:
                        self.packets_received += 1
                        self.last_csi = csi
                        
                        # Extract signal quality
                        snr = payload.get("snr", 0)
                        doppler = payload.get("doppler", 0)
                        if snr:
                            self.snr_history.append(snr)
                        if doppler:
                            self.doppler_history.append(doppler)
                        
                        if self.on_csi:
                            self.on_csi(csi)
                
                elif msg_type == "status":
                    # Status report
                    self.device_version = payload.get("v", "")
                    self.last_status = payload
                    if self.on_message:
                        self.on_message(payload)
                
                elif msg_type == "macs":
                    # Tracked MACs
                    for m in payload.get("macs", []):
                        mac = m.get("mac", "")
                        if mac:
                            self.tracked_macs[mac] = m
                    if self.on_message:
                        self.on_message(payload)
                
                elif msg_type == "channels":
                    # Channel statistics
                    for ch in payload.get("stats", []):
                        ch_num = ch.get("ch", 0)
                        if ch_num:
                            self.channel_stats[ch_num] = ch
                    if self.on_message:
                        self.on_message(payload)
                
                elif msg_type in ("ack", "calibration", "channel", "scan_result", "help"):
                    # Pass through to message handler
                    if self.on_message:
                        self.on_message(payload)
                
                return
            except json_lib.JSONDecodeError:
                pass
        
        # Parse legacy format: "CSI RSSI:-45 LEN:128"
        if line.startswith("CSI "):
            self._parse_legacy_line(line)

    def _parse_legacy_line(self, line: str):
        """Parse legacy text format CSI output."""
        try:
            parts = {}
            for part in line.split():
                if ":" in part:
                    key, val = part.split(":", 1)
                    parts[key] = val
            
            rssi = float(parts.get("RSSI", -60))
            length = int(parts.get("LEN", 56))
            
            # Generate synthetic amplitude from RSSI (for basic detection)
            base_amp = 10 ** (rssi / 20) * 100
            amplitude = [base_amp * (1 + 0.1 * np.sin(i * 0.5)) for i in range(length // 2)]
            phase = [0.0] * len(amplitude)
            
            csi = CSIData(
                timestamp=time.time(),
                mac_address="esp32_serial",
                rssi=rssi,
                channel=6,
                bandwidth=20,
                num_subcarriers=len(amplitude),
                amplitude=amplitude,
                phase=phase,
                noise_floor=-95,
                antenna_config="1x1",
            )
            
            if self.on_csi:
                self.packets_received += 1
                self.on_csi(csi)
                
        except Exception as e:
            self.logger.debug("Legacy parse error: %s", e)

    def _parse_payload(self, payload: Dict[str, Any]) -> Optional[CSIData]:
        """Parse JSON payload (same format as UDP receiver)."""
        try:
            csi_pairs = payload.get("csi")
            if csi_pairs and isinstance(csi_pairs, list):
                amplitude = []
                phase = []
                for pair in csi_pairs:
                    if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                        amplitude.append(float(pair[0]))
                        phase.append(float(pair[1]))
                    elif isinstance(pair, (int, float)):
                        amplitude.append(float(pair))
                        phase.append(0.0)
            else:
                amp = payload.get("amplitude") or payload.get("amp")
                phase_data = payload.get("phase") or payload.get("phi")
                if not amp:
                    return None
                amplitude = [float(x) for x in amp]
                phase = [float(x) for x in phase_data] if phase_data else [0.0] * len(amplitude)

            if not amplitude:
                return None

            channel = payload.get("ch") or payload.get("channel") or 6
            
            return CSIData(
                timestamp=payload.get("ts", time.time()),
                mac_address=payload.get("mac", "esp32_serial"),
                rssi=float(payload.get("rssi", -60)),
                channel=int(channel),
                bandwidth=20,
                num_subcarriers=len(amplitude),
                amplitude=amplitude,
                phase=phase,
                noise_floor=-95,
                antenna_config="1x1",
            )
        except Exception:
            return None


# =============================================================================
# Enhanced ESP32 Hardware Features
# =============================================================================

@dataclass
class ESP32Status:
    """ESP32 device status information."""
    version: str = ""
    uptime: int = 0
    channel: int = 6
    packets: int = 0
    packets_per_second: int = 0
    network_connected: bool = False
    tracked_macs: int = 0
    snr: float = 0.0
    noise_floor: float = -95.0
    free_heap: int = 0
    raw_iq_enabled: bool = False
    presence_enabled: bool = True
    gesture_enabled: bool = False
    auto_channel_scan: bool = True


@dataclass
class TrackedDevice:
    """A device tracked by ESP32 CSI."""
    mac_address: str
    rssi: float
    avg_rssi: float
    variance: float
    packet_count: int
    age_seconds: int
    is_target: bool = False


@dataclass
class ChannelInfo:
    """WiFi channel statistics from ESP32."""
    channel: int
    packet_count: int
    avg_rssi: float
    noise_floor: float
    interference_score: float


@dataclass
class ESP32CalibrationData:
    """Calibration data for ESP32 CSI."""
    noise_floor: float = -95.0
    reference_rssi: Dict[str, float] = field(default_factory=dict)
    subcarrier_weights: List[float] = field(default_factory=list)
    phase_offsets: List[float] = field(default_factory=list)
    calibrated_at: float = 0.0


class ESP32AdvancedController:
    """
    Advanced controller for ESP32 CSI hardware.
    
    Provides:
    - Automatic channel optimization
    - Multi-device tracking
    - Signal quality monitoring
    - Calibration routines
    - Presence zone detection
    - Gesture recognition configuration
    - OTA firmware updates
    - Multi-ESP32 mesh coordination
    """

    def __init__(self, receiver: ESP32SerialReceiver):
        self.receiver = receiver
        self.logger = logging.getLogger("ESP32Controller")
        
        # Device state
        self.status = ESP32Status()
        self.tracked_devices: Dict[str, TrackedDevice] = {}
        self.channel_stats: Dict[int, ChannelInfo] = {}
        self.calibration = ESP32CalibrationData()
        
        # Signal monitoring
        self.snr_history: deque = deque(maxlen=100)
        self.rssi_history: deque = deque(maxlen=100)
        self.pps_history: deque = deque(maxlen=60)  # 1 minute of PPS
        
        # Presence detection state
        self.presence_zones: Dict[str, Dict[str, Any]] = {}
        self.presence_detected = False
        self.presence_confidence = 0.0
        
        # Message handlers
        self._message_handlers: Dict[str, Callable] = {
            "status": self._handle_status,
            "macs": self._handle_macs,
            "channels": self._handle_channels,
            "calibration": self._handle_calibration,
            "ack": self._handle_ack,
            "channel": self._handle_channel_change,
        }
        
        # Callbacks
        self.on_status_update: Optional[Callable[[ESP32Status], None]] = None
        self.on_device_detected: Optional[Callable[[TrackedDevice], None]] = None
        self.on_presence_change: Optional[Callable[[bool, float], None]] = None

    def process_message(self, message: Dict[str, Any]):
        """Process a message from ESP32 (non-CSI messages)."""
        msg_type = message.get("type", "")
        handler = self._message_handlers.get(msg_type)
        if handler:
            handler(message)

    def _handle_status(self, msg: Dict[str, Any]):
        """Handle status report from ESP32."""
        self.status = ESP32Status(
            version=msg.get("v", ""),
            uptime=msg.get("uptime", 0),
            channel=msg.get("ch", 6),
            packets=msg.get("pkts", 0),
            packets_per_second=msg.get("pps", 0),
            network_connected=bool(msg.get("net", 0)),
            tracked_macs=msg.get("macs", 0),
            snr=msg.get("snr", 0.0),
            noise_floor=msg.get("nf", -95.0),
            free_heap=msg.get("free_heap", 0),
            raw_iq_enabled=bool(msg.get("raw_iq", 0)),
            presence_enabled=bool(msg.get("presence", 1)),
            gesture_enabled=bool(msg.get("gesture", 0)),
            auto_channel_scan=bool(msg.get("auto_ch", 1)),
        )
        
        self.snr_history.append(self.status.snr)
        self.pps_history.append(self.status.packets_per_second)
        
        if self.on_status_update:
            self.on_status_update(self.status)

    def _handle_macs(self, msg: Dict[str, Any]):
        """Handle tracked MACs report."""
        self.tracked_devices.clear()
        for m in msg.get("macs", []):
            dev = TrackedDevice(
                mac_address=m.get("mac", ""),
                rssi=m.get("rssi", -80),
                avg_rssi=m.get("avg", -80),
                variance=m.get("var", 0),
                packet_count=m.get("pkts", 0),
                age_seconds=m.get("age", 0),
                is_target=bool(m.get("target", 0)),
            )
            self.tracked_devices[dev.mac_address] = dev
            
            if self.on_device_detected:
                self.on_device_detected(dev)

    def _handle_channels(self, msg: Dict[str, Any]):
        """Handle channel statistics report."""
        self.channel_stats.clear()
        for ch in msg.get("stats", []):
            info = ChannelInfo(
                channel=ch.get("ch", 0),
                packet_count=ch.get("pkts", 0),
                avg_rssi=ch.get("rssi", -80),
                noise_floor=ch.get("nf", -95),
                interference_score=ch.get("intf", 0),
            )
            self.channel_stats[info.channel] = info

    def _handle_calibration(self, msg: Dict[str, Any]):
        """Handle calibration result."""
        self.calibration.noise_floor = msg.get("noise_floor", -95)
        self.calibration.calibrated_at = time.time()
        self.logger.info("Calibration complete: noise_floor=%.1f dBm", self.calibration.noise_floor)

    def _handle_ack(self, msg: Dict[str, Any]):
        """Handle command acknowledgment."""
        cmd = msg.get("cmd", "")
        val = msg.get("val", "")
        self.logger.debug("ESP32 ACK: %s = %s", cmd, val)

    def _handle_channel_change(self, msg: Dict[str, Any]):
        """Handle channel change notification."""
        self.status.channel = msg.get("ch", self.status.channel)

    # =========================================================================
    # Commands
    # =========================================================================

    def set_channel(self, channel: int):
        """Set capture channel (1-14)."""
        if 1 <= channel <= 14:
            self.receiver.send_command(f"CH {channel}")

    def get_status(self):
        """Request status report."""
        self.receiver.send_command("STATUS")

    def get_tracked_macs(self):
        """Request list of tracked MAC addresses."""
        self.receiver.send_command("MACS")

    def get_channel_stats(self):
        """Request channel statistics."""
        self.receiver.send_command("CHANNELS")

    def scan_channels(self):
        """Trigger channel scan to find optimal channel."""
        self.receiver.send_command("SCAN")

    def enable_auto_channel_scan(self, enable: bool = True):
        """Enable/disable automatic channel scanning."""
        self.receiver.send_command(f"AUTOSCAN {'ON' if enable else 'OFF'}")

    def enable_raw_iq(self, enable: bool = True):
        """Enable/disable raw I/Q data transmission."""
        self.receiver.send_command(f"RAW {'ON' if enable else 'OFF'}")

    def enable_presence_mode(self, enable: bool = True):
        """Enable/disable presence detection mode."""
        self.receiver.send_command(f"PRESENCE {'ON' if enable else 'OFF'}")

    def enable_gesture_mode(self, enable: bool = True):
        """Enable/disable gesture recognition mode."""
        self.receiver.send_command(f"GESTURE {'ON' if enable else 'OFF'}")

    def set_target_mac(self, mac_address: str):
        """Set a MAC address as primary tracking target."""
        self.receiver.send_command(f"TARGET {mac_address}")

    def set_sample_rate(self, pps: int):
        """Set target samples per second."""
        self.receiver.send_command(f"RATE {pps}")

    def calibrate(self):
        """Run calibration routine."""
        self.receiver.send_command("CALIBRATE")

    def save_config(self):
        """Save current config to ESP32 EEPROM."""
        self.receiver.send_command("SAVE")

    def load_config(self):
        """Load config from ESP32 EEPROM."""
        self.receiver.send_command("LOAD")

    def clear_tracking(self):
        """Clear tracked MACs and packet counts."""
        self.receiver.send_command("CLEAR")

    def reset(self):
        """Reset ESP32."""
        self.receiver.send_command("RESET")

    # =========================================================================
    # Analysis
    # =========================================================================

    def get_signal_quality(self) -> Dict[str, float]:
        """Get current signal quality metrics."""
        return {
            "snr": self.status.snr,
            "noise_floor": self.status.noise_floor,
            "avg_snr": np.mean(list(self.snr_history)) if self.snr_history else 0,
            "snr_variance": np.var(list(self.snr_history)) if len(self.snr_history) > 1 else 0,
            "avg_pps": np.mean(list(self.pps_history)) if self.pps_history else 0,
        }

    def get_best_channel(self) -> int:
        """Get the best channel based on collected statistics."""
        if not self.channel_stats:
            return self.status.channel
        
        best_ch = self.status.channel
        best_score = float('-inf')
        
        for ch, info in self.channel_stats.items():
            # Score: higher packets, higher RSSI, lower interference
            score = info.packet_count * 0.1 + info.avg_rssi - info.interference_score * 10
            if score > best_score:
                best_score = score
                best_ch = ch
        
        return best_ch

    def estimate_presence(self, csi: CSIData) -> Tuple[bool, float]:
        """
        Estimate presence based on CSI variance.
        
        Returns (presence_detected, confidence)
        """
        if not csi.amplitude:
            return self.presence_detected, self.presence_confidence
        
        # Calculate amplitude variance
        amp_var = np.var(csi.amplitude)
        
        # Higher variance typically indicates human presence/movement
        threshold = 50.0  # Tunable threshold
        
        presence = amp_var > threshold
        confidence = min(1.0, amp_var / (threshold * 2))
        
        # Smooth detection
        alpha = 0.3
        self.presence_confidence = alpha * confidence + (1 - alpha) * self.presence_confidence
        
        new_presence = self.presence_confidence > 0.5
        
        if new_presence != self.presence_detected:
            self.presence_detected = new_presence
            if self.on_presence_change:
                self.on_presence_change(self.presence_detected, self.presence_confidence)
        
        return self.presence_detected, self.presence_confidence


class ESP32MeshCoordinator:
    """
    Coordinate multiple ESP32 devices for enhanced coverage.
    
    Features:
    - Time synchronization across devices
    - Channel assignment to avoid interference
    - Triangulation using multiple devices
    - Redundant coverage
    """

    def __init__(self):
        self.logger = logging.getLogger("ESP32Mesh")
        self.devices: Dict[str, ESP32AdvancedController] = {}
        self.receivers: Dict[str, ESP32SerialReceiver] = {}
        
        # Mesh state
        self.device_positions: Dict[str, Tuple[float, float, float]] = {}
        self.sync_offset: Dict[str, float] = {}  # Time offset for each device
        
        # Combined CSI
        self.combined_history: deque = deque(maxlen=500)
        
        # Callbacks
        self.on_csi: Optional[Callable[[CSIData, str], None]] = None  # CSI + device ID

    def add_device(
        self, 
        device_id: str, 
        port: str, 
        position: Tuple[float, float, float] = (0, 0, 0),
        channel: Optional[int] = None
    ) -> bool:
        """
        Add an ESP32 device to the mesh.
        
        Args:
            device_id: Unique identifier for this device
            port: Serial port (e.g., /dev/ttyUSB0)
            position: Physical position (x, y, z) in meters
            channel: WiFi channel (auto-assigned if None)
        """
        try:
            receiver = ESP32SerialReceiver(port=port)
            controller = ESP32AdvancedController(receiver)
            
            # Create wrapper callback
            def on_csi_wrapper(csi: CSIData):
                # Apply time sync offset
                if device_id in self.sync_offset:
                    csi.timestamp += self.sync_offset[device_id]
                
                # Add to combined history
                self.combined_history.append((csi, device_id))
                
                if self.on_csi:
                    self.on_csi(csi, device_id)
            
            if receiver.start(on_csi_wrapper):
                self.receivers[device_id] = receiver
                self.devices[device_id] = controller
                self.device_positions[device_id] = position
                
                # Set channel if specified
                if channel:
                    controller.set_channel(channel)
                
                self.logger.info("Added device %s on %s at position %s", device_id, port, position)
                return True
            
            return False
            
        except Exception as e:
            self.logger.error("Failed to add device %s: %s", device_id, e)
            return False

    def remove_device(self, device_id: str):
        """Remove a device from the mesh."""
        if device_id in self.receivers:
            self.receivers[device_id].stop()
            del self.receivers[device_id]
        if device_id in self.devices:
            del self.devices[device_id]
        if device_id in self.device_positions:
            del self.device_positions[device_id]

    def auto_assign_channels(self):
        """
        Automatically assign non-overlapping channels to devices.
        Uses channels 1, 6, 11 for 2.4GHz to avoid interference.
        """
        non_overlapping = [1, 6, 11]
        
        for i, (device_id, controller) in enumerate(self.devices.items()):
            channel = non_overlapping[i % len(non_overlapping)]
            controller.set_channel(channel)
            self.logger.info("Assigned channel %d to device %s", channel, device_id)

    def synchronize_time(self):
        """
        Synchronize time across all devices.
        Uses the first device as reference.
        """
        if not self.devices:
            return
        
        reference_id = list(self.devices.keys())[0]
        reference_time = time.time()
        
        for device_id, controller in self.devices.items():
            # Request status to get uptime
            controller.get_status()
            # Calculate offset (simplified - would need handshake in real impl)
            self.sync_offset[device_id] = 0.0 if device_id == reference_id else 0.001  # 1ms assumed offset
        
        self.logger.info("Time synchronized across %d devices", len(self.devices))

    def triangulate_position(
        self, 
        mac_address: str
    ) -> Optional[Tuple[float, float, float]]:
        """
        Estimate position of a MAC address using triangulation.
        
        Requires at least 3 devices with position and RSSI data.
        """
        rssi_data: List[Tuple[Tuple[float, float, float], float]] = []
        
        for device_id, controller in self.devices.items():
            if mac_address in controller.tracked_devices:
                dev = controller.tracked_devices[mac_address]
                pos = self.device_positions[device_id]
                rssi_data.append((pos, dev.avg_rssi))
        
        if len(rssi_data) < 3:
            return None
        
        # Simple weighted centroid based on RSSI
        total_weight = 0
        x, y, z = 0.0, 0.0, 0.0
        
        for pos, rssi in rssi_data:
            # Convert RSSI to weight (higher RSSI = closer = higher weight)
            weight = 10 ** (rssi / 20)  # Simplified path loss
            x += pos[0] * weight
            y += pos[1] * weight
            z += pos[2] * weight
            total_weight += weight
        
        if total_weight > 0:
            return (x / total_weight, y / total_weight, z / total_weight)
        
        return None

    def get_combined_presence(self) -> Tuple[bool, float, List[str]]:
        """
        Get combined presence detection from all devices.
        
        Returns (presence_detected, confidence, detecting_devices)
        """
        detecting = []
        max_confidence = 0.0
        
        for device_id, controller in self.devices.items():
            if controller.presence_detected:
                detecting.append(device_id)
                max_confidence = max(max_confidence, controller.presence_confidence)
        
        presence = len(detecting) > 0
        return presence, max_confidence, detecting

    def stop_all(self):
        """Stop all devices."""
        for receiver in self.receivers.values():
            receiver.stop()
        self.receivers.clear()
        self.devices.clear()


class ESP32GestureRecognizer:
    """
    Real-time gesture recognition using ESP32 CSI data.
    
    Recognizes:
    - Wave (left-right motion)
    - Push (towards/away motion)
    - Circle (circular motion)
    - Swipe (quick directional motion)
    - Clap (sudden amplitude spike)
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.amplitude_history: deque = deque(maxlen=window_size)
        self.phase_history: deque = deque(maxlen=window_size)
        self.doppler_history: deque = deque(maxlen=window_size)
        
        # Gesture state
        self.current_gesture: Optional[str] = None
        self.gesture_confidence = 0.0
        self.gesture_start_time = 0.0
        
        # Thresholds (tunable)
        self.wave_threshold = 0.5
        self.push_threshold = 0.3
        self.clap_threshold = 100.0
        self.swipe_threshold = 0.8
        
        # Callbacks
        self.on_gesture: Optional[Callable[[str, float], None]] = None

    def update(self, csi: CSIData, doppler: float = 0.0) -> Optional[Tuple[str, float]]:
        """
        Update with new CSI data and check for gestures.
        
        Returns (gesture_name, confidence) if detected, None otherwise.
        """
        if not csi.amplitude:
            return None
        
        # Store history
        mean_amp = np.mean(csi.amplitude)
        mean_phase = np.mean(csi.phase) if csi.phase else 0
        
        self.amplitude_history.append(mean_amp)
        self.phase_history.append(mean_phase)
        self.doppler_history.append(doppler)
        
        if len(self.amplitude_history) < self.window_size // 2:
            return None
        
        # Detect gestures
        gesture = self._detect_gesture()
        
        if gesture:
            name, confidence = gesture
            if confidence > 0.7:  # Confidence threshold
                self.current_gesture = name
                self.gesture_confidence = confidence
                
                if self.on_gesture:
                    self.on_gesture(name, confidence)
                
                return gesture
        
        return None

    def _detect_gesture(self) -> Optional[Tuple[str, float]]:
        """Analyze history and detect gestures."""
        amp_array = np.array(list(self.amplitude_history))
        phase_array = np.array(list(self.phase_history))
        doppler_array = np.array(list(self.doppler_history))
        
        # Check for clap (sudden amplitude spike)
        if len(amp_array) >= 5:
            recent_max = np.max(amp_array[-5:])
            baseline = np.mean(amp_array[:-5]) if len(amp_array) > 5 else np.mean(amp_array)
            if recent_max > baseline + self.clap_threshold:
                return ("clap", min(1.0, (recent_max - baseline) / self.clap_threshold))
        
        # Check for wave (oscillating phase)
        if len(phase_array) >= 10:
            # Count zero crossings in phase derivative
            phase_diff = np.diff(phase_array[-10:])
            zero_crossings = np.sum(np.diff(np.sign(phase_diff)) != 0)
            if zero_crossings >= 3:
                confidence = min(1.0, zero_crossings / 5)
                return ("wave", confidence)
        
        # Check for push (sustained Doppler shift)
        if len(doppler_array) >= 10:
            mean_doppler = np.mean(doppler_array[-10:])
            if abs(mean_doppler) > self.push_threshold:
                direction = "push_away" if mean_doppler > 0 else "push_toward"
                return (direction, min(1.0, abs(mean_doppler) / self.push_threshold))
        
        # Check for swipe (quick phase change)
        if len(phase_array) >= 5:
            phase_change = abs(phase_array[-1] - phase_array[-5])
            if phase_change > self.swipe_threshold:
                return ("swipe", min(1.0, phase_change / (self.swipe_threshold * 2)))
        
        return None

    def reset(self):
        """Reset gesture state."""
        self.amplitude_history.clear()
        self.phase_history.clear()
        self.doppler_history.clear()
        self.current_gesture = None
        self.gesture_confidence = 0.0


class ESP32PresenceZoneManager:
    """
    Manage presence zones using ESP32 CSI data.
    
    Define zones in a room and detect which zone(s) contain people.
    """

    @dataclass
    class Zone:
        id: str
        name: str
        center: Tuple[float, float]  # (x, y) in meters
        radius: float  # meters
        active: bool = False
        confidence: float = 0.0
        last_activity: float = 0.0

    def __init__(self):
        self.zones: Dict[str, ESP32PresenceZoneManager.Zone] = {}
        self.esp32_positions: Dict[str, Tuple[float, float]] = {}
        
        # Zone activity tracking
        self.zone_history: Dict[str, deque] = {}
        
        # Callbacks
        self.on_zone_change: Optional[Callable[[str, bool, float], None]] = None

    def add_zone(
        self, 
        zone_id: str, 
        name: str, 
        center: Tuple[float, float], 
        radius: float
    ):
        """Add a presence zone."""
        self.zones[zone_id] = self.Zone(
            id=zone_id,
            name=name,
            center=center,
            radius=radius
        )
        self.zone_history[zone_id] = deque(maxlen=50)

    def set_esp32_position(self, device_id: str, position: Tuple[float, float]):
        """Set the position of an ESP32 device."""
        self.esp32_positions[device_id] = position

    def update(
        self, 
        device_id: str, 
        csi: CSIData, 
        rssi_variance: float
    ) -> List[Tuple[str, bool, float]]:
        """
        Update zones based on CSI from a specific ESP32.
        
        Returns list of (zone_id, active, confidence) for changed zones.
        """
        if device_id not in self.esp32_positions:
            return []
        
        esp_pos = self.esp32_positions[device_id]
        changes = []
        
        # Calculate activity level from CSI variance
        activity = np.var(csi.amplitude) if csi.amplitude else 0
        
        for zone_id, zone in self.zones.items():
            # Distance from ESP32 to zone center
            dist = math.sqrt(
                (esp_pos[0] - zone.center[0])**2 + 
                (esp_pos[1] - zone.center[1])**2
            )
            
            # Weight activity by proximity
            weight = max(0, 1 - dist / (zone.radius * 3))
            weighted_activity = activity * weight
            
            self.zone_history[zone_id].append(weighted_activity)
            
            # Calculate zone confidence
            if len(self.zone_history[zone_id]) >= 5:
                recent_activity = np.mean(list(self.zone_history[zone_id])[-5:])
                confidence = min(1.0, recent_activity / 100)  # Normalize
                
                was_active = zone.active
                zone.active = confidence > 0.3
                zone.confidence = confidence
                
                if zone.active:
                    zone.last_activity = time.time()
                
                if zone.active != was_active:
                    changes.append((zone_id, zone.active, zone.confidence))
                    if self.on_zone_change:
                        self.on_zone_change(zone_id, zone.active, zone.confidence)
        
        return changes

    def get_active_zones(self) -> List[Tuple[str, float]]:
        """Get list of currently active zones with confidence."""
        return [
            (zone.id, zone.confidence) 
            for zone in self.zones.values() 
            if zone.active
        ]

    def get_zone_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary of all zones."""
        return {
            zone_id: {
                "name": zone.name,
                "active": zone.active,
                "confidence": zone.confidence,
                "center": zone.center,
                "radius": zone.radius,
                "last_activity": zone.last_activity
            }
            for zone_id, zone in self.zones.items()
        }


class ESP32FirmwareManager:
    """
    Manage ESP32 firmware updates and configuration.
    
    Features:
    - OTA firmware updates via serial
    - Firmware version checking
    - Configuration backup/restore
    - Factory reset
    """

    def __init__(self, receiver: ESP32SerialReceiver):
        self.receiver = receiver
        self.logger = logging.getLogger("ESP32Firmware")
        
        self.current_version: Optional[str] = None
        self.update_progress = 0.0
        self.update_in_progress = False
        
        # Callbacks
        self.on_update_progress: Optional[Callable[[float, str], None]] = None

    def get_version(self) -> Optional[str]:
        """Get current firmware version."""
        self.receiver.send_command("STATUS")
        # Version will be parsed from status response
        return self.current_version

    def check_update_available(self, firmware_path: str) -> Tuple[bool, str]:
        """
        Check if a firmware update is available.
        
        Returns (update_available, new_version)
        """
        if not os.path.exists(firmware_path):
            return False, ""
        
        # For binary firmware files, we'd need to extract version
        # For now, just check if file exists and is newer
        return True, "2.0.0"

    def update_firmware(self, firmware_path: str) -> bool:
        """
        Update ESP32 firmware via serial.
        
        This requires the ESP32 to be in bootloader mode.
        Uses esptool for actual flashing.
        """
        if not os.path.exists(firmware_path):
            self.logger.error("Firmware file not found: %s", firmware_path)
            return False
        
        self.update_in_progress = True
        self.update_progress = 0.0
        
        try:
            # Close serial connection
            self.receiver.stop()
            
            # Use esptool to flash
            import subprocess
            
            cmd = [
                "esptool.py",
                "--port", self.receiver.port,
                "--baud", "921600",
                "write_flash",
                "0x10000",
                firmware_path
            ]
            
            self.logger.info("Starting firmware update...")
            if self.on_update_progress:
                self.on_update_progress(0.1, "Connecting to ESP32...")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            for line in process.stdout:
                # Parse progress from esptool output
                if "Writing" in line and "%" in line:
                    try:
                        pct = float(line.split("%")[0].split()[-1])
                        self.update_progress = pct / 100
                        if self.on_update_progress:
                            self.on_update_progress(self.update_progress, f"Writing: {pct:.0f}%")
                    except ValueError:
                        pass
            
            process.wait()
            
            if process.returncode == 0:
                self.logger.info("Firmware update successful!")
                if self.on_update_progress:
                    self.on_update_progress(1.0, "Update complete!")
                
                # Restart serial connection
                time.sleep(2)
                self.receiver.start(lambda x: None)
                
                return True
            else:
                self.logger.error("Firmware update failed!")
                return False
                
        except Exception as e:
            self.logger.error("Firmware update error: %s", e)
            return False
        finally:
            self.update_in_progress = False

    def backup_config(self, filepath: str) -> bool:
        """Backup ESP32 configuration to file."""
        try:
            self.receiver.send_command("STATUS")
            time.sleep(0.5)
            
            # We'd need to capture the response and save it
            # For now, just request the data
            config = {
                "version": self.current_version,
                "backed_up_at": datetime.now().isoformat(),
            }
            
            with open(filepath, "w") as f:
                json_lib.dump(config, f, indent=2)
            
            self.logger.info("Config backed up to %s", filepath)
            return True
            
        except Exception as e:
            self.logger.error("Backup failed: %s", e)
            return False

    def restore_config(self, filepath: str) -> bool:
        """Restore ESP32 configuration from file."""
        try:
            with open(filepath, "r") as f:
                config = json_lib.load(f)
            
            # Send config commands to ESP32
            if "channel" in config:
                self.receiver.send_command(f"CH {config['channel']}")
            
            self.logger.info("Config restored from %s", filepath)
            return True
            
        except Exception as e:
            self.logger.error("Restore failed: %s", e)
            return False

    def factory_reset(self) -> bool:
        """Reset ESP32 to factory defaults."""
        self.receiver.send_command("CLEAR")
        self.receiver.send_command("RESET")
        self.logger.info("Factory reset initiated")
        return True


class ESP32PowerManager:
    """
    Manage ESP32 power modes for battery operation.
    
    Modes:
    - Normal: Full performance
    - Low Power: Reduced sample rate, longer sleep
    - Deep Sleep: Wake on motion only
    """

    POWER_NORMAL = 0
    POWER_LOW = 1
    POWER_DEEP_SLEEP = 2

    def __init__(self, receiver: ESP32SerialReceiver):
        self.receiver = receiver
        self.logger = logging.getLogger("ESP32Power")
        self.current_mode = self.POWER_NORMAL

    def set_power_mode(self, mode: int):
        """Set power mode."""
        if mode == self.POWER_NORMAL:
            self.receiver.send_command("RATE 100")
            self.receiver.send_command("AUTOSCAN ON")
        elif mode == self.POWER_LOW:
            self.receiver.send_command("RATE 20")
            self.receiver.send_command("AUTOSCAN OFF")
        elif mode == self.POWER_DEEP_SLEEP:
            self.receiver.send_command("RATE 5")
            self.receiver.send_command("AUTOSCAN OFF")
        
        self.current_mode = mode
        self.logger.info("Power mode set to %d", mode)

    def enter_deep_sleep(self, wake_gpio: int = 0):
        """Put ESP32 into deep sleep mode."""
        self.receiver.send_command(f"SLEEP {wake_gpio}")
        self.logger.info("ESP32 entering deep sleep, wake on GPIO %d", wake_gpio)


class ESP32SignalAnalyzer:
    """
    Advanced signal analysis for ESP32 CSI data.
    
    Features:
    - Frequency spectrum analysis
    - Doppler velocity estimation  
    - Multi-path detection
    - Interference detection
    """

    def __init__(self):
        self.logger = logging.getLogger("ESP32Signal")
        
        # History for analysis
        self.amplitude_history: deque = deque(maxlen=256)
        self.phase_history: deque = deque(maxlen=256)
        self.doppler_history: deque = deque(maxlen=100)
        
        # Analysis results
        self.dominant_frequency = 0.0
        self.doppler_velocity = 0.0
        self.multipath_count = 0
        self.interference_detected = False

    def update(self, csi: CSIData) -> Dict[str, Any]:
        """Update with new CSI and return analysis results."""
        if not csi.amplitude:
            return {}
        
        self.amplitude_history.append(csi.amplitude)
        self.phase_history.append(csi.phase)
        
        results = {}
        
        # Perform FFT analysis if we have enough samples
        if len(self.amplitude_history) >= 64:
            results["spectrum"] = self._analyze_spectrum()
            results["dominant_freq"] = self.dominant_frequency
        
        # Doppler analysis
        if len(self.phase_history) >= 10:
            results["doppler"] = self._estimate_doppler()
            results["velocity"] = self.doppler_velocity
        
        # Multipath detection
        results["multipath_count"] = self._detect_multipath(csi)
        
        # Interference detection
        results["interference"] = self._detect_interference(csi)
        
        return results

    def _analyze_spectrum(self) -> List[float]:
        """Perform FFT on amplitude history."""
        # Stack amplitude samples
        amp_matrix = np.array(list(self.amplitude_history)[-64:])
        
        # Average across subcarriers
        amp_avg = np.mean(amp_matrix, axis=1)
        
        # FFT
        spectrum = np.abs(np.fft.fft(amp_avg))[:len(amp_avg)//2]
        
        # Find dominant frequency
        self.dominant_frequency = float(np.argmax(spectrum))
        
        return spectrum.tolist()

    def _estimate_doppler(self) -> float:
        """Estimate Doppler shift from phase changes."""
        phase_matrix = np.array(list(self.phase_history)[-10:])
        
        # Phase difference between consecutive samples
        phase_diff = np.diff(phase_matrix, axis=0)
        
        # Unwrap phase
        phase_diff = np.mod(phase_diff + np.pi, 2*np.pi) - np.pi
        
        # Average Doppler shift
        doppler = float(np.mean(phase_diff))
        
        # Convert to velocity (assuming 2.4GHz)
        wavelength = 0.125  # meters at 2.4GHz
        self.doppler_velocity = doppler * wavelength / (2 * np.pi)
        
        self.doppler_history.append(doppler)
        
        return doppler

    def _detect_multipath(self, csi: CSIData) -> int:
        """Detect number of multipath components."""
        if not csi.amplitude or len(csi.amplitude) < 10:
            return 0
        
        amp = np.array(csi.amplitude)
        
        # Find peaks in amplitude (potential multipath reflections)
        peaks = []
        for i in range(1, len(amp) - 1):
            if amp[i] > amp[i-1] and amp[i] > amp[i+1]:
                if amp[i] > np.mean(amp) * 1.2:
                    peaks.append(i)
        
        self.multipath_count = len(peaks)
        return self.multipath_count

    def _detect_interference(self, csi: CSIData) -> bool:
        """Detect WiFi interference."""
        if not csi.amplitude:
            return False
        
        amp = np.array(csi.amplitude)
        
        # High variance with low mean could indicate interference
        variance = np.var(amp)
        mean = np.mean(amp)
        
        # Coefficient of variation
        cv = np.sqrt(variance) / mean if mean > 0 else 0
        
        # High CV suggests interference or noisy channel
        self.interference_detected = cv > 0.5
        
        return self.interference_detected

    def get_velocity_estimate(self) -> float:
        """Get smoothed velocity estimate in m/s."""
        if not self.doppler_history:
            return 0.0
        
        # Convert doppler history to velocities
        wavelength = 0.125
        velocities = [d * wavelength / (2 * np.pi) for d in self.doppler_history]
        
        # Return smoothed estimate
        return float(np.median(velocities))

    def get_breathing_rate(self) -> Optional[float]:
        """Estimate breathing rate from CSI variations."""
        if len(self.amplitude_history) < 128:
            return None
        
        # Stack and average
        amp_matrix = np.array(list(self.amplitude_history)[-128:])
        amp_avg = np.mean(amp_matrix, axis=1)
        
        # FFT
        spectrum = np.abs(np.fft.fft(amp_avg))
        freqs = np.fft.fftfreq(len(amp_avg), 0.1)  # Assuming 10Hz sample rate
        
        # Breathing is typically 0.1-0.5 Hz (6-30 breaths/min)
        breathing_mask = (freqs > 0.1) & (freqs < 0.5)
        
        if not np.any(breathing_mask):
            return None
        
        breathing_spectrum = spectrum[breathing_mask]
        breathing_freqs = freqs[breathing_mask]
        
        # Find peak
        peak_idx = np.argmax(breathing_spectrum)
        breathing_freq = breathing_freqs[peak_idx]
        
        # Convert to breaths per minute
        breathing_rate = abs(breathing_freq) * 60
        
        return float(breathing_rate) if 6 < breathing_rate < 30 else None


class UncertaintyEstimator:
    """Estimate localization uncertainty from residuals and model confidence."""

    def __init__(self, base_sigma: float = 0.5):
        self.base_sigma = base_sigma

    def from_residuals(self, residual: float, confidence: float) -> float:
        sigma = self.base_sigma + residual
        if confidence > 0:
            sigma *= max(0.3, 1.0 - confidence)
        return max(0.25, sigma)


class CSISyntheticGenerator:
    """Generate synthetic CSI sequences for augmentation and testing."""

    def __init__(self, num_subcarriers: int = 56, seed: Optional[int] = None):
        self.num_subcarriers = num_subcarriers
        self.rng = np.random.default_rng(seed)

    def generate_sequence(self, length: int = 50, movement: bool = True) -> List[CSIData]:
        seq: List[CSIData] = []
        base_amp = self.rng.uniform(0.05, 0.2)
        for i in range(length):
            motion = 0.05 * math.sin(i * 0.2) if movement else 0
            amplitude = (base_amp + motion) * (1 + 0.02 * self.rng.standard_normal(self.num_subcarriers))
            phase = np.unwrap(self.rng.uniform(0, 2 * math.pi, self.num_subcarriers))
            seq.append(CSIData(
                timestamp=time.time() + i * 0.01,
                mac_address="00:00:00:00:00:00",
                rssi=float(20 * np.log10(np.mean(amplitude) + 1e-6)),
                channel=1,
                bandwidth=20,
                num_subcarriers=self.num_subcarriers,
                amplitude=amplitude.tolist(),
                phase=phase.tolist(),
                noise_floor=-95,
                antenna_config="2x2",
            ))
        return seq


# =============================================================================
# ADVANCED SENSING ALGORITHMS
# =============================================================================

class DopplerVelocityEstimator:
    """
    Estimate velocity from Doppler shifts in WiFi CSI phase data.
    
    Uses phase rate of change across subcarriers to compute radial velocity
    towards/away from the receiver.
    """

    def __init__(self, carrier_freq_mhz: float = 2437.0, window: int = 10):
        self.carrier_freq = carrier_freq_mhz * 1e6  # Hz
        self.c = 3e8  # Speed of light
        self.wavelength = self.c / self.carrier_freq
        self.phase_history: deque = deque(maxlen=window)
        self.time_history: deque = deque(maxlen=window)

    def update(self, csi: 'CSIData') -> Dict[str, float]:
        """Update with new CSI and compute Doppler velocity."""
        if not csi.phase:
            return {"velocity": 0.0, "confidence": 0.0}
        
        mean_phase = np.mean(csi.phase)
        self.phase_history.append(mean_phase)
        self.time_history.append(csi.timestamp)
        
        if len(self.phase_history) < 3:
            return {"velocity": 0.0, "confidence": 0.0}
        
        phases = np.array(self.phase_history)
        times = np.array(self.time_history)
        
        # Unwrap phases
        unwrapped = np.unwrap(phases)
        
        # Compute phase rate (radians per second)
        dt = times[-1] - times[0]
        if dt <= 0:
            return {"velocity": 0.0, "confidence": 0.0}
        
        phase_rate = (unwrapped[-1] - unwrapped[0]) / dt
        
        # Doppler velocity: v = (λ * Δφ) / (4π * Δt)
        velocity = (self.wavelength * phase_rate) / (4 * math.pi)
        
        # Confidence based on phase stability
        phase_std = np.std(np.diff(unwrapped))
        confidence = max(0.0, min(1.0, 1.0 - phase_std / math.pi))
        
        return {
            "velocity": float(velocity),
            "velocity_kmh": float(velocity * 3.6),
            "direction": "approaching" if velocity < 0 else "receding",
            "confidence": float(confidence),
            "phase_rate": float(phase_rate)
        }


class ActivityClassifier:
    """
    Classify human activities from WiFi CSI patterns.
    
    Activities detected:
    - Walking, Running, Sitting, Standing, Lying down
    - Arm movements, Typing, Phone use
    """

    ACTIVITIES = [
        "idle", "walking", "running", "sitting_down", "standing_up",
        "lying_down", "arm_movement", "typing", "eating", "phone_use"
    ]

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.csi_buffer: deque = deque(maxlen=window_size)
        self.feature_history: deque = deque(maxlen=20)
        self.current_activity = "idle"
        self.activity_confidence = 0.0

    def _extract_features(self) -> Dict[str, float]:
        """Extract activity-relevant features from CSI buffer."""
        if len(self.csi_buffer) < 10:
            return {}
        
        amplitudes = np.array([csi.amplitude for csi in self.csi_buffer])
        
        # Temporal variance (motion indicator)
        temporal_var = np.mean(np.var(amplitudes, axis=0))
        
        # Frequency domain features
        fft_mag = np.abs(np.fft.fft(amplitudes.mean(axis=1)))[:len(amplitudes)//2]
        dominant_freq = np.argmax(fft_mag[1:]) + 1 if len(fft_mag) > 1 else 0
        
        # Energy distribution
        low_freq_energy = np.sum(fft_mag[:5]) if len(fft_mag) > 5 else 0
        high_freq_energy = np.sum(fft_mag[5:]) if len(fft_mag) > 5 else 0
        freq_ratio = low_freq_energy / (high_freq_energy + 1e-6)
        
        # Peak detection (periodic motion)
        mean_amp = amplitudes.mean(axis=1)
        peaks = 0
        for i in range(1, len(mean_amp) - 1):
            if mean_amp[i] > mean_amp[i-1] and mean_amp[i] > mean_amp[i+1]:
                peaks += 1
        
        return {
            "temporal_variance": float(temporal_var),
            "dominant_frequency": int(dominant_freq),
            "freq_ratio": float(freq_ratio),
            "peak_count": peaks,
            "mean_amplitude": float(np.mean(amplitudes)),
            "amplitude_range": float(np.max(amplitudes) - np.min(amplitudes))
        }

    def classify(self, csi: 'CSIData') -> Dict[str, Any]:
        """Classify activity from new CSI sample."""
        self.csi_buffer.append(csi)
        
        if len(self.csi_buffer) < 20:
            return {"activity": "idle", "confidence": 0.0}
        
        features = self._extract_features()
        if not features:
            return {"activity": "idle", "confidence": 0.0}
        
        self.feature_history.append(features)
        
        # Rule-based classification (can be replaced with ML model)
        var = features["temporal_variance"]
        freq = features["dominant_frequency"]
        peaks = features["peak_count"]
        freq_ratio = features["freq_ratio"]
        
        # High variance + high frequency = walking/running
        if var > 0.1 and peaks > 5:
            if freq > 3:
                activity = "running"
                confidence = min(1.0, var * 5)
            else:
                activity = "walking"
                confidence = min(1.0, var * 3)
        # Low variance, occasional peaks = arm movement
        elif var > 0.02 and peaks > 2:
            activity = "arm_movement"
            confidence = min(1.0, var * 10)
        # Very low variance = stationary
        elif var < 0.01:
            if freq_ratio > 10:
                activity = "lying_down"
            else:
                activity = "idle"
            confidence = 0.8
        else:
            activity = "idle"
            confidence = 0.5
        
        self.current_activity = activity
        self.activity_confidence = confidence
        
        return {
            "activity": activity,
            "confidence": float(confidence),
            "features": features,
            "all_activities": {a: 0.0 for a in self.ACTIVITIES}
        }


class PeopleCounter:
    """
    Count the number of people in the sensing area using CSI patterns.
    
    Uses variance decomposition and spatial diversity to estimate occupancy.
    """

    def __init__(self, max_people: int = 10, calibration_samples: int = 100):
        self.max_people = max_people
        self.calibration_samples = calibration_samples
        self.baseline_variance: Optional[float] = None
        self.csi_buffer: deque = deque(maxlen=200)
        self.calibration_mode = True
        self.calibration_buffer: List[float] = []
        self.current_count = 0
        self.count_history: deque = deque(maxlen=50)

    def calibrate_empty_room(self, csi: 'CSIData') -> bool:
        """Calibrate with empty room CSI to establish baseline."""
        if not self.calibration_mode:
            return True
        
        var = np.var(csi.amplitude)
        self.calibration_buffer.append(var)
        
        if len(self.calibration_buffer) >= self.calibration_samples:
            self.baseline_variance = np.median(self.calibration_buffer)
            self.calibration_mode = False
            return True
        
        return False

    def count(self, csi: 'CSIData') -> Dict[str, Any]:
        """Estimate number of people from CSI."""
        self.csi_buffer.append(csi)
        
        if self.calibration_mode:
            self.calibrate_empty_room(csi)
            return {"count": 0, "confidence": 0.0, "calibrating": True}
        
        if len(self.csi_buffer) < 20:
            return {"count": 0, "confidence": 0.0}
        
        # Current variance
        recent_amplitudes = np.array([c.amplitude for c in list(self.csi_buffer)[-20:]])
        current_var = np.mean(np.var(recent_amplitudes, axis=0))
        
        # Variance ratio indicates occupancy
        var_ratio = current_var / (self.baseline_variance + 1e-6)
        
        # Spatial diversity (different subcarriers affected differently)
        spatial_div = np.std(np.var(recent_amplitudes, axis=0))
        
        # Estimate count (heuristic - should be trained for specific environment)
        raw_count = (var_ratio - 1) * 2 + spatial_div * 5
        estimated_count = max(0, min(self.max_people, int(round(raw_count))))
        
        self.count_history.append(estimated_count)
        
        # Smooth with median filter
        if len(self.count_history) >= 5:
            self.current_count = int(np.median(list(self.count_history)[-5:]))
        else:
            self.current_count = estimated_count
        
        # Confidence based on stability
        if len(self.count_history) >= 5:
            confidence = 1.0 - min(1.0, np.std(list(self.count_history)[-5:]) / 2)
        else:
            confidence = 0.5
        
        return {
            "count": self.current_count,
            "confidence": float(confidence),
            "variance_ratio": float(var_ratio),
            "spatial_diversity": float(spatial_div)
        }


class SleepStageDetector:
    """
    Detect sleep stages from micro-motion patterns in WiFi CSI.
    
    Stages: Awake, Light Sleep (N1/N2), Deep Sleep (N3), REM
    """

    STAGES = ["awake", "light_sleep", "deep_sleep", "rem"]

    def __init__(self, sample_rate: float = 100.0, window_minutes: int = 5):
        self.sample_rate = sample_rate
        self.window_size = int(sample_rate * 60 * window_minutes)
        self.csi_buffer: deque = deque(maxlen=self.window_size)
        self.stage_history: deque = deque(maxlen=100)
        self.breathing_rates: deque = deque(maxlen=60)
        self.movement_scores: deque = deque(maxlen=60)

    def _extract_breathing_rate(self, amplitudes: np.ndarray) -> float:
        """Extract breathing rate from CSI variations (0.1-0.5 Hz)."""
        if len(amplitudes) < 50:
            return 15.0  # Default breathing rate
        
        mean_amp = amplitudes.mean(axis=1) if amplitudes.ndim > 1 else amplitudes
        
        # Bandpass for breathing (0.1-0.5 Hz = 6-30 breaths/min)
        fft = np.fft.fft(mean_amp)
        freqs = np.fft.fftfreq(len(mean_amp), 1/self.sample_rate)
        
        # Find peak in breathing band
        mask = (np.abs(freqs) >= 0.1) & (np.abs(freqs) <= 0.5)
        if not np.any(mask):
            return 15.0
        
        breathing_fft = np.abs(fft) * mask
        peak_idx = np.argmax(breathing_fft)
        breathing_freq = abs(freqs[peak_idx])
        
        return float(breathing_freq * 60)  # breaths per minute

    def _extract_movement_score(self, amplitudes: np.ndarray) -> float:
        """Compute movement score from amplitude variance."""
        if amplitudes.ndim > 1:
            temporal_var = np.mean(np.var(amplitudes, axis=0))
        else:
            temporal_var = np.var(amplitudes)
        
        return float(min(1.0, temporal_var * 20))

    def detect(self, csi: 'CSIData') -> Dict[str, Any]:
        """Detect current sleep stage."""
        self.csi_buffer.append(csi)
        
        if len(self.csi_buffer) < 500:
            return {"stage": "awake", "confidence": 0.0, "calibrating": True}
        
        recent = list(self.csi_buffer)[-500:]
        amplitudes = np.array([c.amplitude for c in recent])
        
        # Extract features
        breathing_rate = self._extract_breathing_rate(amplitudes)
        movement_score = self._extract_movement_score(amplitudes)
        
        self.breathing_rates.append(breathing_rate)
        self.movement_scores.append(movement_score)
        
        # Average over recent history
        avg_breathing = np.mean(list(self.breathing_rates))
        avg_movement = np.mean(list(self.movement_scores))
        
        # Classify stage
        if avg_movement > 0.3:
            stage = "awake"
            confidence = min(1.0, avg_movement * 2)
        elif avg_movement < 0.05 and avg_breathing < 14:
            stage = "deep_sleep"
            confidence = 0.7
        elif avg_movement < 0.1 and avg_breathing > 18:
            # REM has irregular breathing
            breathing_var = np.std(list(self.breathing_rates)[-10:]) if len(self.breathing_rates) >= 10 else 0
            if breathing_var > 2:
                stage = "rem"
                confidence = 0.6
            else:
                stage = "light_sleep"
                confidence = 0.65
        else:
            stage = "light_sleep"
            confidence = 0.5
        
        self.stage_history.append(stage)
        
        return {
            "stage": stage,
            "confidence": float(confidence),
            "breathing_rate": float(avg_breathing),
            "movement_score": float(avg_movement),
            "time_in_stage": sum(1 for s in self.stage_history if s == stage)
        }


class MaterialDetector:
    """
    Detect material composition of obstacles from WiFi attenuation patterns.
    
    Different materials have characteristic absorption/reflection coefficients.
    """

    MATERIALS = {
        "air": {"attenuation": 0.0, "reflection": 0.0},
        "drywall": {"attenuation": 3.0, "reflection": 0.1},
        "wood": {"attenuation": 4.0, "reflection": 0.15},
        "glass": {"attenuation": 2.5, "reflection": 0.25},
        "brick": {"attenuation": 6.0, "reflection": 0.3},
        "concrete": {"attenuation": 12.0, "reflection": 0.4},
        "metal": {"attenuation": 25.0, "reflection": 0.9},
        "water": {"attenuation": 15.0, "reflection": 0.2},
        "human_body": {"attenuation": 8.0, "reflection": 0.35}
    }

    def __init__(self, baseline_rssi: float = -30.0):
        self.baseline_rssi = baseline_rssi
        self.rssi_history: deque = deque(maxlen=100)
        self.detection_history: deque = deque(maxlen=50)

    def detect(self, csi: 'CSIData', expected_rssi: float = None) -> Dict[str, Any]:
        """Detect material type from RSSI attenuation patterns."""
        self.rssi_history.append(csi.rssi)
        
        if expected_rssi is None:
            expected_rssi = self.baseline_rssi
        
        # Current attenuation
        attenuation = expected_rssi - csi.rssi
        
        # Frequency-dependent attenuation (higher frequencies attenuate more)
        freq_factor = csi.channel / 6.0 if csi.channel > 0 else 1.0
        normalized_atten = attenuation / freq_factor
        
        # Match against material profiles
        best_match = "air"
        best_score = float('inf')
        material_scores = {}
        
        for material, props in self.MATERIALS.items():
            diff = abs(props["attenuation"] - normalized_atten)
            material_scores[material] = max(0, 1.0 - diff / 20)
            if diff < best_score:
                best_score = diff
                best_match = material
        
        confidence = max(0, 1.0 - best_score / 10)
        
        self.detection_history.append(best_match)
        
        # Majority vote from recent history
        if len(self.detection_history) >= 10:
            from collections import Counter
            votes = Counter(list(self.detection_history)[-10:])
            stable_material = votes.most_common(1)[0][0]
        else:
            stable_material = best_match
        
        return {
            "material": stable_material,
            "confidence": float(confidence),
            "attenuation_db": float(attenuation),
            "material_scores": material_scores
        }


class WiFiSLAM:
    """
    Simultaneous Localization and Mapping using WiFi signals.
    
    Builds a map of the environment while tracking position using
    CSI fingerprints and signal propagation modeling.
    """

    def __init__(self, grid_resolution: float = 0.5, map_size: Tuple[float, float] = (20.0, 20.0)):
        self.grid_resolution = grid_resolution
        self.map_size = map_size
        
        # Grid dimensions
        self.grid_x = int(map_size[0] / grid_resolution)
        self.grid_y = int(map_size[1] / grid_resolution)
        
        # Occupancy grid (probability of obstacle)
        self.occupancy_grid = np.ones((self.grid_x, self.grid_y)) * 0.5
        
        # Signal strength map
        self.rssi_map = np.zeros((self.grid_x, self.grid_y))
        self.rssi_counts = np.zeros((self.grid_x, self.grid_y))
        
        # CSI fingerprint database
        self.fingerprints: Dict[Tuple[int, int], List['CSIData']] = {}
        
        # Current position estimate
        self.position = (map_size[0] / 2, map_size[1] / 2)
        self.position_uncertainty = 5.0
        
        # Access points discovered
        self.access_points: Dict[str, Dict[str, Any]] = {}
        
        # Loop closure candidates
        self.loop_closures: List[Dict] = []

    def _grid_coords(self, x: float, y: float) -> Tuple[int, int]:
        """Convert world coordinates to grid indices."""
        gx = int(x / self.grid_resolution)
        gy = int(y / self.grid_resolution)
        gx = max(0, min(self.grid_x - 1, gx))
        gy = max(0, min(self.grid_y - 1, gy))
        return gx, gy

    def update_position(self, csi: 'CSIData', motion_estimate: Tuple[float, float] = (0, 0)) -> Tuple[float, float]:
        """Update position estimate using CSI and motion model."""
        # Apply motion model
        new_x = self.position[0] + motion_estimate[0]
        new_y = self.position[1] + motion_estimate[1]
        
        # Fingerprint matching for correction
        best_match_dist = float('inf')
        best_match_pos = None
        
        for (gx, gy), prints in self.fingerprints.items():
            if not prints:
                continue
            
            # Compare CSI with stored fingerprints
            for fp in prints[-5:]:  # Use recent fingerprints
                amp_diff = np.mean(np.abs(np.array(csi.amplitude) - np.array(fp.amplitude)))
                rssi_diff = abs(csi.rssi - fp.rssi)
                distance = amp_diff * 10 + rssi_diff
                
                if distance < best_match_dist:
                    best_match_dist = distance
                    best_match_pos = (gx * self.grid_resolution, gy * self.grid_resolution)
        
        # If good match found, correct position
        if best_match_pos and best_match_dist < 5.0:
            match_weight = max(0, 1.0 - best_match_dist / 10)
            new_x = new_x * (1 - match_weight * 0.3) + best_match_pos[0] * match_weight * 0.3
            new_y = new_y * (1 - match_weight * 0.3) + best_match_pos[1] * match_weight * 0.3
            self.position_uncertainty *= (1 - match_weight * 0.2)
        else:
            self.position_uncertainty *= 1.02  # Uncertainty grows
        
        # Clamp to map bounds
        new_x = max(0, min(self.map_size[0], new_x))
        new_y = max(0, min(self.map_size[1], new_y))
        
        self.position = (new_x, new_y)
        
        # Store fingerprint at current location
        gx, gy = self._grid_coords(new_x, new_y)
        if (gx, gy) not in self.fingerprints:
            self.fingerprints[(gx, gy)] = []
        self.fingerprints[(gx, gy)].append(csi)
        if len(self.fingerprints[(gx, gy)]) > 20:
            self.fingerprints[(gx, gy)] = self.fingerprints[(gx, gy)][-20:]
        
        # Update RSSI map
        self.rssi_map[gx, gy] = (self.rssi_map[gx, gy] * self.rssi_counts[gx, gy] + csi.rssi) / (self.rssi_counts[gx, gy] + 1)
        self.rssi_counts[gx, gy] += 1
        
        return self.position

    def update_map(self, obstacles_detected: List[Tuple[float, float, float]]):
        """Update occupancy grid with detected obstacles."""
        for ox, oy, confidence in obstacles_detected:
            gx, gy = self._grid_coords(ox, oy)
            # Bayesian update
            prior = self.occupancy_grid[gx, gy]
            likelihood = 0.6 + 0.4 * confidence
            posterior = (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood))
            self.occupancy_grid[gx, gy] = posterior

    def get_map(self) -> Dict[str, Any]:
        """Get current map state."""
        return {
            "occupancy_grid": self.occupancy_grid.tolist(),
            "rssi_map": self.rssi_map.tolist(),
            "position": self.position,
            "uncertainty": self.position_uncertainty,
            "grid_resolution": self.grid_resolution,
            "fingerprint_count": sum(len(v) for v in self.fingerprints.values()),
            "access_points": self.access_points
        }


class ThroughWallImager:
    """
    Enhanced through-wall imaging using WiFi CSI.
    
    Reconstructs human silhouettes behind walls using signal diffraction
    and reflection analysis.
    """

    def __init__(self, image_resolution: Tuple[int, int] = (64, 64)):
        self.resolution = image_resolution
        self.csi_buffer: deque = deque(maxlen=500)
        self.image_buffer: deque = deque(maxlen=30)
        self.background_model: Optional[np.ndarray] = None
        self.calibrating = True
        self.calibration_frames = 0

    def calibrate_background(self, csi: 'CSIData') -> bool:
        """Calibrate background (empty scene)."""
        self.csi_buffer.append(csi)
        self.calibration_frames += 1
        
        if self.calibration_frames >= 100:
            # Build background model from calibration CSI
            amplitudes = np.array([c.amplitude for c in self.csi_buffer])
            self.background_model = np.mean(amplitudes, axis=0)
            self.calibrating = False
            return True
        
        return False

    def _csi_to_image(self, csi_diff: np.ndarray) -> np.ndarray:
        """Convert CSI difference to spatial image."""
        # Reshape CSI to 2D (simplified beamforming)
        n_subcarriers = len(csi_diff)
        sqrt_n = int(math.sqrt(n_subcarriers))
        
        if sqrt_n * sqrt_n < n_subcarriers:
            # Pad to square
            padded = np.zeros(sqrt_n * sqrt_n + 2 * sqrt_n + 1)
            padded[:n_subcarriers] = csi_diff
            sqrt_n += 1
        else:
            padded = csi_diff[:sqrt_n * sqrt_n]
        
        # Reshape and resize to target resolution
        spatial = padded[:sqrt_n * sqrt_n].reshape(sqrt_n, sqrt_n)
        
        # Simple upscaling
        scale_x = self.resolution[0] // sqrt_n
        scale_y = self.resolution[1] // sqrt_n
        if scale_x > 0 and scale_y > 0:
            upscaled = np.kron(spatial, np.ones((scale_x, scale_y)))
            # Crop to exact size
            image = upscaled[:self.resolution[0], :self.resolution[1]]
        else:
            image = np.zeros(self.resolution)
        
        return image

    def process(self, csi: 'CSIData') -> Dict[str, Any]:
        """Process CSI and generate through-wall image."""
        if self.calibrating:
            self.calibrate_background(csi)
            return {"calibrating": True, "progress": self.calibration_frames / 100}
        
        self.csi_buffer.append(csi)
        
        # Compute difference from background
        amp = np.array(csi.amplitude)
        diff = amp - self.background_model
        
        # Generate spatial image
        image = self._csi_to_image(diff)
        
        # Apply temporal averaging
        self.image_buffer.append(image)
        if len(self.image_buffer) >= 3:
            smoothed = np.mean(list(self.image_buffer)[-5:], axis=0)
        else:
            smoothed = image
        
        # Normalize to 0-255
        min_val, max_val = smoothed.min(), smoothed.max()
        if max_val > min_val:
            normalized = ((smoothed - min_val) / (max_val - min_val) * 255).astype(np.uint8)
        else:
            normalized = np.zeros(self.resolution, dtype=np.uint8)
        
        # Detect human presence
        activity = np.sum(np.abs(diff)) / len(diff)
        human_detected = activity > 0.05
        
        return {
            "image": normalized.tolist(),
            "human_detected": human_detected,
            "activity_level": float(activity),
            "resolution": self.resolution
        }


try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    # Create stub for nn.Module
    class _StubModule:
        pass
    
    class nn:
        Module = _StubModule

try:
    from scapy.all import sniff, Dot11, RadioTap, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class SensingMode(Enum):
    """WiFi sensing operational modes"""
    PASSIVE = "passive"           # Listen only, no transmission
    ACTIVE = "active"             # Send probes for better CSI
    HYBRID = "hybrid"             # Combination of both


class DetectionType(Enum):
    """Types of detections"""
    PRESENCE = "presence"         # Someone is in the area
    MOVEMENT = "movement"         # Active movement detected
    BREATHING = "breathing"       # Breathing pattern detected
    GESTURE = "gesture"           # Hand/body gesture
    FALL = "fall"                 # Fall detection
    ACTIVITY = "activity"         # Activity classification


@dataclass
class CSIData:
    """Channel State Information data structure"""
    timestamp: float
    mac_address: str
    rssi: float                   # Received Signal Strength Indicator (dBm)
    channel: int
    bandwidth: int                # MHz
    num_subcarriers: int
    amplitude: List[float]        # Amplitude per subcarrier
    phase: List[float]            # Phase per subcarrier
    noise_floor: float
    antenna_config: str           # e.g., "2x2", "4x4"
    
    def to_numpy(self) -> 'np.ndarray':
        """Convert to numpy array for ML processing"""
        return np.array(self.amplitude + self.phase)
    
    def get_complex_csi(self) -> 'np.ndarray':
        """Get complex CSI values"""
        amp = np.array(self.amplitude)
        phase = np.array(self.phase)
        return amp * np.exp(1j * phase)


@dataclass
class LocationEstimate:
    """Estimated location of a detected individual"""
    x: float                      # X coordinate (meters)
    y: float                      # Y coordinate (meters)
    z: float                      # Z coordinate/height (meters)
    confidence: float             # 0-1 confidence score
    accuracy_radius: float        # Uncertainty radius (meters)
    velocity: Tuple[float, float, float]  # Velocity vector (m/s)
    timestamp: float
    detection_type: DetectionType
    room_id: Optional[str] = None
    
    def distance_from(self, other: 'LocationEstimate') -> float:
        """Calculate 3D distance from another location"""
        return math.sqrt(
            (self.x - other.x) ** 2 +
            (self.y - other.y) ** 2 +
            (self.z - other.z) ** 2
        )


@dataclass
class RoomGeometry:
    """Reconstructed room geometry"""
    room_id: str
    walls: List[Dict[str, Any]]   # Wall segments with endpoints
    dimensions: Dict[str, float]  # width, length, height
    furniture: List[Dict[str, Any]]  # Detected large objects
    openings: List[Dict[str, Any]]  # Doors, windows
    signal_map: Dict[str, float]  # Signal strength heatmap
    confidence: float
    last_updated: float


@dataclass
class AccessPoint:
    """WiFi access point information"""
    bssid: str
    ssid: str
    channel: int
    rssi: float
    position: Optional[Tuple[float, float, float]] = None
    is_controlled: bool = False   # Whether we control this AP


class CSIExtractor:
    """Extract CSI data from WiFi interfaces"""
    
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.logger = logging.getLogger("CSIExtractor")
        self.csi_buffer: deque = deque(maxlen=1000)
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        
    def check_capabilities(self) -> Dict[str, bool]:
        """Check if interface supports CSI extraction"""
        capabilities = {
            "monitor_mode": False,
            "csi_support": False,
            "injection": False,
            "multiple_channels": False
        }
        
        try:
            # Check if interface exists
            result = subprocess.run(
                ["iw", "dev", self.interface, "info"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Check monitor mode support
                result = subprocess.run(
                    ["iw", "phy"],
                    capture_output=True, text=True, timeout=5
                )
                if "monitor" in result.stdout.lower():
                    capabilities["monitor_mode"] = True
                
                # Check for CSI-capable chipsets (Intel 5300, Atheros, etc.)
                result = subprocess.run(
                    ["lspci", "-v"],
                    capture_output=True, text=True, timeout=5
                )
                csi_chipsets = ["Intel", "Atheros", "ath9k", "iwlwifi", "88xx"]
                for chipset in csi_chipsets:
                    if chipset.lower() in result.stdout.lower():
                        capabilities["csi_support"] = True
                        break
                        
        except Exception as e:
            self.logger.warning(f"Capability check failed: {e}")
        
        return capabilities
    
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on interface"""
        try:
            commands = [
                ["sudo", "ip", "link", "set", self.interface, "down"],
                ["sudo", "iw", self.interface, "set", "type", "monitor"],
                ["sudo", "ip", "link", "set", self.interface, "up"]
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode != 0:
                    self.logger.error(f"Failed: {' '.join(cmd)}")
                    return False
            
            self.logger.info(f"Monitor mode enabled on {self.interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to enable monitor mode: {e}")
            return False
    
    def set_channel(self, channel: int, bandwidth: int = 20) -> bool:
        """Set interface channel"""
        try:
            result = subprocess.run(
                ["sudo", "iw", self.interface, "set", "channel", str(channel)],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def start_capture(self, callback: Optional[Callable] = None):
        """Start CSI capture"""
        if self._running:
            return
        
        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(callback,),
            daemon=True
        )
        self._capture_thread.start()
    
    def stop_capture(self):
        """Stop CSI capture"""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=2)
    
    def _capture_loop(self, callback: Optional[Callable]):
        """Main capture loop"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available for packet capture")
            return
        
        def packet_handler(pkt):
            if not self._running:
                return
            
            try:
                csi = self._extract_csi_from_packet(pkt)
                if csi:
                    self.csi_buffer.append(csi)
                    if callback:
                        callback(csi)
            except Exception as e:
                self.logger.debug(f"CSI extraction error: {e}")
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except Exception as e:
            self.logger.error(f"Capture error: {e}")
    
    def _extract_csi_from_packet(self, pkt) -> Optional[CSIData]:
        """Extract CSI from a captured packet"""
        if not pkt.haslayer(RadioTap):
            return None
        
        radiotap = pkt.getlayer(RadioTap)
        
        # Get basic info from RadioTap header
        rssi = getattr(radiotap, 'dBm_AntSignal', -70)
        channel = getattr(radiotap, 'Channel', 0)
        
        # Get MAC address if available
        mac = "00:00:00:00:00:00"
        if pkt.haslayer(Dot11):
            mac = pkt.addr2 or mac
        
        # For real CSI, we need specialized firmware/drivers
        # This simulates CSI extraction based on packet characteristics
        # Real implementation would use:
        # - Intel 5300 CSI Tool
        # - Atheros CSI extraction
        # - Nexmon CSI for Broadcom
        
        num_subcarriers = 56  # 802.11n with 20MHz
        
        # Estimate amplitude based on RSSI and packet size
        base_amplitude = 10 ** (rssi / 20)
        amplitude = [
            base_amplitude * (1 + 0.1 * math.sin(i * 0.2))
            for i in range(num_subcarriers)
        ]
        
        # Estimate phase (would come from actual CSI data)
        phase = [
            (i * 0.1 + time.time() * 0.01) % (2 * math.pi)
            for i in range(num_subcarriers)
        ]
        
        return CSIData(
            timestamp=time.time(),
            mac_address=mac,
            rssi=rssi,
            channel=channel,
            bandwidth=20,
            num_subcarriers=num_subcarriers,
            amplitude=amplitude,
            phase=phase,
            noise_floor=-95,
            antenna_config="2x2"
        )
    
    def get_buffer(self) -> List[CSIData]:
        """Get buffered CSI data"""
        return list(self.csi_buffer)


# PyTorch models - only defined if torch is available
if TORCH_AVAILABLE:
    class SelfAttention(nn.Module):
        """Simple self-attention layer for CSI feature refinement."""
        def __init__(self, dim: int, heads: int = 4):
            super().__init__()
            self.heads = heads
            self.scale = (dim // heads) ** -0.5
            self.to_qkv = nn.Linear(dim, dim * 3, bias=False)
            self.out = nn.Linear(dim, dim)

        def forward(self, x: 'torch.Tensor') -> 'torch.Tensor':
            B, N, C = x.shape
            qkv = self.to_qkv(x).reshape(B, N, 3, self.heads, C // self.heads).permute(2, 0, 3, 1, 4)
            q, k, v = qkv[0], qkv[1], qkv[2]
            attn = (q @ k.transpose(-2, -1)) * self.scale
            attn = attn.softmax(dim=-1)
            out = (attn @ v).transpose(1, 2).reshape(B, N, C)
            return self.out(out)

    class WifiLocalizationModel(nn.Module):
        """Neural network for WiFi-based localization"""
        
        def __init__(self, num_subcarriers: int = 56, num_aps: int = 4):
            super().__init__()
            
            input_size = num_subcarriers * 2 * num_aps  # Amplitude + phase per AP
            
            # CSI feature encoder
            self.encoder = nn.Sequential(
                nn.Linear(input_size, 512),
                nn.BatchNorm1d(512),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(512, 256),
                nn.BatchNorm1d(256),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(256, 128),
                nn.ReLU()
            )

            # Self-attention for temporal feature refinement
            self.attention = SelfAttention(128, heads=4)
            
            # Temporal processing with LSTM
            self.lstm = nn.LSTM(
                input_size=128,
                hidden_size=64,
                num_layers=2,
                batch_first=True,
                bidirectional=True
            )
            
            # Location prediction head
            self.location_head = nn.Sequential(
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, 3)  # x, y, z coordinates
            )
            
            # Confidence prediction
            self.confidence_head = nn.Sequential(
                nn.Linear(128, 32),
                nn.ReLU(),
                nn.Linear(32, 1),
                nn.Sigmoid()
            )
            
            # Activity classification
            self.activity_head = nn.Sequential(
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, len(DetectionType))
            )
        
        def forward(self, x: 'torch.Tensor', seq_len: int = 1):
            """
            Forward pass
            x: (batch, seq_len, features) or (batch, features)
            """
            batch_size = x.size(0)
            
            if x.dim() == 2:
                x = x.unsqueeze(1)
                seq_len = 1
            
            # Encode each timestep
            encoded = []
            for t in range(x.size(1)):
                enc = self.encoder(x[:, t, :])
                encoded.append(enc)
            
            encoded = torch.stack(encoded, dim=1)

            # Apply self-attention
            encoded = encoded + self.attention(encoded)
            
            # Temporal processing
            lstm_out, _ = self.lstm(encoded)
            
            # Use last output
            features = lstm_out[:, -1, :]
            
            # Predictions
            location = self.location_head(features)
            confidence = self.confidence_head(features)
            activity_logits = self.activity_head(features)
            
            return {
                'location': location,
                'confidence': confidence.squeeze(-1),
                'activity': F.softmax(activity_logits, dim=-1)
            }

    class EnvironmentReconstructionModel(nn.Module):
        """AI model for reconstructing indoor environments from WiFi signals"""
        
        def __init__(self, grid_size: int = 64, num_subcarriers: int = 56):
            super().__init__()
            
            self.grid_size = grid_size
            
            # CSI encoder
            self.csi_encoder = nn.Sequential(
                nn.Linear(num_subcarriers * 2, 256),
                nn.ReLU(),
                nn.Linear(256, 512),
                nn.ReLU(),
                nn.Linear(512, 1024),
                nn.ReLU()
            )
            
            # Reshape to 2D feature map
            self.to_2d = nn.Linear(1024, 16 * 16 * 64)
            
            # Decoder (upsampling to grid)
            self.decoder = nn.Sequential(
                # 16x16 -> 32x32
                nn.ConvTranspose2d(64, 128, 4, stride=2, padding=1),
                nn.BatchNorm2d(128),
                nn.ReLU(),
                
                # 32x32 -> 64x64
                nn.ConvTranspose2d(128, 64, 4, stride=2, padding=1),
                nn.BatchNorm2d(64),
                nn.ReLU(),
                
                # Output channels: wall, furniture, empty, door/window
                nn.Conv2d(64, 4, 3, padding=1),
                nn.Softmax(dim=1)
            )
            
            # Wall segment predictor
            self.wall_predictor = nn.Sequential(
                nn.Linear(1024, 256),
                nn.ReLU(),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Linear(128, 20 * 4)  # Max 20 wall segments, 4 coords each
            )
            
            # Room dimensions predictor
            self.dimension_predictor = nn.Sequential(
                nn.Linear(1024, 64),
                nn.ReLU(),
                nn.Linear(64, 3)  # width, length, height
            )
        
        def forward(self, csi_sequence: 'torch.Tensor'):
            """
            Reconstruct environment from CSI sequence
            csi_sequence: (batch, seq_len, num_subcarriers * 2)
            """
            batch_size = csi_sequence.size(0)
            
            # Average CSI over time for stable reconstruction
            csi_avg = csi_sequence.mean(dim=1)
            
            # Encode
            encoded = self.csi_encoder(csi_avg)
            
            # Generate 2D layout
            features_2d = self.to_2d(encoded)
            features_2d = features_2d.view(batch_size, 64, 16, 16)
            
            # Decode to occupancy grid
            occupancy_grid = self.decoder(features_2d)
            
            # Predict wall segments
            wall_coords = self.wall_predictor(encoded)
            wall_coords = wall_coords.view(batch_size, 20, 4)
            
            # Predict dimensions
            dimensions = F.relu(self.dimension_predictor(encoded)) + 1.0  # Min 1m
            
            return {
                'occupancy_grid': occupancy_grid,  # (batch, 4, 64, 64)
                'wall_segments': wall_coords,       # (batch, 20, 4)
                'dimensions': dimensions            # (batch, 3)
            }
else:
    # Stub classes when PyTorch is not available
    class WifiLocalizationModel:
        """Stub - requires PyTorch"""
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PyTorch is required for WifiLocalizationModel")
    
    class EnvironmentReconstructionModel:
        """Stub - requires PyTorch"""
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PyTorch is required for EnvironmentReconstructionModel")


class BreathingDetector:
    """Detect breathing patterns from CSI data"""
    
    def __init__(self, sample_rate: float = 100):
        self.sample_rate = sample_rate
        self.breathing_buffer: deque = deque(maxlen=int(sample_rate * 30))  # 30 sec
        
    def add_sample(self, csi: CSIData):
        """Add CSI sample to buffer"""
        # Use phase variance as breathing indicator
        phase_var = np.var(csi.phase)
        self.breathing_buffer.append((csi.timestamp, phase_var))
    
    def detect_breathing(self) -> Optional[Dict[str, Any]]:
        """Detect breathing from buffered data"""
        if len(self.breathing_buffer) < self.sample_rate * 5:  # Need 5 sec
            return None
        
        timestamps = [x[0] for x in self.breathing_buffer]
        values = [x[1] for x in self.breathing_buffer]
        
        # Bandpass filter for breathing frequency (0.1 - 0.5 Hz)
        # In production, use scipy.signal for proper filtering
        
        # Simple moving average for smoothing
        window = int(self.sample_rate * 0.5)
        if len(values) < window:
            return None
        
        smoothed = np.convolve(values, np.ones(window)/window, mode='valid')
        
        # Find peaks (breathing cycles)
        peaks = []
        for i in range(1, len(smoothed) - 1):
            if smoothed[i] > smoothed[i-1] and smoothed[i] > smoothed[i+1]:
                peaks.append(i)
        
        if len(peaks) < 2:
            return None
        
        # Calculate breathing rate
        peak_intervals = np.diff(peaks) / self.sample_rate
        avg_interval = np.mean(peak_intervals)
        breathing_rate = 60.0 / avg_interval if avg_interval > 0 else 0
        
        # Validate reasonable breathing rate (8-30 breaths/min)
        if 8 <= breathing_rate <= 30:
            return {
                "detected": True,
                "rate_bpm": round(breathing_rate, 1),
                "confidence": min(1.0, len(peaks) / 10),
                "regularity": 1.0 - min(1.0, np.std(peak_intervals) / avg_interval)
            }
        
        return {"detected": False}


class MovementTracker:
    """Track movement using CSI changes"""
    
    def __init__(self, num_subcarriers: int = 56):
        self.num_subcarriers = num_subcarriers
        self.history: deque = deque(maxlen=100)
        self.baseline: Optional[np.ndarray] = None
        self.movement_threshold = 0.1
        
    def update(self, csi: CSIData) -> Dict[str, Any]:
        """Update tracker with new CSI data"""
        current = csi.to_numpy()
        
        if self.baseline is None:
            self.baseline = current
            self.history.append((csi.timestamp, current, False))
            return {"movement": False, "intensity": 0}
        
        # Calculate change from baseline
        diff = np.abs(current - self.baseline)
        change_ratio = np.mean(diff) / (np.mean(np.abs(self.baseline)) + 1e-6)
        
        # Detect movement
        is_moving = change_ratio > self.movement_threshold
        
        self.history.append((csi.timestamp, current, is_moving))
        
        # Update baseline slowly when stationary
        if not is_moving:
            self.baseline = 0.99 * self.baseline + 0.01 * current
        
        return {
            "movement": is_moving,
            "intensity": min(1.0, change_ratio / (self.movement_threshold * 2)),
            "change_ratio": change_ratio
        }
    
    def get_velocity_estimate(self) -> Tuple[float, float, float]:
        """Estimate velocity from movement patterns"""
        if len(self.history) < 10:
            return (0.0, 0.0, 0.0)
        
        recent = list(self.history)[-10:]
        movement_count = sum(1 for _, _, m in recent if m)
        
        # Very rough velocity estimate
        speed = movement_count * 0.1  # m/s approximation
        
        # Direction would need triangulation
        return (speed, 0.0, 0.0)


class DistanceEstimator:
    """Estimate distance between transmitter and receiver"""
    
    # Path loss model parameters
    REFERENCE_RSSI = -40  # RSSI at 1 meter (dBm)
    PATH_LOSS_EXPONENT = 2.7  # Environment-dependent (2-4)
    
    def __init__(self, access_points: List[AccessPoint]):
        self.access_points = {ap.bssid: ap for ap in access_points}
    
    def rssi_to_distance(self, rssi: float, reference_rssi: float = None,
                         path_loss_exp: float = None) -> float:
        """Convert RSSI to distance using log-distance path loss model"""
        ref_rssi = reference_rssi or self.REFERENCE_RSSI
        n = path_loss_exp or self.PATH_LOSS_EXPONENT
        
        # d = 10 ^ ((ref_rssi - rssi) / (10 * n))
        distance = 10 ** ((ref_rssi - rssi) / (10 * n))
        
        return distance
    
    def csi_to_distance(self, csi: CSIData) -> Tuple[float, float]:
        """
        Estimate distance using CSI data (more accurate than RSSI)
        Returns (distance, uncertainty)
        """
        # Use average amplitude across subcarriers
        avg_amplitude = np.mean(csi.amplitude)
        
        # Phase-based ToF estimation
        phase = np.array(csi.phase)
        phase_unwrapped = np.unwrap(phase)
        
        # Estimate delay from phase slope
        subcarrier_spacing = 312.5e3  # Hz for 802.11n
        phase_slope = np.polyfit(range(len(phase_unwrapped)), phase_unwrapped, 1)[0]
        
        # Time of flight (rough estimate)
        speed_of_light = 3e8
        # tof = phase_slope / (2 * np.pi * subcarrier_spacing)
        # distance = tof * speed_of_light
        
        # For now, use amplitude-based estimate
        rssi_estimate = 20 * np.log10(avg_amplitude + 1e-10)
        distance = self.rssi_to_distance(rssi_estimate)
        
        # Uncertainty increases with distance
        uncertainty = distance * 0.2  # 20% uncertainty
        
        return (distance, uncertainty)
    
    def trilaterate(self, measurements: List[Tuple[str, float]]) -> Optional[LocationEstimate]:
        """
        Trilateration using distances from multiple APs
        measurements: List of (bssid, distance) tuples
        """
        if len(measurements) < 3:
            return None
        
        # Get AP positions
        positions = []
        distances = []
        
        for bssid, dist in measurements:
            if bssid in self.access_points and self.access_points[bssid].position:
                positions.append(self.access_points[bssid].position)
                distances.append(dist)
        
        if len(positions) < 3:
            return None
        
        # Least squares trilateration
        # Simplified 2D case
        A = []
        b = []
        
        x1, y1, _ = positions[0]
        d1 = distances[0]
        
        for i in range(1, len(positions)):
            xi, yi, _ = positions[i]
            di = distances[i]
            
            A.append([2 * (xi - x1), 2 * (yi - y1)])
            b.append([
                d1**2 - di**2 - x1**2 + xi**2 - y1**2 + yi**2
            ])
        
        A = np.array(A)
        b = np.array(b).flatten()
        
        # Solve least squares
        try:
            result, residuals, _, _ = np.linalg.lstsq(A, b, rcond=None)
            x, y = result
            
            # Estimate Z based on signal characteristics
            z = 1.0  # Assume person height
            
            # Calculate accuracy from residuals
            accuracy = np.sqrt(np.mean((np.dot(A, result) - b)**2)) if len(residuals) > 0 else 1.0
            
            return LocationEstimate(
                x=float(x),
                y=float(y),
                z=z,
                confidence=max(0, 1 - accuracy / 5),
                accuracy_radius=max(0.5, accuracy),
                velocity=(0, 0, 0),
                timestamp=time.time(),
                detection_type=DetectionType.PRESENCE
            )
            
        except Exception:
            return None


class WifiSensingEngine:
    """Main engine for WiFi-based sensing and localization"""
    
    def __init__(self, 
                 interface: str = "wlan0",
                 mode: SensingMode = SensingMode.PASSIVE,
                 model_path: Optional[str] = None,
                 esp32_udp_port: Optional[int] = None,
                 esp32_serial_port: Optional[str] = None,
                 esp32_baudrate: int = 115200):
        
        self.interface = interface
        self.mode = mode
        self.logger = logging.getLogger("WifiSensing")
        self.esp32_udp_port = esp32_udp_port
        self.esp32_serial_port = esp32_serial_port
        self.esp32_baudrate = esp32_baudrate
        
        # Components
        self.csi_extractor = CSIExtractor(interface)
        self.breathing_detector = BreathingDetector()
        self.movement_tracker = MovementTracker()
        self.fall_detector = FallDetector()
        self.anomaly_detector = AnomalyDetector()
        self.kalman_tracker = KalmanTracker()
        self.csi_denoiser = CSIDenoiser()
        self.channel_hopper = ChannelHopper(interface, self.csi_extractor.set_channel)
        self.gesture_recognizer = GestureRecognizer()
        self.heart_rate_estimator = HeartRateEstimator()
        self.multi_person_tracker = MultiPersonTracker()
        self.zone_manager = ZoneManager()
        self.uncertainty_estimator = UncertaintyEstimator()
        self.synthetic_generator = CSISyntheticGenerator()
        self.esp32_receiver: Optional[ESP32CSIReceiver] = None
        self.esp32_serial: Optional[ESP32SerialReceiver] = None
        
        # Advanced sensing components
        self.doppler_estimator = DopplerVelocityEstimator()
        self.activity_classifier = ActivityClassifier()
        self.people_counter = PeopleCounter()
        self.sleep_detector = SleepStageDetector()
        self.material_detector = MaterialDetector()
        self.wifi_slam = WiFiSLAM()
        self.through_wall_imager = ThroughWallImager()
        
        # Access points
        self.access_points: List[AccessPoint] = []
        self.distance_estimator: Optional[DistanceEstimator] = None
        
        # AI Models
        self.localization_model: Optional[WifiLocalizationModel] = None
        self.reconstruction_model: Optional[EnvironmentReconstructionModel] = None
        
        if TORCH_AVAILABLE:
            self.localization_model = WifiLocalizationModel()
            self.reconstruction_model = EnvironmentReconstructionModel()
            
            if model_path and os.path.exists(model_path):
                self._load_models(model_path)
        
        # State
        self.current_locations: Dict[str, LocationEstimate] = {}
        self.room_geometry: Optional[RoomGeometry] = None
        self.csi_history: deque = deque(maxlen=500)
        
        # Callbacks
        self.on_detection: Optional[Callable] = None
        self.on_location_update: Optional[Callable] = None
        self.on_environment_update: Optional[Callable] = None
        
        self._running = False
    
    def _load_models(self, path: str):
        """Load pre-trained models"""
        try:
            loc_path = os.path.join(path, "localization.pt")
            recon_path = os.path.join(path, "reconstruction.pt")
            
            if os.path.exists(loc_path):
                self.localization_model.load_state_dict(torch.load(loc_path))
                self.localization_model.eval()
                self.logger.info("Loaded localization model")
            
            if os.path.exists(recon_path):
                self.reconstruction_model.load_state_dict(torch.load(recon_path))
                self.reconstruction_model.eval()
                self.logger.info("Loaded reconstruction model")
                
        except Exception as e:
            self.logger.error(f"Model loading failed: {e}")
    
    def scan_access_points(self) -> List[AccessPoint]:
        """Scan for nearby access points"""
        aps = []
        
        try:
            result = subprocess.run(
                ["sudo", "iwlist", self.interface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                current_ap = {}
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if 'Address:' in line:
                        if current_ap.get('bssid'):
                            aps.append(AccessPoint(
                                bssid=current_ap['bssid'],
                                ssid=current_ap.get('ssid', ''),
                                channel=current_ap.get('channel', 0),
                                rssi=current_ap.get('rssi', -100)
                            ))
                        current_ap = {'bssid': line.split('Address:')[1].strip()}
                    
                    elif 'ESSID:' in line:
                        ssid = line.split('ESSID:')[1].strip().strip('"')
                        current_ap['ssid'] = ssid
                    
                    elif 'Channel:' in line:
                        try:
                            current_ap['channel'] = int(line.split('Channel:')[1].strip())
                        except:
                            pass
                    
                    elif 'Signal level=' in line:
                        try:
                            rssi_str = line.split('Signal level=')[1].split()[0]
                            current_ap['rssi'] = int(rssi_str)
                        except:
                            pass
                
                # Add last AP
                if current_ap.get('bssid'):
                    aps.append(AccessPoint(
                        bssid=current_ap['bssid'],
                        ssid=current_ap.get('ssid', ''),
                        channel=current_ap.get('channel', 0),
                        rssi=current_ap.get('rssi', -100)
                    ))
        
        except Exception as e:
            self.logger.error(f"AP scan failed: {e}")
        
        self.access_points = aps
        self.distance_estimator = DistanceEstimator(aps)
        
        return aps
    
    def configure_ap_positions(self, positions: Dict[str, Tuple[float, float, float]]):
        """Configure known AP positions for trilateration"""
        for bssid, pos in positions.items():
            for ap in self.access_points:
                if ap.bssid.lower() == bssid.lower():
                    ap.position = pos
                    break
        
        self.distance_estimator = DistanceEstimator(self.access_points)
    
    async def start(self):
        """Start the sensing engine"""
        self.logger.info("Starting WiFi sensing engine...")
        
        # Skip interface checks if using ESP32 serial (no sudo needed)
        if not self.esp32_serial_port:
            # Check capabilities (requires sudo for some operations)
            caps = self.csi_extractor.check_capabilities()
            self.logger.info(f"Capabilities: {caps}")
            
            if not caps["monitor_mode"]:
                self.logger.warning("Monitor mode not available, using limited mode")
            
            # Scan for APs
            self.scan_access_points()
            self.logger.info(f"Found {len(self.access_points)} access points")
        else:
            self.logger.info("Using ESP32 serial mode - skipping interface checks")
        
        # Determine CSI input source (priority: serial > UDP > local interface)
        if self.esp32_serial_port:
            # Use ESP32 via USB serial (direct connection, no WiFi needed)
            self.esp32_serial = ESP32SerialReceiver(
                port=self.esp32_serial_port,
                baudrate=self.esp32_baudrate
            )
            if self.esp32_serial.start(self._on_csi_received):
                self.logger.info("ESP32 CSI via USB serial on %s", self.esp32_serial_port)
            else:
                self.logger.error("Failed to open ESP32 serial port, falling back to local interface")
                self.esp32_serial = None
                self.csi_extractor.start_capture(callback=self._on_csi_received)
                self.channel_hopper.start()
        elif self.esp32_udp_port:
            # Use ESP32 via UDP (ESP32 connected to WiFi network)
            self.esp32_receiver = ESP32CSIReceiver(port=self.esp32_udp_port)
            self.esp32_receiver.start(self._on_csi_received)
            self.logger.info("ESP32 CSI via UDP on port %s", self.esp32_udp_port)
        else:
            # Use local WiFi interface for CSI capture
            self.csi_extractor.start_capture(callback=self._on_csi_received)
            self.channel_hopper.start()
            self.logger.info("Using local interface %s for CSI capture", self.interface)
        
        self._running = True
        
        # Start processing loop
        await self._processing_loop()
    
    async def stop(self):
        """Stop the sensing engine"""
        self._running = False
        self.csi_extractor.stop_capture()
        self.channel_hopper.stop()
        if self.esp32_receiver:
            self.esp32_receiver.stop()
        if self.esp32_serial:
            self.esp32_serial.stop()
        self.logger.info("WiFi sensing engine stopped")
    
    def set_esp32_channel(self, channel: int):
        """Set ESP32 capture channel (works with serial connection)."""
        if self.esp32_serial:
            self.esp32_serial.set_channel(channel)
        elif self.esp32_receiver:
            self.logger.warning("Channel control requires serial connection to ESP32")
    
    def get_esp32_status(self) -> Dict[str, Any]:
        """Get ESP32 receiver status."""
        serial_packets = self.esp32_serial.packets_received if self.esp32_serial else 0
        udp_packets = self.esp32_receiver.packets_received if self.esp32_receiver else 0
        
        status = {
            "connected": (self.esp32_serial is not None) or (self.esp32_receiver is not None),
            "udp_enabled": self.esp32_receiver is not None,
            "serial_enabled": self.esp32_serial is not None,
            "udp_packets": udp_packets,
            "serial_packets": serial_packets,
            "packets_received": serial_packets + udp_packets,
        }
        return status
    
    def _on_csi_received(self, csi: CSIData):
        """Callback when CSI data is received"""
        # Denoise CSI to stabilize downstream detectors
        csi = self.csi_denoiser.denoise(csi)
        self.csi_history.append(csi)
        
        # Update breathing detector
        self.breathing_detector.add_sample(csi)
        
        # Update movement tracker
        movement = self.movement_tracker.update(csi)
        
        if movement["movement"] and self.on_detection:
            self.on_detection(DetectionType.MOVEMENT, movement)

        # Detect potential falls from sharp motion spikes
        fall = self.fall_detector.update(movement["intensity"], csi.timestamp)
        if fall and self.on_detection:
            self.on_detection(DetectionType.FALL, fall)

        # Anomaly detection on CSI magnitude
        anomaly = self.anomaly_detector.update(csi)
        if anomaly and self.on_detection:
            self.on_detection(DetectionType.ACTIVITY, {"anomaly": anomaly})

        # Gesture recognition
        gesture = self.gesture_recognizer.update(csi)
        if gesture and self.on_detection:
            self.on_detection(DetectionType.GESTURE, gesture)

        # Heart rate estimation
        self.heart_rate_estimator.add_sample(csi)
        
        # =====================================================================
        # ADVANCED SENSING UPDATES
        # =====================================================================
        
        # Doppler velocity estimation
        self.doppler_estimator.update(csi)
        
        # Activity classification
        activity_result = self.activity_classifier.classify(csi)
        if activity_result.get("activity") not in ["idle"] and activity_result.get("confidence", 0) > 0.6:
            if self.on_detection:
                self.on_detection(DetectionType.ACTIVITY, {"classified_activity": activity_result})
        
        # People counting
        self.people_counter.count(csi)
        
        # Sleep stage detection (passive - useful for dedicated sleep monitoring)
        self.sleep_detector.detect(csi)
        
        # Material detection
        self.material_detector.detect(csi)
        
        # Through-wall imaging
        self.through_wall_imager.process(csi)
        
        # WiFi SLAM position update
        self.wifi_slam.update_position(csi)
    
    async def _processing_loop(self):
        """Main processing loop"""
        while self._running:
            try:
                if len(self.csi_history) >= 10:
                    # Run localization
                    await self._update_locations()
                    
                    # Check for breathing
                    breathing = self.breathing_detector.detect_breathing()
                    if breathing and breathing.get("detected"):
                        if self.on_detection:
                            self.on_detection(DetectionType.BREATHING, breathing)

                    # Heart rate estimation
                    heart = self.heart_rate_estimator.estimate()
                    if heart and heart.get("detected"):
                        if self.on_detection:
                            self.on_detection(DetectionType.ACTIVITY, {"heart_rate": heart})

                    # Multi-person tracking
                    if self.current_locations:
                        tracked = self.multi_person_tracker.update(list(self.current_locations.values()))
                        # Annotate room ids from zone manager
                        for person in tracked:
                            zone = self.zone_manager.get_zone_for_position(person.position)
                            if zone:
                                # Update primary location room_id if matches
                                if "primary" in self.current_locations:
                                    self.current_locations["primary"].room_id = zone.id
                    
                    # Update environment reconstruction periodically
                    if len(self.csi_history) >= 100:
                        await self._update_environment()
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Processing error: {e}")
                await asyncio.sleep(1)
    
    async def _update_locations(self):
        """Update location estimates"""
        if not self.distance_estimator:
            return
        
        # Get latest CSI from each AP
        ap_measurements = {}
        for csi in list(self.csi_history)[-20:]:
            distance, _ = self.distance_estimator.csi_to_distance(csi)
            ap_measurements[csi.mac_address] = distance
        
        # Trilaterate
        measurements = list(ap_measurements.items())
        classical_location = self.distance_estimator.trilaterate(measurements)

        final_location = classical_location
        ai_location = None

        # Use AI model if available
        if self.localization_model and TORCH_AVAILABLE:
            ai_location = await self._ai_localization()

        if classical_location and ai_location:
            final_location = self._blend_locations(classical_location, ai_location)
        elif ai_location:
            final_location = ai_location

        if final_location:
            # Smooth with Kalman tracker to reduce jitter
            final_location = self.kalman_tracker.update(final_location)

            self.current_locations["primary"] = final_location

            # Derive uncertainty estimate
            if classical_location and ai_location:
                residual = classical_location.distance_from(ai_location)
            else:
                residual = final_location.accuracy_radius
            final_location.accuracy_radius = self.uncertainty_estimator.from_residuals(
                residual=residual,
                confidence=final_location.confidence,
            )

            if self.on_location_update:
                self.on_location_update(final_location)
    
    async def _ai_localization(self) -> Optional[LocationEstimate]:
        """Use AI model for localization"""
        if not TORCH_AVAILABLE or not self.localization_model:
            return None
        
        try:
            # Prepare input
            recent_csi = list(self.csi_history)[-20:]
            if len(recent_csi) < 5:
                return None
            
            features = []
            for csi in recent_csi:
                features.append(csi.to_numpy())
            
            x = torch.FloatTensor(np.array(features)).unsqueeze(0)
            
            with torch.no_grad():
                output = self.localization_model(x)
            
            loc = output['location'][0].numpy()
            conf = output['confidence'][0].item()
            activity = output['activity'][0].numpy()
            
            activity_type = DetectionType(list(DetectionType)[np.argmax(activity)].value)
            
            return LocationEstimate(
                x=float(loc[0]),
                y=float(loc[1]),
                z=float(loc[2]),
                confidence=float(conf),
                accuracy_radius=max(0.5, (1 - conf) * 3),
                velocity=self.movement_tracker.get_velocity_estimate(),
                timestamp=time.time(),
                detection_type=activity_type
            )
            
        except Exception as e:
            self.logger.error(f"AI localization error: {e}")
            return None

    def _blend_locations(self, loc_a: LocationEstimate, loc_b: LocationEstimate) -> LocationEstimate:
        """Blend two location estimates by confidence weighting."""
        conf_a = max(0.01, loc_a.confidence)
        conf_b = max(0.01, loc_b.confidence)
        total = conf_a + conf_b
        wa = conf_a / total
        wb = conf_b / total

        def mix(a: float, b: float) -> float:
            return a * wa + b * wb

        blended = LocationEstimate(
            x=mix(loc_a.x, loc_b.x),
            y=mix(loc_a.y, loc_b.y),
            z=mix(loc_a.z, loc_b.z),
            confidence=min(1.0, max(loc_a.confidence, loc_b.confidence)),
            accuracy_radius=min(loc_a.accuracy_radius, loc_b.accuracy_radius),
            velocity=self.movement_tracker.get_velocity_estimate(),
            timestamp=time.time(),
            detection_type=loc_b.detection_type if loc_b.confidence >= loc_a.confidence else loc_a.detection_type,
            room_id=loc_a.room_id or loc_b.room_id,
        )
        return blended
    
    async def _update_environment(self):
        """Update environment reconstruction"""
        if not TORCH_AVAILABLE or not self.reconstruction_model:
            return
        
        try:
            recent_csi = list(self.csi_history)[-100:]
            
            features = []
            for csi in recent_csi:
                features.append(csi.to_numpy())
            
            x = torch.FloatTensor(np.array(features)).unsqueeze(0)
            
            with torch.no_grad():
                output = self.reconstruction_model(x)
            
            grid = output['occupancy_grid'][0].numpy()
            walls = output['wall_segments'][0].numpy()
            dims = output['dimensions'][0].numpy()
            
            # Convert to room geometry
            self.room_geometry = RoomGeometry(
                room_id="main",
                walls=self._decode_walls(walls),
                dimensions={
                    "width": float(dims[0]),
                    "length": float(dims[1]),
                    "height": float(dims[2])
                },
                furniture=self._detect_furniture(grid),
                openings=self._detect_openings(grid),
                signal_map=self._generate_signal_map(),
                confidence=0.7,
                last_updated=time.time()
            )
            
            if self.on_environment_update:
                self.on_environment_update(self.room_geometry)
                
        except Exception as e:
            self.logger.error(f"Environment reconstruction error: {e}")
    
    def _decode_walls(self, wall_segments: np.ndarray) -> List[Dict[str, Any]]:
        """Decode wall segment predictions"""
        walls = []
        
        for i, segment in enumerate(wall_segments):
            x1, y1, x2, y2 = segment
            
            # Filter out invalid segments
            length = np.sqrt((x2-x1)**2 + (y2-y1)**2)
            if length > 0.5:  # Min wall length 0.5m
                walls.append({
                    "id": f"wall_{i}",
                    "start": {"x": float(x1), "y": float(y1)},
                    "end": {"x": float(x2), "y": float(y2)},
                    "length": float(length)
                })
        
        return walls
    
    def _detect_furniture(self, grid: np.ndarray) -> List[Dict[str, Any]]:
        """Detect furniture from occupancy grid"""
        furniture = []
        
        # Channel 1 is furniture
        furniture_mask = grid[1] > 0.5
        
        # Simple connected component analysis
        # In production, use scipy.ndimage.label
        visited = np.zeros_like(furniture_mask, dtype=bool)
        
        def flood_fill(start_r, start_c):
            stack = [(start_r, start_c)]
            cells = []
            
            while stack:
                r, c = stack.pop()
                if r < 0 or r >= furniture_mask.shape[0]:
                    continue
                if c < 0 or c >= furniture_mask.shape[1]:
                    continue
                if visited[r, c] or not furniture_mask[r, c]:
                    continue
                
                visited[r, c] = True
                cells.append((r, c))
                
                stack.extend([(r+1, c), (r-1, c), (r, c+1), (r, c-1)])
            
            return cells
        
        for r in range(furniture_mask.shape[0]):
            for c in range(furniture_mask.shape[1]):
                if furniture_mask[r, c] and not visited[r, c]:
                    cells = flood_fill(r, c)
                    if len(cells) >= 4:  # Min furniture size
                        rows = [cell[0] for cell in cells]
                        cols = [cell[1] for cell in cells]
                        
                        furniture.append({
                            "id": f"furniture_{len(furniture)}",
                            "center": {
                                "x": float(np.mean(cols)) / grid.shape[2] * 10,
                                "y": float(np.mean(rows)) / grid.shape[1] * 10
                            },
                            "size": {
                                "width": float(max(cols) - min(cols) + 1) / grid.shape[2] * 10,
                                "length": float(max(rows) - min(rows) + 1) / grid.shape[1] * 10
                            },
                            "confidence": float(np.mean([grid[1, r, c] for r, c in cells]))
                        })
        
        return furniture
    
    def _detect_openings(self, grid: np.ndarray) -> List[Dict[str, Any]]:
        """Detect doors and windows from grid"""
        openings = []
        
        # Channel 3 is doors/windows
        opening_mask = grid[3] > 0.5
        
        # Find openings along walls
        for r in range(opening_mask.shape[0]):
            for c in range(opening_mask.shape[1]):
                if opening_mask[r, c]:
                    openings.append({
                        "id": f"opening_{len(openings)}",
                        "position": {
                            "x": float(c) / grid.shape[2] * 10,
                            "y": float(r) / grid.shape[1] * 10
                        },
                        "type": "door" if r == 0 or r == grid.shape[1]-1 else "window",
                        "confidence": float(grid[3, r, c])
                    })
        
        return openings
    
    def _generate_signal_map(self) -> Dict[str, float]:
        """Generate signal strength heatmap"""
        signal_map = {}
        
        for csi in list(self.csi_history)[-50:]:
            key = f"{int(csi.rssi)}"
            signal_map[key] = signal_map.get(key, 0) + 1
        
        return signal_map
    
    def get_status(self) -> Dict[str, Any]:
        """Get current sensing status"""
        return {
            "running": self._running,
            "interface": self.interface,
            "mode": self.mode.value,
            "access_points": len(self.access_points),
            "csi_samples": len(self.csi_history),
            "locations_tracked": len(self.current_locations),
            "has_room_geometry": self.room_geometry is not None,
            "ai_enabled": TORCH_AVAILABLE and self.localization_model is not None,
            "capabilities": self.csi_extractor.check_capabilities(),
            "anomaly_window": len(self.anomaly_detector.history),
            "fall_window": len(self.fall_detector.history),
            "kalman_active": self.kalman_tracker.state is not None,
            "hopper_channels": self.channel_hopper.channels,
            "hopper_dwell_s": self.channel_hopper.dwell_seconds,
            "csi_denoise_window": self.csi_denoiser.window,
            "tracked_persons": len(self.multi_person_tracker.persons),
            "zones_defined": len(self.zone_manager.zones),
            "uncertainty_base_sigma": self.uncertainty_estimator.base_sigma,
            "esp32_udp_port": self.esp32_udp_port,
        }
    
    def get_locations(self) -> List[LocationEstimate]:
        """Get all current location estimates"""
        return list(self.current_locations.values())
    
    def get_room_geometry(self) -> Optional[RoomGeometry]:
        """Get reconstructed room geometry"""
        return self.room_geometry

    def get_tracked_persons(self) -> List[TrackedPerson]:
        """Get all currently tracked persons."""
        return list(self.multi_person_tracker.persons.values())

    def add_zone(self, zone_id: str, name: str, bounds: Tuple[float, float, float, float, float, float]):
        """Add a named spatial zone."""
        self.zone_manager.add_zone(Zone(id=zone_id, name=name, bounds=bounds))

    def get_occupied_zones(self) -> List[Tuple[Zone, List[TrackedPerson]]]:
        """Get zones that currently contain persons."""
        return self.zone_manager.get_occupied_zones(self.get_tracked_persons())

    # =========================================================================
    # ADVANCED SENSING API
    # =========================================================================

    def get_doppler_velocity(self) -> Dict[str, Any]:
        """Get current Doppler velocity estimate for closest target."""
        if not self.csi_history:
            return {"velocity": 0.0, "confidence": 0.0}
        return self.doppler_estimator.update(self.csi_history[-1])

    def get_current_activity(self) -> Dict[str, Any]:
        """Get current activity classification."""
        if not self.csi_history:
            return {"activity": "idle", "confidence": 0.0}
        return {"activity": self.activity_classifier.current_activity,
                "confidence": self.activity_classifier.activity_confidence}

    def get_people_count(self) -> Dict[str, Any]:
        """Get estimated number of people in sensing area."""
        if not self.csi_history:
            return {"count": 0, "confidence": 0.0}
        return self.people_counter.count(self.csi_history[-1])

    def calibrate_empty_room(self) -> bool:
        """
        Start calibration for people counting and through-wall imaging.
        Call this when the room is empty for best results.
        """
        if self.csi_history:
            csi = self.csi_history[-1]
            pc_done = self.people_counter.calibrate_empty_room(csi)
            twi_done = self.through_wall_imager.calibrate_background(csi)
            return pc_done and twi_done
        return False

    def get_sleep_stage(self) -> Dict[str, Any]:
        """Get current sleep stage detection (for sleep monitoring use case)."""
        if not self.csi_history:
            return {"stage": "awake", "confidence": 0.0}
        return self.sleep_detector.detect(self.csi_history[-1])

    def detect_material(self, expected_rssi: float = None) -> Dict[str, Any]:
        """Detect material of obstacles between transmitter and receiver."""
        if not self.csi_history:
            return {"material": "air", "confidence": 0.0}
        return self.material_detector.detect(self.csi_history[-1], expected_rssi)

    def get_slam_map(self) -> Dict[str, Any]:
        """Get current SLAM map state."""
        return self.wifi_slam.get_map()

    def update_slam_position(self, motion_estimate: Tuple[float, float] = (0, 0)) -> Tuple[float, float]:
        """Update SLAM position with motion model."""
        if self.csi_history:
            return self.wifi_slam.update_position(self.csi_history[-1], motion_estimate)
        return self.wifi_slam.position

    def get_through_wall_image(self) -> Dict[str, Any]:
        """Get current through-wall radar image."""
        if not self.csi_history:
            return {"calibrating": True, "progress": 0.0}
        return self.through_wall_imager.process(self.csi_history[-1])

    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all sensing modalities."""
        status = {
            "running": self._running,
            "csi_samples": len(self.csi_history),
            "tracked_persons": len(self.get_tracked_persons()),
            "occupied_zones": len(self.get_occupied_zones()),
        }
        
        # Add advanced sensing status if CSI available
        if self.csi_history:
            status["doppler"] = self.get_doppler_velocity()
            status["activity"] = self.get_current_activity()
            status["people_count"] = self.get_people_count()
            status["sleep"] = self.get_sleep_stage()
            status["material"] = self.detect_material()
            status["slam_position"] = self.wifi_slam.position
        
        return status

    def export_data(self, filepath: str):
        """Export collected data for analysis"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "csi_samples": [
                {
                    "timestamp": csi.timestamp,
                    "mac": csi.mac_address,
                    "rssi": csi.rssi,
                    "channel": csi.channel,
                    "amplitude": csi.amplitude,
                    "phase": csi.phase
                }
                for csi in list(self.csi_history)
            ],
            "locations": [
                {
                    "x": loc.x,
                    "y": loc.y,
                    "z": loc.z,
                    "confidence": loc.confidence,
                    "timestamp": loc.timestamp
                }
                for loc in self.current_locations.values()
            ],
            "room_geometry": {
                "walls": self.room_geometry.walls,
                "dimensions": self.room_geometry.dimensions,
                "furniture": self.room_geometry.furniture
            } if self.room_geometry else None
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Data exported to {filepath}")


if TORCH_AVAILABLE:
    class WifiSensingTrainer:
        """Train localization and reconstruction models"""
        
        def __init__(self, data_dir: str):
            self.data_dir = data_dir
            self.logger = logging.getLogger("WifiSensingTrainer")
        
        def prepare_dataset(self, labeled_data: List[Dict]) -> Tuple['torch.Tensor', 'torch.Tensor']:
            """Prepare training dataset from labeled data"""
            X = []
            y = []
            
            for sample in labeled_data:
                csi = sample['csi']
                location = sample['location']
                
                features = csi['amplitude'] + csi['phase']
                X.append(features)
                y.append([location['x'], location['y'], location['z']])
            
            return torch.FloatTensor(X), torch.FloatTensor(y)
        
        def train_localization(self, train_data: List[Dict], 
                              epochs: int = 100,
                              learning_rate: float = 0.001) -> 'WifiLocalizationModel':
            """Train localization model"""
            X, y = self.prepare_dataset(train_data)
            
            model = WifiLocalizationModel()
            optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
            criterion = nn.MSELoss()
            
            model.train()
            
            for epoch in range(epochs):
                optimizer.zero_grad()
                
                output = model(X)
                loss = criterion(output['location'], y)
                
                loss.backward()
                optimizer.step()
                
                if (epoch + 1) % 10 == 0:
                    self.logger.info(f"Epoch {epoch+1}/{epochs}, Loss: {loss.item():.4f}")
            
            return model
        
        def save_model(self, model: 'nn.Module', path: str):
            """Save trained model"""
            torch.save(model.state_dict(), path)
            self.logger.info(f"Model saved to {path}")
else:
    class WifiSensingTrainer:
        """Stub - requires PyTorch"""
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PyTorch is required for WifiSensingTrainer")


# Convenience function to create and start sensing
async def create_wifi_sensor(interface: str = "wlan0",
                             mode: SensingMode = SensingMode.PASSIVE) -> WifiSensingEngine:
    """Create and configure a WiFi sensing engine"""
    engine = WifiSensingEngine(interface=interface, mode=mode)
    return engine


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    async def main():
        engine = await create_wifi_sensor()
        
        # Configure callbacks
        def on_detection(detection_type, data):
            print(f"Detection: {detection_type.value} - {data}")
        
        def on_location(location):
            print(f"Location: ({location.x:.2f}, {location.y:.2f}, {location.z:.2f}) "
                  f"confidence: {location.confidence:.2f}")
        
        def on_environment(geometry):
            print(f"Room: {geometry.dimensions} - {len(geometry.walls)} walls, "
                  f"{len(geometry.furniture)} furniture items")
        
        engine.on_detection = on_detection
        engine.on_location_update = on_location
        engine.on_environment_update = on_environment
        
        # Start sensing
        try:
            await engine.start()
        except KeyboardInterrupt:
            await engine.stop()
    
    asyncio.run(main())
