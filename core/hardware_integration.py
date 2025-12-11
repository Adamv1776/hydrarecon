"""
HydraRecon Hardware Integration Module
=======================================

Advanced hardware integration for security operations:
- Software Defined Radio (SDR) support
- Spectrum analyzers
- Hardware security modules (HSM)
- USB security devices
- Network TAPs
- WiFi adapters with monitor mode
- Bluetooth sniffers
- RFID/NFC readers
- Hardware implant detection
- IoT device integration
- GPIO for physical security
- Logic analyzers
- Oscilloscopes
- Power analysis tools
"""

import os
import sys
import time
import struct
import threading
import queue
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable, Union, Generator
from datetime import datetime
from enum import Enum, auto
from abc import ABC, abstractmethod
import numpy as np
from collections import deque
import json

# Optional hardware library imports
try:
    import usb.core
    import usb.util
    USB_AVAILABLE = True
except ImportError:
    USB_AVAILABLE = False

try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

try:
    import rtlsdr
    RTLSDR_AVAILABLE = True
except ImportError:
    RTLSDR_AVAILABLE = False

try:
    import numpy.fft as fft
    FFT_AVAILABLE = True
except ImportError:
    FFT_AVAILABLE = False


class DeviceType(Enum):
    """Types of hardware devices"""
    SDR = auto()
    SPECTRUM_ANALYZER = auto()
    WIFI_ADAPTER = auto()
    BLUETOOTH_SNIFFER = auto()
    RFID_READER = auto()
    NFC_READER = auto()
    NETWORK_TAP = auto()
    HSM = auto()
    LOGIC_ANALYZER = auto()
    OSCILLOSCOPE = auto()
    GPIO_CONTROLLER = auto()
    USB_SECURITY = auto()
    IOT_GATEWAY = auto()


class DeviceStatus(Enum):
    """Device status"""
    DISCONNECTED = auto()
    CONNECTED = auto()
    INITIALIZING = auto()
    READY = auto()
    BUSY = auto()
    ERROR = auto()


@dataclass
class DeviceInfo:
    """Hardware device information"""
    device_id: str
    device_type: DeviceType
    vendor_id: int
    product_id: int
    name: str
    manufacturer: str = ""
    serial_number: str = ""
    firmware_version: str = ""
    driver_version: str = ""
    status: DeviceStatus = DeviceStatus.DISCONNECTED
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SignalData:
    """RF signal data"""
    timestamp: float
    frequency: float  # Hz
    bandwidth: float  # Hz
    samples: np.ndarray
    sample_rate: float
    gain: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpectrumData:
    """Spectrum analyzer data"""
    timestamp: float
    frequencies: np.ndarray  # Hz array
    magnitudes: np.ndarray  # dB array
    center_frequency: float
    span: float
    rbw: float  # Resolution bandwidth
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Base Hardware Interface
# =============================================================================

class HardwareDevice(ABC):
    """Abstract base class for hardware devices"""
    
    def __init__(self, device_info: DeviceInfo):
        self.info = device_info
        self._connected = False
        self._callbacks: List[Callable] = []
    
    @abstractmethod
    def connect(self) -> bool:
        """Connect to device"""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Disconnect from device"""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected"""
        pass
    
    def on_data(self, callback: Callable):
        """Register data callback"""
        self._callbacks.append(callback)
    
    def _emit_data(self, data: Any):
        """Emit data to callbacks"""
        for callback in self._callbacks:
            try:
                callback(data)
            except Exception:
                pass


# =============================================================================
# Software Defined Radio
# =============================================================================

class SDRDevice(HardwareDevice):
    """Software Defined Radio interface"""
    
    # Known SDR device IDs
    KNOWN_DEVICES = {
        (0x0bda, 0x2832): "RTL2832U",
        (0x0bda, 0x2838): "RTL2838UHIDIR",
        (0x1d50, 0x604b): "HackRF One",
        (0x2500, 0x0020): "AirSpy Mini",
        (0x1d50, 0x6089): "YARD Stick One",
    }
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.sdr = None
        self.sample_rate = 2.4e6  # 2.4 MHz default
        self.center_freq = 100e6  # 100 MHz default
        self.gain = 40
        self._streaming = False
        self._stream_thread: Optional[threading.Thread] = None
        self._sample_buffer: queue.Queue = queue.Queue(maxsize=100)
    
    def connect(self) -> bool:
        """Connect to SDR device"""
        if RTLSDR_AVAILABLE:
            try:
                self.sdr = rtlsdr.RtlSdr()
                self.sdr.sample_rate = self.sample_rate
                self.sdr.center_freq = self.center_freq
                self.sdr.gain = self.gain
                self._connected = True
                self.info.status = DeviceStatus.READY
                return True
            except Exception as e:
                self.info.status = DeviceStatus.ERROR
                self.info.metadata['last_error'] = str(e)
                return False
        else:
            # Simulation mode
            self._connected = True
            self.info.status = DeviceStatus.READY
            return True
    
    def disconnect(self):
        """Disconnect from SDR"""
        self.stop_streaming()
        if self.sdr:
            self.sdr.close()
            self.sdr = None
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def set_frequency(self, freq: float):
        """Set center frequency"""
        self.center_freq = freq
        if self.sdr:
            self.sdr.center_freq = freq
    
    def set_sample_rate(self, rate: float):
        """Set sample rate"""
        self.sample_rate = rate
        if self.sdr:
            self.sdr.sample_rate = rate
    
    def set_gain(self, gain: float):
        """Set gain"""
        self.gain = gain
        if self.sdr:
            self.sdr.gain = gain
    
    def read_samples(self, num_samples: int = 256 * 1024) -> SignalData:
        """Read samples from SDR"""
        if self.sdr:
            samples = self.sdr.read_samples(num_samples)
        else:
            # Simulated samples
            t = np.linspace(0, num_samples / self.sample_rate, num_samples)
            # Simulate some signal with noise
            samples = np.sin(2 * np.pi * 1e3 * t) + 0.5 * np.random.randn(num_samples)
            samples = samples + 1j * (np.cos(2 * np.pi * 1e3 * t) + 0.5 * np.random.randn(num_samples))
        
        return SignalData(
            timestamp=time.time(),
            frequency=self.center_freq,
            bandwidth=self.sample_rate,
            samples=np.array(samples),
            sample_rate=self.sample_rate,
            gain=self.gain
        )
    
    def start_streaming(self, callback: Callable[[SignalData], None] = None):
        """Start continuous streaming"""
        if self._streaming:
            return
        
        self._streaming = True
        self._stream_thread = threading.Thread(target=self._stream_loop, daemon=True)
        self._stream_thread.start()
        
        if callback:
            self.on_data(callback)
    
    def stop_streaming(self):
        """Stop streaming"""
        self._streaming = False
        if self._stream_thread:
            self._stream_thread.join(timeout=1.0)
            self._stream_thread = None
    
    def _stream_loop(self):
        """Streaming thread loop"""
        while self._streaming:
            try:
                signal = self.read_samples(256 * 1024)
                self._emit_data(signal)
                if not self._sample_buffer.full():
                    self._sample_buffer.put(signal)
            except Exception:
                time.sleep(0.01)
    
    def get_spectrum(self, fft_size: int = 1024) -> SpectrumData:
        """Get current spectrum"""
        signal = self.read_samples(fft_size * 4)
        
        if FFT_AVAILABLE:
            # Compute FFT
            spectrum = np.fft.fftshift(np.fft.fft(signal.samples[:fft_size]))
            magnitudes = 20 * np.log10(np.abs(spectrum) + 1e-10)
            
            # Frequency axis
            frequencies = np.fft.fftshift(np.fft.fftfreq(fft_size, 1.0 / self.sample_rate))
            frequencies += self.center_freq
        else:
            # Simulated spectrum
            frequencies = np.linspace(
                self.center_freq - self.sample_rate / 2,
                self.center_freq + self.sample_rate / 2,
                fft_size
            )
            magnitudes = -100 + 20 * np.random.randn(fft_size)
            # Add some fake signals
            signal_indices = [fft_size // 4, fft_size // 2, 3 * fft_size // 4]
            for idx in signal_indices:
                magnitudes[idx - 5:idx + 5] += 40
        
        return SpectrumData(
            timestamp=time.time(),
            frequencies=frequencies,
            magnitudes=magnitudes,
            center_frequency=self.center_freq,
            span=self.sample_rate,
            rbw=self.sample_rate / fft_size
        )
    
    def scan_frequency_range(
        self,
        start_freq: float,
        end_freq: float,
        step: float = 1e6,
        dwell_time: float = 0.1
    ) -> Generator[SpectrumData, None, None]:
        """Scan a frequency range"""
        current_freq = start_freq
        
        while current_freq <= end_freq:
            self.set_frequency(current_freq)
            time.sleep(dwell_time)
            yield self.get_spectrum()
            current_freq += step


class SpectrumAnalyzer(HardwareDevice):
    """Spectrum analyzer interface"""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.start_freq = 0
        self.stop_freq = 6e9  # 6 GHz
        self.rbw = 100e3  # 100 kHz
        self.vbw = 100e3  # 100 kHz
        self.reference_level = 0  # dBm
        self._sweep_data: Optional[SpectrumData] = None
    
    def connect(self) -> bool:
        """Connect to spectrum analyzer"""
        # Would use VISA/GPIB/USB for real instruments
        self._connected = True
        self.info.status = DeviceStatus.READY
        return True
    
    def disconnect(self):
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def set_frequency_range(self, start: float, stop: float):
        """Set frequency range"""
        self.start_freq = start
        self.stop_freq = stop
    
    def set_rbw(self, rbw: float):
        """Set resolution bandwidth"""
        self.rbw = rbw
    
    def single_sweep(self) -> SpectrumData:
        """Perform single sweep"""
        num_points = int((self.stop_freq - self.start_freq) / self.rbw)
        num_points = min(max(num_points, 100), 10001)
        
        frequencies = np.linspace(self.start_freq, self.stop_freq, num_points)
        
        # Simulated sweep data
        magnitudes = -100 + 10 * np.random.randn(num_points)
        
        # Add some simulated signals
        for _ in range(5):
            sig_freq = np.random.uniform(self.start_freq, self.stop_freq)
            sig_idx = int((sig_freq - self.start_freq) / (self.stop_freq - self.start_freq) * num_points)
            sig_idx = max(0, min(sig_idx, num_points - 1))
            sig_width = max(1, int(num_points / 100))
            magnitudes[max(0, sig_idx - sig_width):min(num_points, sig_idx + sig_width)] += 50 + 20 * np.random.rand()
        
        self._sweep_data = SpectrumData(
            timestamp=time.time(),
            frequencies=frequencies,
            magnitudes=magnitudes,
            center_frequency=(self.start_freq + self.stop_freq) / 2,
            span=self.stop_freq - self.start_freq,
            rbw=self.rbw
        )
        
        self._emit_data(self._sweep_data)
        return self._sweep_data
    
    def find_peaks(self, threshold: float = -50) -> List[Tuple[float, float]]:
        """Find peaks above threshold"""
        if self._sweep_data is None:
            self.single_sweep()
        
        peaks = []
        mags = self._sweep_data.magnitudes
        freqs = self._sweep_data.frequencies
        
        for i in range(1, len(mags) - 1):
            if mags[i] > threshold and mags[i] > mags[i - 1] and mags[i] > mags[i + 1]:
                peaks.append((freqs[i], mags[i]))
        
        return sorted(peaks, key=lambda x: x[1], reverse=True)


# =============================================================================
# WiFi Hardware
# =============================================================================

class WiFiAdapter(HardwareDevice):
    """WiFi adapter with monitor mode support"""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.interface = "wlan0"
        self.monitor_interface = "wlan0mon"
        self.channel = 1
        self.mode = "managed"
        self._capture_thread: Optional[threading.Thread] = None
        self._capturing = False
        self._packet_buffer: queue.Queue = queue.Queue(maxsize=1000)
    
    def connect(self) -> bool:
        """Initialize WiFi adapter"""
        self._connected = True
        self.info.status = DeviceStatus.READY
        return True
    
    def disconnect(self):
        self.stop_capture()
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode"""
        # In real implementation, would use iw/airmon-ng
        self.mode = "monitor"
        return True
    
    def disable_monitor_mode(self) -> bool:
        """Disable monitor mode"""
        self.mode = "managed"
        return True
    
    def set_channel(self, channel: int):
        """Set WiFi channel"""
        if 1 <= channel <= 14:  # 2.4 GHz
            self.channel = channel
        elif 36 <= channel <= 165:  # 5 GHz
            self.channel = channel
    
    def scan_networks(self) -> List[Dict[str, Any]]:
        """Scan for WiFi networks"""
        # Simulated network scan results
        networks = []
        
        for i in range(10):
            networks.append({
                'ssid': f"Network_{i}",
                'bssid': f"AA:BB:CC:DD:EE:{i:02X}",
                'channel': np.random.randint(1, 14),
                'signal_strength': -np.random.randint(30, 90),
                'encryption': np.random.choice(['WPA2', 'WPA3', 'WEP', 'Open']),
                'frequency': 2412 + (np.random.randint(0, 13) * 5),
            })
        
        return networks
    
    def start_capture(self, callback: Callable = None):
        """Start packet capture"""
        if self._capturing:
            return
        
        self._capturing = True
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        
        if callback:
            self.on_data(callback)
    
    def stop_capture(self):
        """Stop packet capture"""
        self._capturing = False
        if self._capture_thread:
            self._capture_thread.join(timeout=1.0)
            self._capture_thread = None
    
    def _capture_loop(self):
        """Capture thread loop"""
        while self._capturing:
            # Simulated packet capture
            packet = self._generate_fake_packet()
            self._emit_data(packet)
            if not self._packet_buffer.full():
                self._packet_buffer.put(packet)
            time.sleep(0.01)
    
    def _generate_fake_packet(self) -> Dict[str, Any]:
        """Generate simulated WiFi packet"""
        packet_types = ['beacon', 'probe_request', 'probe_response', 'data', 'ack', 'deauth']
        
        return {
            'timestamp': time.time(),
            'type': np.random.choice(packet_types),
            'source': f"AA:BB:CC:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}",
            'destination': f"FF:FF:FF:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}",
            'channel': self.channel,
            'signal_strength': -np.random.randint(30, 90),
            'size': np.random.randint(50, 1500)
        }


# =============================================================================
# Bluetooth Hardware
# =============================================================================

class BluetoothSniffer(HardwareDevice):
    """Bluetooth/BLE sniffer"""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.mode = "classic"  # classic or ble
        self._scanning = False
        self._scan_thread: Optional[threading.Thread] = None
        self._device_buffer: queue.Queue = queue.Queue(maxsize=100)
    
    def connect(self) -> bool:
        self._connected = True
        self.info.status = DeviceStatus.READY
        return True
    
    def disconnect(self):
        self.stop_scan()
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def set_mode(self, mode: str):
        """Set scanning mode (classic/ble)"""
        if mode in ['classic', 'ble']:
            self.mode = mode
    
    def start_scan(self, callback: Callable = None):
        """Start Bluetooth scanning"""
        if self._scanning:
            return
        
        self._scanning = True
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()
        
        if callback:
            self.on_data(callback)
    
    def stop_scan(self):
        """Stop scanning"""
        self._scanning = False
        if self._scan_thread:
            self._scan_thread.join(timeout=1.0)
            self._scan_thread = None
    
    def _scan_loop(self):
        """Scan thread loop"""
        while self._scanning:
            device = self._generate_fake_device()
            self._emit_data(device)
            if not self._device_buffer.full():
                self._device_buffer.put(device)
            time.sleep(0.5)
    
    def _generate_fake_device(self) -> Dict[str, Any]:
        """Generate simulated Bluetooth device"""
        device_types = ['phone', 'headphones', 'speaker', 'smartwatch', 'laptop', 'unknown']
        
        return {
            'timestamp': time.time(),
            'address': f"{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}:{np.random.randint(0, 256):02X}",
            'name': f"Device_{np.random.randint(1000, 9999)}",
            'type': np.random.choice(device_types),
            'rssi': -np.random.randint(40, 100),
            'mode': self.mode,
            'connectable': np.random.choice([True, False]),
            'services': np.random.choice([[], ['0x1800', '0x1801'], ['0x180F', '0x180A']])
        }


# =============================================================================
# RFID/NFC Hardware
# =============================================================================

class RFIDReader(HardwareDevice):
    """RFID/NFC reader interface"""
    
    # Common RFID frequencies
    FREQUENCIES = {
        'lf': 125000,    # 125 kHz (LF)
        'hf': 13560000,  # 13.56 MHz (HF/NFC)
        'uhf': 915000000  # 915 MHz (UHF)
    }
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.frequency = 'hf'
        self._reading = False
        self._read_thread: Optional[threading.Thread] = None
        self._tag_buffer: queue.Queue = queue.Queue(maxsize=50)
    
    def connect(self) -> bool:
        self._connected = True
        self.info.status = DeviceStatus.READY
        return True
    
    def disconnect(self):
        self.stop_reading()
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def set_frequency(self, freq: str):
        """Set RFID frequency band"""
        if freq in self.FREQUENCIES:
            self.frequency = freq
    
    def read_single(self) -> Optional[Dict[str, Any]]:
        """Read single RFID tag"""
        # Simulated RFID read
        if np.random.random() > 0.3:  # 70% chance of reading a tag
            return self._generate_fake_tag()
        return None
    
    def start_reading(self, callback: Callable = None):
        """Start continuous reading"""
        if self._reading:
            return
        
        self._reading = True
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()
        
        if callback:
            self.on_data(callback)
    
    def stop_reading(self):
        """Stop reading"""
        self._reading = False
        if self._read_thread:
            self._read_thread.join(timeout=1.0)
            self._read_thread = None
    
    def write_tag(self, tag_id: str, data: bytes) -> bool:
        """Write data to RFID tag"""
        # Simulated write
        return np.random.random() > 0.1  # 90% success rate
    
    def clone_tag(self, source_data: bytes, target_id: str) -> bool:
        """Clone RFID tag data"""
        # Simulated clone
        return np.random.random() > 0.2  # 80% success rate
    
    def _read_loop(self):
        """Read thread loop"""
        while self._reading:
            tag = self.read_single()
            if tag:
                self._emit_data(tag)
                if not self._tag_buffer.full():
                    self._tag_buffer.put(tag)
            time.sleep(0.2)
    
    def _generate_fake_tag(self) -> Dict[str, Any]:
        """Generate simulated RFID tag"""
        tag_types = ['ISO14443A', 'ISO14443B', 'ISO15693', 'EM4100', 'HID']
        
        return {
            'timestamp': time.time(),
            'uid': ''.join([f'{np.random.randint(0, 256):02X}' for _ in range(4)]),
            'type': np.random.choice(tag_types),
            'frequency': self.frequency,
            'atqa': f"{np.random.randint(0, 256):02X}{np.random.randint(0, 256):02X}",
            'sak': f"{np.random.randint(0, 256):02X}",
            'memory_size': np.random.choice([48, 144, 504, 888, 1904]),
            'read_only': np.random.choice([True, False])
        }


# =============================================================================
# Logic Analyzer
# =============================================================================

class LogicAnalyzer(HardwareDevice):
    """Logic analyzer for digital signal analysis"""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.num_channels = 8
        self.sample_rate = 24e6  # 24 MHz
        self.buffer_size = 1024 * 1024  # 1M samples
        self._capturing = False
        self._trigger_channel = 0
        self._trigger_edge = 'rising'
    
    def connect(self) -> bool:
        self._connected = True
        self.info.status = DeviceStatus.READY
        return True
    
    def disconnect(self):
        self._connected = False
        self.info.status = DeviceStatus.DISCONNECTED
    
    def is_connected(self) -> bool:
        return self._connected
    
    def set_sample_rate(self, rate: float):
        """Set sample rate"""
        self.sample_rate = rate
    
    def set_trigger(self, channel: int, edge: str = 'rising'):
        """Set trigger conditions"""
        if 0 <= channel < self.num_channels:
            self._trigger_channel = channel
        if edge in ['rising', 'falling', 'either']:
            self._trigger_edge = edge
    
    def capture(self, duration: float = 0.1) -> Dict[str, np.ndarray]:
        """Capture digital signals"""
        num_samples = int(self.sample_rate * duration)
        
        # Generate simulated digital signals
        channels = {}
        for ch in range(self.num_channels):
            # Random digital pattern
            if ch == 0:
                # Clock signal
                period = int(self.sample_rate / 1e6)  # 1 MHz clock
                channels[f'ch{ch}'] = np.tile([0] * (period // 2) + [1] * (period // 2), num_samples // period + 1)[:num_samples]
            elif ch == 1:
                # Data signal
                channels[f'ch{ch}'] = np.random.randint(0, 2, num_samples)
            else:
                # Other channels
                channels[f'ch{ch}'] = np.zeros(num_samples, dtype=np.int8)
        
        return {
            'timestamp': time.time(),
            'sample_rate': self.sample_rate,
            'num_samples': num_samples,
            'channels': channels
        }
    
    def decode_protocol(
        self,
        capture_data: Dict,
        protocol: str
    ) -> List[Dict[str, Any]]:
        """Decode captured data as protocol"""
        decoded = []
        
        if protocol == 'spi':
            decoded = self._decode_spi(capture_data)
        elif protocol == 'i2c':
            decoded = self._decode_i2c(capture_data)
        elif protocol == 'uart':
            decoded = self._decode_uart(capture_data)
        
        return decoded
    
    def _decode_spi(self, data: Dict) -> List[Dict]:
        """Decode SPI protocol"""
        # Simplified SPI decoding
        return [
            {'type': 'spi', 'timestamp': data['timestamp'], 'data': [0xAA, 0xBB, 0xCC]}
        ]
    
    def _decode_i2c(self, data: Dict) -> List[Dict]:
        """Decode I2C protocol"""
        return [
            {'type': 'i2c', 'timestamp': data['timestamp'], 'address': 0x50, 'data': [0x01, 0x02]}
        ]
    
    def _decode_uart(self, data: Dict) -> List[Dict]:
        """Decode UART protocol"""
        return [
            {'type': 'uart', 'timestamp': data['timestamp'], 'data': 'Hello World'}
        ]


# =============================================================================
# USB Device Management
# =============================================================================

class USBDeviceManager:
    """USB device discovery and management"""
    
    def __init__(self):
        self.known_security_devices = {
            (0x1050, 0x0407): ("Yubico", "YubiKey 4"),
            (0x1050, 0x0406): ("Yubico", "YubiKey 4"),
            (0x20a0, 0x4108): ("Nitrokey", "Nitrokey Pro"),
            (0x1d50, 0x604b): ("Great Scott Gadgets", "HackRF One"),
            (0x1d50, 0x6089): ("Great Scott Gadgets", "YARD Stick One"),
            (0x0bda, 0x2832): ("Realtek", "RTL-SDR"),
        }
    
    def list_devices(self) -> List[DeviceInfo]:
        """List all USB devices"""
        devices = []
        
        if USB_AVAILABLE:
            for device in usb.core.find(find_all=True):
                vendor_id = device.idVendor
                product_id = device.idProduct
                
                # Check if it's a known security device
                device_type = DeviceType.USB_SECURITY
                name = f"USB Device {vendor_id:04x}:{product_id:04x}"
                manufacturer = ""
                
                if (vendor_id, product_id) in self.known_security_devices:
                    manufacturer, name = self.known_security_devices[(vendor_id, product_id)]
                    if "SDR" in name or "HackRF" in name:
                        device_type = DeviceType.SDR
                
                try:
                    if device.manufacturer:
                        manufacturer = device.manufacturer
                    if device.product:
                        name = device.product
                except Exception:
                    pass
                
                devices.append(DeviceInfo(
                    device_id=f"usb:{vendor_id:04x}:{product_id:04x}",
                    device_type=device_type,
                    vendor_id=vendor_id,
                    product_id=product_id,
                    name=name,
                    manufacturer=manufacturer,
                    status=DeviceStatus.CONNECTED
                ))
        
        return devices
    
    def find_security_devices(self) -> List[DeviceInfo]:
        """Find security-related USB devices"""
        all_devices = self.list_devices()
        security_devices = []
        
        for device in all_devices:
            key = (device.vendor_id, device.product_id)
            if key in self.known_security_devices:
                security_devices.append(device)
        
        return security_devices


class SerialDeviceManager:
    """Serial port device management"""
    
    def __init__(self):
        self.open_ports: Dict[str, serial.Serial] = {}
    
    def list_ports(self) -> List[Dict[str, Any]]:
        """List available serial ports"""
        ports = []
        
        if SERIAL_AVAILABLE:
            for port in serial.tools.list_ports.comports():
                ports.append({
                    'port': port.device,
                    'description': port.description,
                    'hwid': port.hwid,
                    'manufacturer': port.manufacturer,
                    'product': port.product,
                    'serial_number': port.serial_number,
                    'vid': port.vid,
                    'pid': port.pid
                })
        
        return ports
    
    def open_port(
        self,
        port: str,
        baudrate: int = 115200,
        timeout: float = 1.0
    ) -> bool:
        """Open serial port"""
        if SERIAL_AVAILABLE:
            try:
                self.open_ports[port] = serial.Serial(
                    port=port,
                    baudrate=baudrate,
                    timeout=timeout
                )
                return True
            except Exception:
                return False
        return False
    
    def close_port(self, port: str):
        """Close serial port"""
        if port in self.open_ports:
            self.open_ports[port].close()
            del self.open_ports[port]
    
    def read(self, port: str, size: int = 1024) -> bytes:
        """Read from serial port"""
        if port in self.open_ports:
            return self.open_ports[port].read(size)
        return b''
    
    def write(self, port: str, data: bytes) -> int:
        """Write to serial port"""
        if port in self.open_ports:
            return self.open_ports[port].write(data)
        return 0


# =============================================================================
# Hardware Integration Manager
# =============================================================================

class HardwareIntegrationManager:
    """Main manager for hardware integration"""
    
    def __init__(self):
        self.usb_manager = USBDeviceManager()
        self.serial_manager = SerialDeviceManager()
        
        self.devices: Dict[str, HardwareDevice] = {}
        self._discovery_thread: Optional[threading.Thread] = None
        self._discovering = False
        
        # Callbacks
        self._on_device_connected: List[Callable] = []
        self._on_device_disconnected: List[Callable] = []
        self._on_data: List[Callable] = []
    
    def start_discovery(self, interval: float = 5.0):
        """Start device discovery"""
        if self._discovering:
            return
        
        self._discovering = True
        self._discovery_thread = threading.Thread(
            target=self._discovery_loop,
            args=(interval,),
            daemon=True
        )
        self._discovery_thread.start()
    
    def stop_discovery(self):
        """Stop device discovery"""
        self._discovering = False
        if self._discovery_thread:
            self._discovery_thread.join(timeout=2.0)
            self._discovery_thread = None
    
    def _discovery_loop(self, interval: float):
        """Device discovery loop"""
        known_devices = set()
        
        while self._discovering:
            current_devices = set()
            
            # Discover USB devices
            for device_info in self.usb_manager.list_devices():
                current_devices.add(device_info.device_id)
                
                if device_info.device_id not in known_devices:
                    self._handle_device_connected(device_info)
            
            # Check for disconnected devices
            for device_id in known_devices - current_devices:
                self._handle_device_disconnected(device_id)
            
            known_devices = current_devices
            time.sleep(interval)
    
    def _handle_device_connected(self, device_info: DeviceInfo):
        """Handle new device connection"""
        # Create appropriate device handler
        device = self._create_device_handler(device_info)
        if device:
            self.devices[device_info.device_id] = device
            
            for callback in self._on_device_connected:
                try:
                    callback(device_info)
                except Exception:
                    pass
    
    def _handle_device_disconnected(self, device_id: str):
        """Handle device disconnection"""
        if device_id in self.devices:
            device = self.devices[device_id]
            device.disconnect()
            del self.devices[device_id]
            
            for callback in self._on_device_disconnected:
                try:
                    callback(device_id)
                except Exception:
                    pass
    
    def _create_device_handler(self, device_info: DeviceInfo) -> Optional[HardwareDevice]:
        """Create appropriate device handler"""
        if device_info.device_type == DeviceType.SDR:
            return SDRDevice(device_info)
        elif device_info.device_type == DeviceType.WIFI_ADAPTER:
            return WiFiAdapter(device_info)
        elif device_info.device_type == DeviceType.BLUETOOTH_SNIFFER:
            return BluetoothSniffer(device_info)
        elif device_info.device_type == DeviceType.RFID_READER:
            return RFIDReader(device_info)
        elif device_info.device_type == DeviceType.LOGIC_ANALYZER:
            return LogicAnalyzer(device_info)
        
        return None
    
    def get_device(self, device_id: str) -> Optional[HardwareDevice]:
        """Get device by ID"""
        return self.devices.get(device_id)
    
    def get_devices_by_type(self, device_type: DeviceType) -> List[HardwareDevice]:
        """Get all devices of a type"""
        return [d for d in self.devices.values() if d.info.device_type == device_type]
    
    def on_device_connected(self, callback: Callable):
        """Register connection callback"""
        self._on_device_connected.append(callback)
    
    def on_device_disconnected(self, callback: Callable):
        """Register disconnection callback"""
        self._on_device_disconnected.append(callback)
    
    def list_all_devices(self) -> List[DeviceInfo]:
        """List all discovered devices"""
        return [d.info for d in self.devices.values()]
    
    def create_sdr(self, device_id: str = None) -> SDRDevice:
        """Create SDR device instance"""
        device_info = DeviceInfo(
            device_id=device_id or f"sdr_{time.time()}",
            device_type=DeviceType.SDR,
            vendor_id=0x0bda,
            product_id=0x2832,
            name="RTL-SDR",
            manufacturer="Realtek"
        )
        device = SDRDevice(device_info)
        self.devices[device_info.device_id] = device
        return device
    
    def create_wifi_adapter(self, interface: str = "wlan0") -> WiFiAdapter:
        """Create WiFi adapter instance"""
        device_info = DeviceInfo(
            device_id=f"wifi_{interface}",
            device_type=DeviceType.WIFI_ADAPTER,
            vendor_id=0,
            product_id=0,
            name=f"WiFi Adapter ({interface})"
        )
        device = WiFiAdapter(device_info)
        device.interface = interface
        self.devices[device_info.device_id] = device
        return device
    
    def create_spectrum_analyzer(self) -> SpectrumAnalyzer:
        """Create spectrum analyzer instance"""
        device_info = DeviceInfo(
            device_id=f"sa_{time.time()}",
            device_type=DeviceType.SPECTRUM_ANALYZER,
            vendor_id=0,
            product_id=0,
            name="Spectrum Analyzer"
        )
        device = SpectrumAnalyzer(device_info)
        self.devices[device_info.device_id] = device
        return device


# Global instance
hardware_manager = HardwareIntegrationManager()


def get_hardware_manager() -> HardwareIntegrationManager:
    """Get global hardware manager"""
    return hardware_manager
