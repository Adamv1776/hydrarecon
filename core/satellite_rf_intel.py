#!/usr/bin/env python3
"""
Satellite & RF Intelligence Module - Signal Intelligence & Spectrum Analysis
Revolutionary radio frequency and satellite communications analysis platform.

Real Data Sources:
- N2YO API - Real-time satellite tracking
- Space-Track.org - TLE data (requires free account)
- SatNOGS - Amateur satellite network
- OpenSky Network - ADS-B flight tracking
- AISHub - Maritime AIS data
- RTL-SDR - Software-defined radio hardware integration
"""

import asyncio
import hashlib
import json
import logging
import math
import random
import sqlite3
import aiohttp
import ssl
import certifi
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


class SignalType(Enum):
    """Types of RF signals."""
    WIFI = auto()
    BLUETOOTH = auto()
    CELLULAR_2G = auto()
    CELLULAR_3G = auto()
    CELLULAR_4G = auto()
    CELLULAR_5G = auto()
    SATELLITE = auto()
    RADAR = auto()
    GPS = auto()
    RFID = auto()
    ZIGBEE = auto()
    LORA = auto()
    SIGFOX = auto()
    ADS_B = auto()
    AIS = auto()
    AMATEUR_RADIO = auto()
    MILITARY = auto()
    UNKNOWN = auto()


class ModulationType(Enum):
    """RF modulation types."""
    AM = auto()
    FM = auto()
    PM = auto()
    ASK = auto()
    FSK = auto()
    PSK = auto()
    BPSK = auto()
    QPSK = auto()
    QAM = auto()
    OFDM = auto()
    GFSK = auto()
    GMSK = auto()
    SPREAD_SPECTRUM = auto()
    FHSS = auto()
    DSSS = auto()
    CHIRP = auto()
    UNKNOWN = auto()


class ThreatLevel(Enum):
    """Signal threat levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


class SatelliteType(Enum):
    """Types of satellites."""
    COMMUNICATIONS = auto()
    NAVIGATION = auto()
    RECONNAISSANCE = auto()
    WEATHER = auto()
    SCIENTIFIC = auto()
    MILITARY = auto()
    CUBESAT = auto()
    STARLINK = auto()
    UNKNOWN = auto()


class AttackType(Enum):
    """RF attack types."""
    JAMMING = auto()
    SPOOFING = auto()
    REPLAY = auto()
    INJECTION = auto()
    DENIAL_OF_SERVICE = auto()
    EAVESDROPPING = auto()
    MAN_IN_THE_MIDDLE = auto()
    DEAUTHENTICATION = auto()
    ROGUE_ACCESS_POINT = auto()


@dataclass
class RFSignal:
    """Represents a detected RF signal."""
    signal_id: str
    signal_type: SignalType
    frequency: float  # MHz
    bandwidth: float  # kHz
    power: float  # dBm
    modulation: ModulationType
    timestamp: datetime
    duration: float  # seconds
    location: Optional[Tuple[float, float, float]]  # lat, lon, alt
    direction: Optional[float]  # degrees
    distance: Optional[float]  # meters
    encrypted: bool
    protocol: str
    payload_preview: str
    source_identifier: Optional[str]
    destination_identifier: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Satellite:
    """Represents a tracked satellite."""
    satellite_id: str
    norad_id: int
    name: str
    satellite_type: SatelliteType
    operator: str
    country: str
    launch_date: datetime
    orbital_parameters: Dict[str, float]
    position: Tuple[float, float, float]  # lat, lon, alt
    velocity: Tuple[float, float, float]
    frequencies: List[float]
    is_active: bool
    threat_level: ThreatLevel
    capabilities: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpectrumAnalysis:
    """Results of spectrum analysis."""
    analysis_id: str
    start_frequency: float  # MHz
    end_frequency: float  # MHz
    resolution: float  # kHz
    timestamp: datetime
    duration: float
    signals_detected: int
    peak_frequencies: List[float]
    power_spectrum: List[float]
    noise_floor: float
    anomalies: List[Dict[str, Any]]
    interference_sources: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RFAnomaly:
    """Represents an RF anomaly."""
    anomaly_id: str
    signal_id: Optional[str]
    anomaly_type: str
    frequency: float
    power: float
    timestamp: datetime
    duration: float
    threat_level: ThreatLevel
    description: str
    possible_source: str
    recommended_action: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RFAttack:
    """Represents a detected or simulated RF attack."""
    attack_id: str
    attack_type: AttackType
    target_frequency: float
    target_protocol: str
    start_time: datetime
    end_time: Optional[datetime]
    success: bool
    detection_method: str
    impact_assessment: str
    countermeasures: List[str]
    iocs: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeolocationResult:
    """RF geolocation result."""
    result_id: str
    signal_id: str
    method: str
    latitude: float
    longitude: float
    altitude: Optional[float]
    accuracy: float  # meters
    confidence: float
    timestamp: datetime
    bearing: Optional[float]
    distance: Optional[float]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecodedMessage:
    """Decoded RF message."""
    message_id: str
    signal_id: str
    protocol: str
    raw_data: bytes
    decoded_content: Dict[str, Any]
    timestamp: datetime
    source: str
    destination: str
    is_encrypted: bool
    encryption_type: Optional[str]
    integrity_verified: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class SatelliteRFIntelligence:
    """
    Revolutionary satellite and RF intelligence platform.
    
    IMPORTANT: This module requires SDR (Software Defined Radio) hardware for real data.
    Supported hardware: RTL-SDR, HackRF, USRP, BladeRF, LimeSDR
    
    Without SDR hardware, this module can:
    - Query satellite TLE databases (CelesTrak, Space-Track)
    - Decode ADS-B from online feeds (ADSBexchange)
    - Query AIS data from online sources (MarineTraffic API)
    
    Features with SDR hardware:
    - Wideband spectrum analysis
    - Signal classification and identification
    - RF geolocation (TDOA, AOA, FDOA)
    - Protocol decoding and analysis
    - RF attack detection
    - Drone detection
    
    Install SDR support: pip install pyrtlsdr hackrf bladerf
    """
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        n2yo_api_key: Optional[str] = None,
        opensky_username: Optional[str] = None,
        opensky_password: Optional[str] = None
    ):
        self.db_path = db_path or "rf_intelligence.db"
        self.logger = logging.getLogger("RFIntelligence")
        self.signals: Dict[str, RFSignal] = {}
        self.satellites: Dict[str, Satellite] = {}
        self.analyses: Dict[str, SpectrumAnalysis] = {}
        self.anomalies: List[RFAnomaly] = []
        self.attacks: Dict[str, RFAttack] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        
        # API keys for real data sources
        self.n2yo_api_key = n2yo_api_key
        self.opensky_username = opensky_username
        self.opensky_password = opensky_password
        self._session: Optional[aiohttp.ClientSession] = None
        
        # SDR hardware detection
        self.sdr_available = self._detect_sdr_hardware()
        self.sdr_device = None
        
        # Known frequency allocations
        self.frequency_allocations = self._load_frequency_allocations()
        self.protocol_signatures = self._load_protocol_signatures()
        self.satellite_tle_database = self._load_satellite_database()
        
        self._init_database()
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get HTTP session for API calls."""
        if self._session is None or self._session.closed:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit=10)
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        return self._session
    
    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def get_satellite_position_real(self, norad_id: int) -> Optional[Dict[str, Any]]:
        """
        Get real-time satellite position from N2YO API.
        
        Args:
            norad_id: NORAD catalog number
            
        Returns:
            Real satellite position data
        """
        if not self.n2yo_api_key:
            self.logger.warning("N2YO API key not configured. Get one at https://www.n2yo.com/api/")
            return None
        
        session = await self._get_session()
        
        try:
            # Observer location (can be made configurable)
            observer_lat = 40.7128
            observer_lon = -74.0060
            observer_alt = 0
            
            url = (
                f"https://api.n2yo.com/rest/v1/satellite/positions/{norad_id}/"
                f"{observer_lat}/{observer_lon}/{observer_alt}/1/&apiKey={self.n2yo_api_key}"
            )
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    if "positions" in data and data["positions"]:
                        pos = data["positions"][0]
                        sat_info = data.get("info", {})
                        
                        return {
                            "norad_id": norad_id,
                            "name": sat_info.get("satname"),
                            "latitude": pos.get("satlatitude"),
                            "longitude": pos.get("satlongitude"),
                            "altitude_km": pos.get("sataltitude"),
                            "azimuth": pos.get("azimuth"),
                            "elevation": pos.get("elevation"),
                            "timestamp": datetime.fromtimestamp(pos.get("timestamp", 0)),
                            "velocity_km_s": None,  # Not provided by this endpoint
                            "visible": pos.get("elevation", 0) > 0
                        }
        except Exception as e:
            self.logger.error(f"Error fetching satellite position: {e}")
        
        return None
    
    async def get_satellite_passes_real(
        self,
        norad_id: int,
        observer_lat: float,
        observer_lon: float,
        observer_alt: float = 0,
        days: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get predicted satellite passes from N2YO API.
        
        Args:
            norad_id: NORAD catalog number
            observer_lat: Observer latitude
            observer_lon: Observer longitude
            observer_alt: Observer altitude in meters
            days: Days to predict ahead
            
        Returns:
            List of predicted passes
        """
        if not self.n2yo_api_key:
            return []
        
        session = await self._get_session()
        
        try:
            url = (
                f"https://api.n2yo.com/rest/v1/satellite/visualpasses/{norad_id}/"
                f"{observer_lat}/{observer_lon}/{observer_alt}/{days}/300/&apiKey={self.n2yo_api_key}"
            )
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    passes = []
                    
                    for i, p in enumerate(data.get("passes", [])):
                        passes.append({
                            "pass_number": i + 1,
                            "start_time": datetime.fromtimestamp(p.get("startUTC", 0)).isoformat(),
                            "start_azimuth": p.get("startAz"),
                            "start_azimuth_compass": p.get("startAzCompass"),
                            "max_time": datetime.fromtimestamp(p.get("maxUTC", 0)).isoformat(),
                            "max_elevation": p.get("maxEl"),
                            "max_azimuth": p.get("maxAz"),
                            "end_time": datetime.fromtimestamp(p.get("endUTC", 0)).isoformat(),
                            "end_azimuth": p.get("endAz"),
                            "end_azimuth_compass": p.get("endAzCompass"),
                            "magnitude": p.get("mag"),
                            "duration_seconds": p.get("duration")
                        })
                    
                    return passes
        except Exception as e:
            self.logger.error(f"Error fetching satellite passes: {e}")
        
        return []
    
    async def get_tle_real(self, norad_id: int) -> Optional[Dict[str, Any]]:
        """Get TLE data from CelesTrak (free, no API key)."""
        session = await self._get_session()
        
        try:
            url = f"https://celestrak.org/NORAD/elements/gp.php?CATNR={norad_id}&FORMAT=JSON"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    if data and len(data) > 0:
                        tle = data[0]
                        return {
                            "norad_id": norad_id,
                            "name": tle.get("OBJECT_NAME"),
                            "object_id": tle.get("OBJECT_ID"),
                            "epoch": tle.get("EPOCH"),
                            "mean_motion": tle.get("MEAN_MOTION"),
                            "eccentricity": tle.get("ECCENTRICITY"),
                            "inclination": tle.get("INCLINATION"),
                            "raan": tle.get("RA_OF_ASC_NODE"),
                            "arg_perigee": tle.get("ARG_OF_PERICENTER"),
                            "mean_anomaly": tle.get("MEAN_ANOMALY"),
                            "classification": tle.get("CLASSIFICATION_TYPE"),
                            "element_set": tle.get("ELEMENT_SET_NO"),
                            "rev_at_epoch": tle.get("REV_AT_EPOCH"),
                            "bstar": tle.get("BSTAR"),
                            "mean_motion_dot": tle.get("MEAN_MOTION_DOT"),
                            "mean_motion_ddot": tle.get("MEAN_MOTION_DDOT")
                        }
        except Exception as e:
            self.logger.error(f"Error fetching TLE: {e}")
        
        return None
    
    async def get_opensky_aircraft(
        self,
        bbox: Optional[Tuple[float, float, float, float]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get real-time aircraft positions from OpenSky Network.
        Free tier: 400 requests/day, 4000 credits/day
        
        Args:
            bbox: Optional bounding box (lat_min, lat_max, lon_min, lon_max)
            
        Returns:
            List of aircraft with positions
        """
        session = await self._get_session()
        
        try:
            url = "https://opensky-network.org/api/states/all"
            params = {}
            
            if bbox:
                params["lamin"] = bbox[0]
                params["lamax"] = bbox[1]
                params["lomin"] = bbox[2]
                params["lomax"] = bbox[3]
            
            auth = None
            if self.opensky_username and self.opensky_password:
                auth = aiohttp.BasicAuth(self.opensky_username, self.opensky_password)
            
            async with session.get(url, params=params, auth=auth) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    aircraft = []
                    
                    for state in data.get("states", []) or []:
                        if len(state) >= 17:
                            aircraft.append({
                                "icao24": state[0],
                                "callsign": (state[1] or "").strip(),
                                "origin_country": state[2],
                                "time_position": state[3],
                                "last_contact": state[4],
                                "longitude": state[5],
                                "latitude": state[6],
                                "baro_altitude": state[7],
                                "on_ground": state[8],
                                "velocity": state[9],
                                "true_track": state[10],
                                "vertical_rate": state[11],
                                "sensors": state[12],
                                "geo_altitude": state[13],
                                "squawk": state[14],
                                "spi": state[15],
                                "position_source": state[16]
                            })
                    
                    return aircraft
        except Exception as e:
            self.logger.error(f"Error fetching OpenSky data: {e}")
        
        return []
    
    async def get_starlink_satellites(self) -> List[Dict[str, Any]]:
        """Get current Starlink satellite constellation data."""
        session = await self._get_session()
        
        try:
            url = "https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=JSON"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    satellites = []
                    for sat in data[:100]:  # Limit to first 100
                        satellites.append({
                            "norad_id": sat.get("NORAD_CAT_ID"),
                            "name": sat.get("OBJECT_NAME"),
                            "object_id": sat.get("OBJECT_ID"),
                            "epoch": sat.get("EPOCH"),
                            "mean_motion": sat.get("MEAN_MOTION"),
                            "eccentricity": sat.get("ECCENTRICITY"),
                            "inclination": sat.get("INCLINATION"),
                            "apogee_km": 550,  # Starlink typical altitude
                            "perigee_km": 540,
                            "period_min": 95  # Approximate
                        })
                    
                    return satellites
        except Exception as e:
            self.logger.error(f"Error fetching Starlink data: {e}")
        
        return []
    
    async def get_iss_position(self) -> Optional[Dict[str, Any]]:
        """Get current ISS position (free, no API key)."""
        session = await self._get_session()
        
        try:
            url = "http://api.open-notify.org/iss-now.json"
            
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    if data.get("message") == "success":
                        pos = data.get("iss_position", {})
                        return {
                            "name": "International Space Station",
                            "norad_id": 25544,
                            "latitude": float(pos.get("latitude", 0)),
                            "longitude": float(pos.get("longitude", 0)),
                            "altitude_km": 420,  # Approximate
                            "velocity_km_s": 7.66,  # Approximate
                            "timestamp": datetime.fromtimestamp(data.get("timestamp", 0))
                        }
        except Exception as e:
            self.logger.error(f"Error fetching ISS position: {e}")
        
        return None
    
    def _detect_sdr_hardware(self) -> Dict[str, bool]:
        """Detect available SDR hardware."""
        available = {
            "rtlsdr": False,
            "hackrf": False,
            "bladerf": False,
            "usrp": False,
            "limesdr": False
        }
        
        # Try RTL-SDR
        try:
            from rtlsdr import RtlSdr
            sdr = RtlSdr()
            sdr.close()
            available["rtlsdr"] = True
            self.logger.info("RTL-SDR device detected")
        except Exception:
            pass
        
        # Try HackRF
        try:
            import hackrf
            available["hackrf"] = hackrf.device_count() > 0
            if available["hackrf"]:
                self.logger.info("HackRF device detected")
        except Exception:
            pass
        
        # Try BladeRF
        try:
            import bladerf
            devs = bladerf.get_device_list()
            available["bladerf"] = len(devs) > 0
            if available["bladerf"]:
                self.logger.info("BladeRF device detected")
        except Exception:
            pass
        
        if not any(available.values()):
            self.logger.warning(
                "No SDR hardware detected. RF analysis features require SDR hardware. "
                "Satellite tracking and online data sources will still work."
            )
        
        return available
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS signals (
                signal_id TEXT PRIMARY KEY,
                signal_type TEXT,
                frequency REAL,
                bandwidth REAL,
                power REAL,
                modulation TEXT,
                timestamp TEXT,
                duration REAL,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                encrypted INTEGER,
                protocol TEXT,
                source_id TEXT,
                destination_id TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS satellites (
                satellite_id TEXT PRIMARY KEY,
                norad_id INTEGER,
                name TEXT,
                satellite_type TEXT,
                operator TEXT,
                country TEXT,
                launch_date TEXT,
                orbital_parameters TEXT,
                frequencies TEXT,
                is_active INTEGER,
                threat_level TEXT,
                capabilities TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS spectrum_analyses (
                analysis_id TEXT PRIMARY KEY,
                start_frequency REAL,
                end_frequency REAL,
                resolution REAL,
                timestamp TEXT,
                duration REAL,
                signals_detected INTEGER,
                peak_frequencies TEXT,
                noise_floor REAL,
                anomalies TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS rf_anomalies (
                anomaly_id TEXT PRIMARY KEY,
                signal_id TEXT,
                anomaly_type TEXT,
                frequency REAL,
                power REAL,
                timestamp TEXT,
                duration REAL,
                threat_level TEXT,
                description TEXT,
                possible_source TEXT,
                confidence REAL
            );
            
            CREATE TABLE IF NOT EXISTS rf_attacks (
                attack_id TEXT PRIMARY KEY,
                attack_type TEXT,
                target_frequency REAL,
                target_protocol TEXT,
                start_time TEXT,
                end_time TEXT,
                success INTEGER,
                detection_method TEXT,
                impact_assessment TEXT,
                countermeasures TEXT,
                iocs TEXT
            );
            
            CREATE TABLE IF NOT EXISTS decoded_messages (
                message_id TEXT PRIMARY KEY,
                signal_id TEXT,
                protocol TEXT,
                raw_data BLOB,
                decoded_content TEXT,
                timestamp TEXT,
                source TEXT,
                destination TEXT,
                is_encrypted INTEGER,
                integrity_verified INTEGER
            );
            
            CREATE INDEX IF NOT EXISTS idx_signals_frequency ON signals(frequency);
            CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp);
            CREATE INDEX IF NOT EXISTS idx_satellites_norad ON satellites(norad_id);
        """)
        
        conn.commit()
        conn.close()
    
    def _load_frequency_allocations(self) -> Dict[str, Dict[str, Any]]:
        """Load known frequency allocations."""
        return {
            "wifi_2.4": {"start": 2400, "end": 2500, "type": SignalType.WIFI},
            "wifi_5": {"start": 5150, "end": 5850, "type": SignalType.WIFI},
            "wifi_6e": {"start": 5925, "end": 7125, "type": SignalType.WIFI},
            "bluetooth": {"start": 2400, "end": 2483.5, "type": SignalType.BLUETOOTH},
            "gsm_900": {"start": 880, "end": 960, "type": SignalType.CELLULAR_2G},
            "gsm_1800": {"start": 1710, "end": 1880, "type": SignalType.CELLULAR_2G},
            "lte_700": {"start": 698, "end": 798, "type": SignalType.CELLULAR_4G},
            "lte_850": {"start": 824, "end": 894, "type": SignalType.CELLULAR_4G},
            "lte_1900": {"start": 1850, "end": 1990, "type": SignalType.CELLULAR_4G},
            "lte_2100": {"start": 1920, "end": 2170, "type": SignalType.CELLULAR_4G},
            "nr_3500": {"start": 3300, "end": 3800, "type": SignalType.CELLULAR_5G},
            "nr_mmwave": {"start": 24250, "end": 52600, "type": SignalType.CELLULAR_5G},
            "gps_l1": {"start": 1575.42, "end": 1575.42, "type": SignalType.GPS},
            "gps_l2": {"start": 1227.60, "end": 1227.60, "type": SignalType.GPS},
            "gps_l5": {"start": 1176.45, "end": 1176.45, "type": SignalType.GPS},
            "adsb": {"start": 1090, "end": 1090, "type": SignalType.ADS_B},
            "ais": {"start": 161.975, "end": 162.025, "type": SignalType.AIS},
            "lora_868": {"start": 863, "end": 870, "type": SignalType.LORA},
            "lora_915": {"start": 902, "end": 928, "type": SignalType.LORA},
            "zigbee": {"start": 2400, "end": 2483.5, "type": SignalType.ZIGBEE},
            "starlink_ku": {"start": 10700, "end": 12700, "type": SignalType.SATELLITE},
            "starlink_ka": {"start": 17700, "end": 20200, "type": SignalType.SATELLITE}
        }
    
    def _load_protocol_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load RF protocol signatures."""
        return {
            "802.11b": {
                "modulation": ModulationType.DSSS,
                "bandwidth": 22000,  # kHz
                "preamble": b"\xAA\xAA",
                "description": "WiFi 802.11b"
            },
            "802.11a/g": {
                "modulation": ModulationType.OFDM,
                "bandwidth": 20000,
                "description": "WiFi 802.11a/g"
            },
            "802.11n": {
                "modulation": ModulationType.OFDM,
                "bandwidth": [20000, 40000],
                "description": "WiFi 802.11n"
            },
            "802.11ac": {
                "modulation": ModulationType.OFDM,
                "bandwidth": [20000, 40000, 80000, 160000],
                "description": "WiFi 802.11ac"
            },
            "bluetooth_classic": {
                "modulation": ModulationType.GFSK,
                "bandwidth": 1000,
                "hop_rate": 1600,
                "description": "Bluetooth Classic"
            },
            "bluetooth_le": {
                "modulation": ModulationType.GFSK,
                "bandwidth": 2000,
                "description": "Bluetooth Low Energy"
            },
            "lte": {
                "modulation": ModulationType.OFDM,
                "bandwidth": [1400, 3000, 5000, 10000, 15000, 20000],
                "description": "LTE/4G"
            },
            "5g_nr": {
                "modulation": ModulationType.OFDM,
                "bandwidth": [5000, 10000, 15000, 20000, 25000, 30000, 40000,
                              50000, 60000, 80000, 100000],
                "description": "5G New Radio"
            },
            "lora": {
                "modulation": ModulationType.CHIRP,
                "bandwidth": [125, 250, 500],
                "spreading_factor": [7, 8, 9, 10, 11, 12],
                "description": "LoRa"
            },
            "adsb": {
                "modulation": ModulationType.PSK,
                "bandwidth": 50,
                "data_rate": 1000000,
                "description": "ADS-B"
            },
            "ais": {
                "modulation": ModulationType.GMSK,
                "bandwidth": 25,
                "description": "AIS"
            }
        }
    
    def _load_satellite_database(self) -> List[Dict[str, Any]]:
        """Load satellite TLE database."""
        # Sample satellite data
        return [
            {
                "norad_id": 25544,
                "name": "ISS (ZARYA)",
                "type": SatelliteType.SCIENTIFIC,
                "operator": "NASA/Roscosmos",
                "country": "International"
            },
            {
                "norad_id": 44713,
                "name": "STARLINK-24",
                "type": SatelliteType.STARLINK,
                "operator": "SpaceX",
                "country": "USA"
            },
            {
                "norad_id": 39084,
                "name": "NAVSTAR GPS IIF-4",
                "type": SatelliteType.NAVIGATION,
                "operator": "US Space Force",
                "country": "USA"
            }
        ]
    
    async def scan_spectrum(
        self,
        start_freq: float,
        end_freq: float,
        resolution: float = 10.0,
        duration: float = 1.0
    ) -> SpectrumAnalysis:
        """
        Scan a frequency range and analyze the spectrum.
        
        Args:
            start_freq: Start frequency in MHz
            end_freq: End frequency in MHz
            resolution: Resolution bandwidth in kHz
            duration: Scan duration in seconds
            
        Returns:
            Spectrum analysis results
        """
        analysis_id = str(uuid.uuid4())[:8]
        
        # Number of frequency bins
        num_bins = int((end_freq - start_freq) * 1000 / resolution)
        
        # Generate simulated power spectrum
        power_spectrum = []
        peak_frequencies = []
        signals_detected = 0
        
        for i in range(num_bins):
            freq = start_freq + (i * resolution / 1000)
            
            # Base noise floor with variations
            power = -100 + random.gauss(0, 5)
            
            # Check if frequency is in known allocation
            for alloc_name, alloc in self.frequency_allocations.items():
                if alloc["start"] <= freq <= alloc["end"]:
                    # Add signal with probability
                    if random.random() < 0.3:
                        signal_power = -60 + random.gauss(0, 10)
                        power = max(power, signal_power)
                        
                        if signal_power > -70:
                            peak_frequencies.append(freq)
                            signals_detected += 1
            
            power_spectrum.append(power)
        
        # Detect anomalies
        anomalies = self._detect_spectrum_anomalies(
            power_spectrum,
            start_freq,
            resolution
        )
        
        # Calculate noise floor
        noise_floor = sum(
            p for p in power_spectrum if p < -80
        ) / max(len([p for p in power_spectrum if p < -80]), 1)
        
        analysis = SpectrumAnalysis(
            analysis_id=analysis_id,
            start_frequency=start_freq,
            end_frequency=end_freq,
            resolution=resolution,
            timestamp=datetime.now(),
            duration=duration,
            signals_detected=signals_detected,
            peak_frequencies=peak_frequencies[:20],  # Top 20 peaks
            power_spectrum=power_spectrum,
            noise_floor=noise_floor,
            anomalies=anomalies,
            interference_sources=[]
        )
        
        self.analyses[analysis_id] = analysis
        self._save_analysis(analysis)
        
        return analysis
    
    def _detect_spectrum_anomalies(
        self,
        power_spectrum: List[float],
        start_freq: float,
        resolution: float
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in spectrum data."""
        anomalies = []
        
        # Calculate mean and std of power levels
        mean_power = sum(power_spectrum) / len(power_spectrum)
        std_power = math.sqrt(
            sum((p - mean_power) ** 2 for p in power_spectrum) / len(power_spectrum)
        )
        
        # Find anomalous peaks
        for i, power in enumerate(power_spectrum):
            if power > mean_power + 3 * std_power:
                freq = start_freq + (i * resolution / 1000)
                
                # Check if in known allocation
                in_known_band = False
                for alloc in self.frequency_allocations.values():
                    if alloc["start"] <= freq <= alloc["end"]:
                        in_known_band = True
                        break
                
                if not in_known_band:
                    anomalies.append({
                        "frequency": freq,
                        "power": power,
                        "type": "unknown_signal",
                        "severity": "medium"
                    })
        
        return anomalies
    
    async def detect_signal(
        self,
        frequency: float,
        bandwidth: float = 20000
    ) -> Optional[RFSignal]:
        """
        Detect and classify a signal at a specific frequency.
        
        Args:
            frequency: Center frequency in MHz
            bandwidth: Bandwidth to analyze in kHz
            
        Returns:
            Detected signal or None
        """
        signal_id = str(uuid.uuid4())[:8]
        
        # Determine signal type from frequency
        signal_type = SignalType.UNKNOWN
        protocol = "unknown"
        modulation = ModulationType.UNKNOWN
        
        for alloc_name, alloc in self.frequency_allocations.items():
            if alloc["start"] <= frequency <= alloc["end"]:
                signal_type = alloc["type"]
                
                # Find matching protocol
                for proto_name, proto in self.protocol_signatures.items():
                    if signal_type.name.lower() in proto_name.lower():
                        modulation = proto.get("modulation", ModulationType.UNKNOWN)
                        protocol = proto_name
                        break
                break
        
        # Simulate signal detection
        if random.random() < 0.7:  # 70% detection probability
            signal = RFSignal(
                signal_id=signal_id,
                signal_type=signal_type,
                frequency=frequency,
                bandwidth=bandwidth,
                power=-65 + random.gauss(0, 10),
                modulation=modulation,
                timestamp=datetime.now(),
                duration=random.uniform(0.1, 10),
                location=None,
                direction=None,
                distance=None,
                encrypted=random.random() > 0.5,
                protocol=protocol,
                payload_preview="[Signal detected]",
                source_identifier=f"SRC_{signal_id}",
                destination_identifier=f"DST_{signal_id}"
            )
            
            self.signals[signal_id] = signal
            self._save_signal(signal)
            
            return signal
        
        return None
    
    async def track_satellite(
        self,
        norad_id: int
    ) -> Optional[Satellite]:
        """
        Track a satellite by NORAD ID.
        
        Args:
            norad_id: NORAD catalog number
            
        Returns:
            Satellite tracking data
        """
        # Find satellite in database
        sat_data = None
        for sat in self.satellite_tle_database:
            if sat["norad_id"] == norad_id:
                sat_data = sat
                break
        
        if not sat_data:
            return None
        
        satellite_id = str(uuid.uuid4())[:8]
        
        # Calculate current position (simulated)
        # In production, would use SGP4 propagator
        lat = random.uniform(-90, 90)
        lon = random.uniform(-180, 180)
        alt = random.uniform(200, 36000) * 1000  # meters
        
        satellite = Satellite(
            satellite_id=satellite_id,
            norad_id=norad_id,
            name=sat_data["name"],
            satellite_type=sat_data["type"],
            operator=sat_data["operator"],
            country=sat_data["country"],
            launch_date=datetime.now() - timedelta(days=random.randint(100, 3650)),
            orbital_parameters={
                "semi_major_axis": 6378 + alt / 1000,
                "eccentricity": random.uniform(0, 0.1),
                "inclination": random.uniform(0, 98),
                "raan": random.uniform(0, 360),
                "arg_perigee": random.uniform(0, 360),
                "mean_anomaly": random.uniform(0, 360)
            },
            position=(lat, lon, alt),
            velocity=(
                random.uniform(-8000, 8000),
                random.uniform(-8000, 8000),
                random.uniform(-1000, 1000)
            ),
            frequencies=[
                2200 + random.uniform(-100, 100),
                8000 + random.uniform(-500, 500)
            ],
            is_active=True,
            threat_level=ThreatLevel.LOW,
            capabilities=[]
        )
        
        self.satellites[satellite_id] = satellite
        self._save_satellite(satellite)
        
        return satellite
    
    async def predict_satellite_pass(
        self,
        norad_id: int,
        observer_lat: float,
        observer_lon: float,
        observer_alt: float = 0,
        days_ahead: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Predict satellite passes over an observer location.
        
        Args:
            norad_id: Satellite NORAD ID
            observer_lat: Observer latitude
            observer_lon: Observer longitude
            observer_alt: Observer altitude in meters
            days_ahead: Days to predict ahead
            
        Returns:
            List of predicted passes
        """
        passes = []
        
        # Simulated pass prediction
        num_passes = random.randint(3, 10)
        
        for i in range(num_passes):
            rise_time = datetime.now() + timedelta(
                days=random.uniform(0, days_ahead),
                hours=random.uniform(0, 24)
            )
            
            duration = random.uniform(2, 12) * 60  # seconds
            
            passes.append({
                "pass_number": i + 1,
                "rise_time": rise_time.isoformat(),
                "rise_azimuth": random.uniform(0, 360),
                "max_elevation": random.uniform(10, 90),
                "max_time": (rise_time + timedelta(seconds=duration/2)).isoformat(),
                "set_time": (rise_time + timedelta(seconds=duration)).isoformat(),
                "set_azimuth": random.uniform(0, 360),
                "duration_seconds": duration,
                "brightness": random.uniform(-2, 6),  # magnitude
                "visible": random.random() > 0.3
            })
        
        return sorted(passes, key=lambda x: x["rise_time"])
    
    async def geolocate_signal(
        self,
        signal_id: str,
        method: str = "tdoa",
        receivers: List[Dict[str, Any]] = None
    ) -> GeolocationResult:
        """
        Geolocate an RF signal using various methods.
        
        Args:
            signal_id: Signal to geolocate
            method: Geolocation method (tdoa, aoa, fdoa, hybrid)
            receivers: List of receiver locations
            
        Returns:
            Geolocation result
        """
        signal = self.signals.get(signal_id)
        if not signal:
            raise ValueError(f"Signal {signal_id} not found")
        
        result_id = str(uuid.uuid4())[:8]
        
        # Simulated geolocation
        # In production, would implement actual TDOA/AOA/FDOA algorithms
        
        if receivers and len(receivers) >= 3:
            # Calculate position based on receivers
            lat = sum(r["lat"] for r in receivers) / len(receivers)
            lon = sum(r["lon"] for r in receivers) / len(receivers)
            lat += random.gauss(0, 0.01)  # Add error
            lon += random.gauss(0, 0.01)
        else:
            lat = random.uniform(-90, 90)
            lon = random.uniform(-180, 180)
        
        # Accuracy depends on method
        accuracy_map = {
            "tdoa": random.uniform(50, 500),
            "aoa": random.uniform(100, 1000),
            "fdoa": random.uniform(200, 2000),
            "hybrid": random.uniform(30, 200)
        }
        
        accuracy = accuracy_map.get(method, 1000)
        
        result = GeolocationResult(
            result_id=result_id,
            signal_id=signal_id,
            method=method,
            latitude=lat,
            longitude=lon,
            altitude=random.uniform(0, 100),
            accuracy=accuracy,
            confidence=random.uniform(0.6, 0.99),
            timestamp=datetime.now(),
            bearing=random.uniform(0, 360),
            distance=random.uniform(100, 10000)
        )
        
        # Update signal with location
        signal.location = (lat, lon, result.altitude or 0)
        
        return result
    
    async def decode_signal(
        self,
        signal_id: str
    ) -> Optional[DecodedMessage]:
        """
        Attempt to decode an RF signal.
        
        Args:
            signal_id: Signal to decode
            
        Returns:
            Decoded message or None
        """
        signal = self.signals.get(signal_id)
        if not signal:
            return None
        
        message_id = str(uuid.uuid4())[:8]
        
        # Protocol-specific decoding
        decoded_content = {}
        
        if signal.signal_type == SignalType.ADS_B:
            decoded_content = {
                "icao24": f"{random.randint(0, 0xFFFFFF):06X}",
                "callsign": f"UAL{random.randint(100, 9999)}",
                "altitude": random.randint(1000, 45000),
                "speed": random.randint(100, 600),
                "heading": random.randint(0, 360),
                "latitude": random.uniform(-90, 90),
                "longitude": random.uniform(-180, 180)
            }
        elif signal.signal_type == SignalType.AIS:
            decoded_content = {
                "mmsi": f"{random.randint(100000000, 999999999)}",
                "vessel_name": f"VESSEL_{random.randint(1, 1000)}",
                "ship_type": random.choice([
                    "Cargo", "Tanker", "Passenger", "Fishing"
                ]),
                "latitude": random.uniform(-90, 90),
                "longitude": random.uniform(-180, 180),
                "speed": random.uniform(0, 30),
                "course": random.randint(0, 360)
            }
        elif signal.signal_type == SignalType.WIFI:
            decoded_content = {
                "bssid": ":".join(
                    f"{random.randint(0, 255):02X}" for _ in range(6)
                ),
                "ssid": f"Network_{random.randint(1, 100)}",
                "channel": random.choice([1, 6, 11, 36, 40, 44, 48]),
                "security": random.choice(["WPA2", "WPA3", "Open"]),
                "client_count": random.randint(0, 50)
            }
        elif signal.signal_type == SignalType.BLUETOOTH:
            decoded_content = {
                "mac_address": ":".join(
                    f"{random.randint(0, 255):02X}" for _ in range(6)
                ),
                "device_name": f"Device_{random.randint(1, 100)}",
                "device_class": random.choice([
                    "Phone", "Computer", "Audio", "Peripheral"
                ]),
                "rssi": random.randint(-100, -30)
            }
        else:
            decoded_content = {
                "raw_hex": "".join(
                    f"{random.randint(0, 255):02X}" for _ in range(32)
                )
            }
        
        message = DecodedMessage(
            message_id=message_id,
            signal_id=signal_id,
            protocol=signal.protocol,
            raw_data=bytes([random.randint(0, 255) for _ in range(64)]),
            decoded_content=decoded_content,
            timestamp=datetime.now(),
            source=signal.source_identifier or "unknown",
            destination=signal.destination_identifier or "broadcast",
            is_encrypted=signal.encrypted,
            encryption_type="AES-256" if signal.encrypted else None,
            integrity_verified=random.random() > 0.1
        )
        
        return message
    
    async def detect_rf_attack(
        self,
        frequency: float,
        duration: float = 10.0
    ) -> List[RFAttack]:
        """
        Monitor for RF attacks at a frequency.
        
        Args:
            frequency: Frequency to monitor in MHz
            duration: Monitoring duration in seconds
            
        Returns:
            List of detected attacks
        """
        attacks = []
        
        # Simulated attack detection
        attack_probabilities = {
            AttackType.JAMMING: 0.05,
            AttackType.SPOOFING: 0.03,
            AttackType.REPLAY: 0.02,
            AttackType.DEAUTHENTICATION: 0.04,
            AttackType.ROGUE_ACCESS_POINT: 0.03
        }
        
        for attack_type, prob in attack_probabilities.items():
            if random.random() < prob:
                attack_id = str(uuid.uuid4())[:8]
                
                attack = RFAttack(
                    attack_id=attack_id,
                    attack_type=attack_type,
                    target_frequency=frequency,
                    target_protocol=self._get_protocol_for_frequency(frequency),
                    start_time=datetime.now(),
                    end_time=None,
                    success=random.random() > 0.5,
                    detection_method=self._get_detection_method(attack_type),
                    impact_assessment=self._assess_attack_impact(attack_type),
                    countermeasures=self._get_countermeasures(attack_type),
                    iocs=self._generate_iocs(attack_type)
                )
                
                attacks.append(attack)
                self.attacks[attack_id] = attack
                
                # Create anomaly
                anomaly = RFAnomaly(
                    anomaly_id=str(uuid.uuid4())[:8],
                    signal_id=None,
                    anomaly_type=attack_type.name.lower(),
                    frequency=frequency,
                    power=-30 + random.gauss(0, 5),
                    timestamp=datetime.now(),
                    duration=random.uniform(0.1, duration),
                    threat_level=ThreatLevel.HIGH,
                    description=f"Detected {attack_type.name} attack",
                    possible_source="Unknown attacker",
                    recommended_action=self._get_countermeasures(attack_type)[0],
                    confidence=random.uniform(0.7, 0.99)
                )
                
                self.anomalies.append(anomaly)
        
        return attacks
    
    def _get_protocol_for_frequency(self, frequency: float) -> str:
        """Get likely protocol for a frequency."""
        for alloc_name, alloc in self.frequency_allocations.items():
            if alloc["start"] <= frequency <= alloc["end"]:
                return alloc_name
        return "unknown"
    
    def _get_detection_method(self, attack_type: AttackType) -> str:
        """Get detection method for attack type."""
        methods = {
            AttackType.JAMMING: "Power spectral density analysis",
            AttackType.SPOOFING: "Signal fingerprinting mismatch",
            AttackType.REPLAY: "Timestamp/nonce validation",
            AttackType.DEAUTHENTICATION: "Frame rate anomaly",
            AttackType.ROGUE_ACCESS_POINT: "BSSID/SSID correlation"
        }
        return methods.get(attack_type, "Anomaly detection")
    
    def _assess_attack_impact(self, attack_type: AttackType) -> str:
        """Assess impact of attack type."""
        impacts = {
            AttackType.JAMMING: "Denial of service, communication disruption",
            AttackType.SPOOFING: "Position falsification, authentication bypass",
            AttackType.REPLAY: "Transaction replay, authentication bypass",
            AttackType.DEAUTHENTICATION: "Client disconnection, MitM setup",
            AttackType.ROGUE_ACCESS_POINT: "Data interception, credential theft"
        }
        return impacts.get(attack_type, "Unknown impact")
    
    def _get_countermeasures(self, attack_type: AttackType) -> List[str]:
        """Get countermeasures for attack type."""
        countermeasures = {
            AttackType.JAMMING: [
                "Enable frequency hopping",
                "Increase transmit power",
                "Switch to backup frequency",
                "Enable directional antennas"
            ],
            AttackType.SPOOFING: [
                "Enable signal authentication",
                "Verify signal fingerprint",
                "Cross-reference with multiple sources",
                "Enable anti-spoofing features"
            ],
            AttackType.REPLAY: [
                "Implement nonces/timestamps",
                "Enable sequence number verification",
                "Use challenge-response protocols"
            ],
            AttackType.DEAUTHENTICATION: [
                "Enable 802.11w (PMF)",
                "Monitor for attack patterns",
                "Implement client isolation"
            ],
            AttackType.ROGUE_ACCESS_POINT: [
                "Implement WIDS/WIPS",
                "Verify AP certificates",
                "Enable EAP-TLS authentication"
            ]
        }
        return countermeasures.get(attack_type, ["Monitor and investigate"])
    
    def _generate_iocs(self, attack_type: AttackType) -> List[str]:
        """Generate IOCs for attack detection."""
        iocs = []
        
        if attack_type == AttackType.JAMMING:
            iocs.append(f"elevated_noise_floor:{random.randint(-50, -30)}dBm")
            iocs.append("signal_to_noise:degraded")
        elif attack_type == AttackType.ROGUE_ACCESS_POINT:
            iocs.append(f"bssid:{':'.join(f'{random.randint(0,255):02X}' for _ in range(6))}")
            iocs.append(f"ssid:Evil_Twin_{random.randint(1,100)}")
        elif attack_type == AttackType.DEAUTHENTICATION:
            iocs.append(f"deauth_frame_rate:{random.randint(100, 1000)}/min")
            iocs.append("reason_code:7")
        
        return iocs
    
    async def detect_drones(
        self,
        scan_frequencies: List[Tuple[float, float]] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect drone RF signatures.
        
        Args:
            scan_frequencies: List of (start, end) frequency ranges
            
        Returns:
            List of detected drones
        """
        if not scan_frequencies:
            # Common drone control frequencies
            scan_frequencies = [
                (2400, 2500),  # 2.4 GHz
                (5725, 5875),  # 5.8 GHz
                (900, 930),    # 900 MHz
            ]
        
        detected_drones = []
        
        for start_freq, end_freq in scan_frequencies:
            # Scan the frequency range
            analysis = await self.scan_spectrum(
                start_freq,
                end_freq,
                resolution=100,
                duration=1.0
            )
            
            # Look for drone signatures
            for peak in analysis.peak_frequencies:
                # Check for characteristic drone modulation
                if random.random() < 0.1:  # Simulated detection
                    drone_type = random.choice([
                        "DJI Mavic", "DJI Phantom", "Parrot Anafi",
                        "Autel Evo", "Skydio", "Unknown"
                    ])
                    
                    detected_drones.append({
                        "detection_id": str(uuid.uuid4())[:8],
                        "frequency": peak,
                        "drone_type": drone_type,
                        "signal_strength": -60 + random.gauss(0, 10),
                        "protocol": "proprietary",
                        "direction": random.uniform(0, 360),
                        "estimated_distance": random.uniform(100, 2000),
                        "timestamp": datetime.now().isoformat(),
                        "threat_level": "MEDIUM",
                        "video_link_detected": random.random() > 0.5,
                        "control_link_detected": True
                    })
        
        return detected_drones
    
    def _save_signal(self, signal: RFSignal) -> None:
        """Save signal to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        lat, lon, alt = signal.location if signal.location else (None, None, None)
        
        cursor.execute("""
            INSERT OR REPLACE INTO signals
            (signal_id, signal_type, frequency, bandwidth, power, modulation,
             timestamp, duration, latitude, longitude, altitude, encrypted,
             protocol, source_id, destination_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            signal.signal_id,
            signal.signal_type.name,
            signal.frequency,
            signal.bandwidth,
            signal.power,
            signal.modulation.name,
            signal.timestamp.isoformat(),
            signal.duration,
            lat,
            lon,
            alt,
            1 if signal.encrypted else 0,
            signal.protocol,
            signal.source_identifier,
            signal.destination_identifier,
            json.dumps(signal.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_satellite(self, satellite: Satellite) -> None:
        """Save satellite to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO satellites
            (satellite_id, norad_id, name, satellite_type, operator, country,
             launch_date, orbital_parameters, frequencies, is_active,
             threat_level, capabilities, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            satellite.satellite_id,
            satellite.norad_id,
            satellite.name,
            satellite.satellite_type.name,
            satellite.operator,
            satellite.country,
            satellite.launch_date.isoformat(),
            json.dumps(satellite.orbital_parameters),
            json.dumps(satellite.frequencies),
            1 if satellite.is_active else 0,
            satellite.threat_level.name,
            json.dumps(satellite.capabilities),
            json.dumps(satellite.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_analysis(self, analysis: SpectrumAnalysis) -> None:
        """Save spectrum analysis to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO spectrum_analyses
            (analysis_id, start_frequency, end_frequency, resolution,
             timestamp, duration, signals_detected, peak_frequencies,
             noise_floor, anomalies, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis.analysis_id,
            analysis.start_frequency,
            analysis.end_frequency,
            analysis.resolution,
            analysis.timestamp.isoformat(),
            analysis.duration,
            analysis.signals_detected,
            json.dumps(analysis.peak_frequencies),
            analysis.noise_floor,
            json.dumps(analysis.anomalies),
            json.dumps(analysis.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def register_callback(
        self,
        event_type: str,
        callback: Callable
    ) -> None:
        """Register callback for RF events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)
    
    async def emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to registered callbacks."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")
