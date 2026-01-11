"""
word_scrubber.py - ULTRA ADVANCED Word Scrubbing Engine

Enterprise-grade content filtering, redaction, and compliance engine.
Features:
- Multi-protocol crawling (HTTP/HTTPS/FTP/FILE/S3/GCS)
- AI-powered PII/sensitive data detection
- OCR for images and PDFs
- JavaScript rendering with headless browser
- Blockchain audit trail
- Machine learning pattern detection
- Real-time monitoring mode
- Cloud storage integration
- Database content scrubbing
- Advanced session management with proxy/TOR support
- Steganography detection
- Metadata scrubbing
- Differential/incremental scrubbing
- Multiple export formats (JSON, CSV, XML, DIFF, PATCH, HTML)
"""

import re
import os
import sys
import time
import json
import csv
import hashlib
import random
import string
import logging
import threading
import asyncio
import base64
import mimetypes
import tempfile
import difflib
import sqlite3
import pickle
import gzip
import io
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from functools import lru_cache, wraps
from contextlib import contextmanager
import warnings

# Core dependencies
import requests
from bs4 import BeautifulSoup, NavigableString, Comment

# Optional advanced dependencies with graceful fallback
try:
    import aiohttp
    import aiofiles
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    import PyPDF2
    import pdfplumber
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import storage as gcs_storage
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

try:
    import spacy
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Additional bypass dependencies
try:
    import cloudscraper
    CLOUDSCRAPER_AVAILABLE = True
except ImportError:
    CLOUDSCRAPER_AVAILABLE = False

try:
    import undetected_chromedriver as uc
    UNDETECTED_CHROME_AVAILABLE = True
except ImportError:
    UNDETECTED_CHROME_AVAILABLE = False

try:
    from fake_useragent import UserAgent
    FAKE_UA_AVAILABLE = True
except ImportError:
    FAKE_UA_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False

try:
    import tls_client
    TLS_CLIENT_AVAILABLE = True
except ImportError:
    TLS_CLIENT_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BypassMode(Enum):
    """Protocol bypass modes"""
    STANDARD = auto()           # Normal requests
    STEALTH = auto()            # Stealth mode with fingerprint randomization
    CLOUDFLARE = auto()         # Cloudflare bypass
    AKAMAI = auto()             # Akamai bypass
    IMPERVA = auto()            # Imperva/Incapsula bypass
    DATADOME = auto()           # DataDome bypass
    PERIMETERX = auto()         # PerimeterX bypass
    DISTIL = auto()             # Distil Networks bypass
    KASADA = auto()             # Kasada bypass
    SHAPE = auto()              # Shape Security bypass
    RECAPTCHA = auto()          # reCAPTCHA solving
    HCAPTCHA = auto()           # hCaptcha solving
    AGGRESSIVE = auto()         # All bypass techniques combined
    BROWSER_EMULATION = auto()  # Full browser emulation
    NUCLEAR = auto()            # Maximum power, all techniques at once
    UNDETECTABLE = auto()       # Real browser fingerprint, undetectable
    RESIDENTIAL = auto()        # Residential proxy mode
    MOBILE = auto()             # Mobile device emulation
    API = auto()                # API endpoint targeting


class ProtocolBypass:
    """
    Advanced protocol bypass engine for scraping protected websites.
    Handles anti-bot systems, CAPTCHAs, WAFs, and rate limiting.
    """
    
    # Comprehensive list of real browser User-Agents
    USER_AGENTS = [
        # Chrome on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Chrome on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Firefox on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Firefox on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari on Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge on Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Chrome on Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Mobile Chrome
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ]
    
    # Browser fingerprint configurations
    FINGERPRINTS = {
        'chrome_win': {
            'platform': 'Win32',
            'vendor': 'Google Inc.',
            'renderer': 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)',
            'webgl_vendor': 'Google Inc. (Intel)',
            'languages': ['en-US', 'en'],
            'timezone': -300,
            'screen': {'width': 1920, 'height': 1080, 'depth': 24},
            'hardware_concurrency': 8,
            'device_memory': 8,
        },
        'chrome_mac': {
            'platform': 'MacIntel',
            'vendor': 'Google Inc.',
            'renderer': 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
            'webgl_vendor': 'Google Inc. (Apple)',
            'languages': ['en-US', 'en'],
            'timezone': -480,
            'screen': {'width': 2560, 'height': 1600, 'depth': 30},
            'hardware_concurrency': 8,
            'device_memory': 16,
        },
        'firefox_win': {
            'platform': 'Win32',
            'vendor': '',
            'renderer': 'Intel(R) UHD Graphics 630',
            'webgl_vendor': 'Intel Inc.',
            'languages': ['en-US', 'en'],
            'timezone': -300,
            'screen': {'width': 1920, 'height': 1080, 'depth': 24},
            'hardware_concurrency': 8,
            'device_memory': None,
        },
    }
    
    # TLS fingerprints for different browsers
    TLS_FINGERPRINTS = {
        'chrome': 'chrome_120',
        'firefox': 'firefox_120',
        'safari': 'safari_17_2',
        'edge': 'edge_120',
    }
    
    def __init__(
        self,
        bypass_mode: BypassMode = BypassMode.AGGRESSIVE,
        rotate_user_agent: bool = True,
        rotate_fingerprint: bool = True,
        use_stealth: bool = True,
        captcha_solver: str = None,  # '2captcha', 'anticaptcha', 'capsolver'
        captcha_api_key: str = None,
        max_retries: int = 5,
        retry_delay: float = 2.0,
        random_delays: bool = True,
        delay_range: Tuple[float, float] = (1.0, 3.0),
        spoof_referrer: bool = True,
        simulate_human: bool = True,
        cookie_persistence: bool = True,
        session_rotation: bool = False,
        proxy_rotation: bool = False,
        proxies: List[str] = None,
        use_tor: bool = False,
        rotate_interval: int = 5,
        timeout: int = 30,
    ):
        self.bypass_mode = bypass_mode
        self.rotate_user_agent = rotate_user_agent
        self.rotate_fingerprint = rotate_fingerprint
        self.use_stealth = use_stealth
        self.captcha_solver = captcha_solver
        self.captcha_api_key = captcha_api_key
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.random_delays = random_delays
        self.delay_range = delay_range
        self.spoof_referrer = spoof_referrer
        self.simulate_human = simulate_human
        self.cookie_persistence = cookie_persistence
        self.session_rotation = session_rotation
        self.proxy_rotation = proxy_rotation
        self.proxies = proxies or []
        self.use_tor = use_tor
        self.rotate_interval = rotate_interval
        self.timeout = timeout
        
        self.current_proxy_index = 0
        self.sessions: Dict[str, Any] = {}
        self.cookies: Dict[str, Dict] = {}
        self.request_count = 0
        self.ua_generator = UserAgent() if FAKE_UA_AVAILABLE else None
        
        # Initialize various clients
        self._init_clients()
    
    def _init_clients(self):
        """Initialize different HTTP clients for bypass"""
        self.clients = {}
        
        # Standard requests session
        self.clients['requests'] = self._create_stealth_session()
        
        # CloudScraper for Cloudflare
        if CLOUDSCRAPER_AVAILABLE:
            self.clients['cloudscraper'] = cloudscraper.create_scraper(
                browser={
                    'browser': 'chrome',
                    'platform': 'windows',
                    'desktop': True
                }
            )
        
        # HTTPX for HTTP/2 support
        if HTTPX_AVAILABLE:
            self.clients['httpx'] = httpx.Client(
                http2=True,
                follow_redirects=True,
                timeout=30.0
            )
        
        # curl_cffi for TLS fingerprint impersonation
        if CURL_CFFI_AVAILABLE:
            self.clients['curl_cffi'] = curl_requests.Session(impersonate="chrome120")
        
        # TLS Client for advanced TLS fingerprinting
        if TLS_CLIENT_AVAILABLE:
            self.clients['tls_client'] = tls_client.Session(
                client_identifier="chrome_120",
                random_tls_extension_order=True
            )
    
    def _create_stealth_session(self) -> requests.Session:
        """Create a stealth requests session with proper headers"""
        session = requests.Session()
        
        # Set default headers to mimic real browser
        session.headers.update(self._get_browser_headers())
        
        # Disable SSL warnings for some edge cases
        session.verify = True
        
        return session
    
    def _get_browser_headers(self, url: str = None) -> Dict[str, str]:
        """Generate realistic browser headers"""
        ua = self._get_user_agent()
        
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        
        # Add referrer if spoofing enabled
        if self.spoof_referrer and url:
            parsed = urlparse(url)
            headers['Referer'] = f"{parsed.scheme}://{parsed.netloc}/"
            headers['Origin'] = f"{parsed.scheme}://{parsed.netloc}"
        
        return headers
    
    def _get_user_agent(self) -> str:
        """Get a user agent string"""
        if self.rotate_user_agent:
            if self.ua_generator:
                return self.ua_generator.random
            return random.choice(self.USER_AGENTS)
        return self.USER_AGENTS[0]
    
    def _get_fingerprint(self) -> Dict:
        """Get a browser fingerprint configuration"""
        if self.rotate_fingerprint:
            return random.choice(list(self.FINGERPRINTS.values()))
        return self.FINGERPRINTS['chrome_win']
    
    def _get_proxy(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration"""
        if not self.proxies:
            return None
        
        if self.proxy_rotation:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        proxy_url = self.proxies[self.current_proxy_index]
        return {'http': proxy_url, 'https': proxy_url}
    
    def _add_delay(self):
        """Add human-like delay between requests"""
        if self.random_delays:
            delay = random.uniform(*self.delay_range)
        else:
            delay = self.delay_range[0]
        
        if self.simulate_human:
            # Add some jitter for more realistic behavior
            delay += random.gauss(0, 0.3)
            delay = max(0.1, delay)
        
        time.sleep(delay)
    
    def _detect_protection(self, response: requests.Response, content: str) -> Optional[str]:
        """Detect what type of protection is in place"""
        headers = response.headers
        status = response.status_code
        
        # Cloudflare detection
        if 'cf-ray' in headers or 'cf-cache-status' in headers:
            if status == 403 or 'cf-chl-bypass' in headers:
                return 'cloudflare'
            if 'Checking your browser' in content or 'cf-browser-verification' in content:
                return 'cloudflare_challenge'
        
        # Akamai detection
        if 'akamai' in headers.get('server', '').lower():
            return 'akamai'
        if '_abck' in response.cookies:
            return 'akamai_bot_manager'
        
        # Imperva/Incapsula detection
        if 'incap_ses' in str(response.cookies) or 'visid_incap' in str(response.cookies):
            return 'imperva'
        if 'Request unsuccessful' in content and 'Incapsula' in content:
            return 'imperva'
        
        # DataDome detection
        if 'datadome' in str(response.cookies).lower():
            return 'datadome'
        
        # PerimeterX detection
        if '_px' in str(response.cookies):
            return 'perimeterx'
        
        # Distil Networks detection
        if 'distil' in content.lower() or 'X-Distil-CS' in headers:
            return 'distil'
        
        # reCAPTCHA detection
        if 'g-recaptcha' in content or 'grecaptcha' in content:
            return 'recaptcha'
        
        # hCaptcha detection
        if 'h-captcha' in content or 'hcaptcha' in content:
            return 'hcaptcha'
        
        # Generic bot detection
        if status == 403 or status == 429:
            if 'bot' in content.lower() or 'blocked' in content.lower():
                return 'generic_bot_block'
        
        # Rate limiting
        if status == 429:
            return 'rate_limited'
        
        return None
    
    def _solve_captcha(self, captcha_type: str, site_key: str, url: str) -> Optional[str]:
        """Solve CAPTCHA using external service"""
        if not self.captcha_solver or not self.captcha_api_key:
            logger.warning("CAPTCHA solver not configured")
            return None
        
        try:
            if self.captcha_solver == '2captcha':
                return self._solve_2captcha(captcha_type, site_key, url)
            elif self.captcha_solver == 'anticaptcha':
                return self._solve_anticaptcha(captcha_type, site_key, url)
            elif self.captcha_solver == 'capsolver':
                return self._solve_capsolver(captcha_type, site_key, url)
        except Exception as e:
            logger.error(f"CAPTCHA solving failed: {e}")
        
        return None
    
    def _solve_2captcha(self, captcha_type: str, site_key: str, url: str) -> Optional[str]:
        """Solve CAPTCHA using 2captcha service"""
        import requests as req
        
        # Submit CAPTCHA
        if captcha_type == 'recaptcha':
            submit_url = f"http://2captcha.com/in.php?key={self.captcha_api_key}&method=userrecaptcha&googlekey={site_key}&pageurl={url}&json=1"
        elif captcha_type == 'hcaptcha':
            submit_url = f"http://2captcha.com/in.php?key={self.captcha_api_key}&method=hcaptcha&sitekey={site_key}&pageurl={url}&json=1"
        else:
            return None
        
        resp = req.get(submit_url)
        data = resp.json()
        
        if data.get('status') != 1:
            return None
        
        task_id = data.get('request')
        
        # Poll for result
        for _ in range(60):
            time.sleep(3)
            result_url = f"http://2captcha.com/res.php?key={self.captcha_api_key}&action=get&id={task_id}&json=1"
            resp = req.get(result_url)
            data = resp.json()
            
            if data.get('status') == 1:
                return data.get('request')
            elif data.get('request') != 'CAPCHA_NOT_READY':
                return None
        
        return None
    
    def _solve_anticaptcha(self, captcha_type: str, site_key: str, url: str) -> Optional[str]:
        """Solve CAPTCHA using Anti-Captcha service"""
        import requests as req
        
        task_type = 'RecaptchaV2TaskProxyless' if captcha_type == 'recaptcha' else 'HCaptchaTaskProxyless'
        
        # Create task
        create_data = {
            "clientKey": self.captcha_api_key,
            "task": {
                "type": task_type,
                "websiteURL": url,
                "websiteKey": site_key
            }
        }
        
        resp = req.post("https://api.anti-captcha.com/createTask", json=create_data)
        data = resp.json()
        
        if data.get('errorId') != 0:
            return None
        
        task_id = data.get('taskId')
        
        # Poll for result
        for _ in range(60):
            time.sleep(3)
            result_data = {
                "clientKey": self.captcha_api_key,
                "taskId": task_id
            }
            resp = req.post("https://api.anti-captcha.com/getTaskResult", json=result_data)
            data = resp.json()
            
            if data.get('status') == 'ready':
                return data.get('solution', {}).get('gRecaptchaResponse')
            elif data.get('errorId') != 0:
                return None
        
        return None
    
    def _solve_capsolver(self, captcha_type: str, site_key: str, url: str) -> Optional[str]:
        """Solve CAPTCHA using CapSolver service"""
        import requests as req
        
        task_type = 'ReCaptchaV2TaskProxyLess' if captcha_type == 'recaptcha' else 'HCaptchaTaskProxyLess'
        
        create_data = {
            "clientKey": self.captcha_api_key,
            "task": {
                "type": task_type,
                "websiteURL": url,
                "websiteKey": site_key
            }
        }
        
        resp = req.post("https://api.capsolver.com/createTask", json=create_data)
        data = resp.json()
        
        if data.get('errorId') != 0:
            return None
        
        task_id = data.get('taskId')
        
        for _ in range(60):
            time.sleep(3)
            result_data = {
                "clientKey": self.captcha_api_key,
                "taskId": task_id
            }
            resp = req.post("https://api.capsolver.com/getTaskResult", json=result_data)
            data = resp.json()
            
            if data.get('status') == 'ready':
                return data.get('solution', {}).get('gRecaptchaResponse')
        
        return None
    
    def _bypass_cloudflare(self, url: str, session: requests.Session) -> Optional[requests.Response]:
        """Bypass Cloudflare protection"""
        # Try CloudScraper first
        if CLOUDSCRAPER_AVAILABLE:
            try:
                scraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'desktop': True
                    },
                    delay=10
                )
                response = scraper.get(url, timeout=30)
                if response.status_code == 200:
                    return response
            except Exception as e:
                logger.debug(f"CloudScraper failed: {e}")
        
        # Try curl_cffi with TLS fingerprint
        if CURL_CFFI_AVAILABLE:
            try:
                response = curl_requests.get(
                    url,
                    impersonate="chrome120",
                    headers=self._get_browser_headers(url)
                )
                if response.status_code == 200:
                    return response
            except Exception as e:
                logger.debug(f"curl_cffi failed: {e}")
        
        # Try with undetected Chrome
        if UNDETECTED_CHROME_AVAILABLE or SELENIUM_AVAILABLE:
            try:
                return self._fetch_with_undetected_browser(url)
            except Exception as e:
                logger.debug(f"Undetected browser failed: {e}")
        
        return None
    
    def _bypass_akamai(self, url: str, session: requests.Session) -> Optional[requests.Response]:
        """Bypass Akamai Bot Manager"""
        # Akamai requires proper sensor data and cookie generation
        # Use TLS client with proper fingerprint
        if TLS_CLIENT_AVAILABLE:
            try:
                tls_session = tls_client.Session(
                    client_identifier="chrome_120",
                    random_tls_extension_order=True
                )
                
                # First request to get cookies
                response = tls_session.get(url, headers=self._get_browser_headers(url))
                
                # If we have _abck cookie, we might need to generate sensor data
                if '_abck' in tls_session.cookies:
                    # Additional requests to build session
                    time.sleep(random.uniform(1, 2))
                    response = tls_session.get(url, headers=self._get_browser_headers(url))
                
                if response.status_code == 200:
                    return response
            except Exception as e:
                logger.debug(f"TLS client Akamai bypass failed: {e}")
        
        # Fall back to browser
        return self._fetch_with_undetected_browser(url)
    
    def _bypass_imperva(self, url: str, session: requests.Session) -> Optional[requests.Response]:
        """Bypass Imperva/Incapsula protection"""
        # Imperva uses cookie-based protection
        if CURL_CFFI_AVAILABLE:
            try:
                curl_session = curl_requests.Session(impersonate="chrome120")
                
                # First request
                response = curl_session.get(url, headers=self._get_browser_headers(url))
                
                # Imperva often requires JavaScript execution
                if 'incap_ses' not in str(curl_session.cookies):
                    # Try with browser
                    return self._fetch_with_undetected_browser(url)
                
                # Second request with cookies
                time.sleep(random.uniform(1, 3))
                response = curl_session.get(url, headers=self._get_browser_headers(url))
                
                if response.status_code == 200:
                    return response
            except Exception as e:
                logger.debug(f"Imperva bypass failed: {e}")
        
        return self._fetch_with_undetected_browser(url)
    
    def _fetch_with_undetected_browser(self, url: str) -> Optional[requests.Response]:
        """Fetch URL using undetected Chrome driver"""
        driver = None
        try:
            if UNDETECTED_CHROME_AVAILABLE:
                options = uc.ChromeOptions()
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-blink-features=AutomationControlled')
                
                driver = uc.Chrome(options=options)
            elif SELENIUM_AVAILABLE:
                options = ChromeOptions()
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-blink-features=AutomationControlled')
                options.add_experimental_option("excludeSwitches", ["enable-automation"])
                options.add_experimental_option('useAutomationExtension', False)
                
                driver = webdriver.Chrome(options=options)
                driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                    'source': '''
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        })
                    '''
                })
            else:
                return None
            
            driver.get(url)
            
            # Wait for page to load and any challenges to complete
            time.sleep(random.uniform(3, 5))
            
            # Try to wait for body to be present
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                pass
            
            # Get page content
            content = driver.page_source
            cookies = driver.get_cookies()
            
            # Create mock response
            class MockResponse:
                def __init__(self, text, cookies_list):
                    self.text = text
                    self.content = text.encode()
                    self.status_code = 200
                    self.headers = {'Content-Type': 'text/html'}
                    self.cookies = {c['name']: c['value'] for c in cookies_list}
                    self.ok = True
            
            return MockResponse(content, cookies)
            
        except Exception as e:
            logger.error(f"Undetected browser fetch failed: {e}")
            return None
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    def fetch(self, url: str, method: str = 'GET', **kwargs) -> Optional[Tuple[bytes, Dict]]:
        """
        Fetch URL with automatic protection bypass.
        Returns (content, headers) tuple or None on failure.
        """
        self.request_count += 1
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                # Add delay between requests
                if attempt > 0 or self.request_count > 1:
                    self._add_delay()
                
                # Get current client and settings
                headers = self._get_browser_headers(url)
                proxies = self._get_proxy()
                
                # Try different clients based on bypass mode
                response = None
                
                if self.bypass_mode == BypassMode.STANDARD:
                    response = self._standard_fetch(url, method, headers, proxies, **kwargs)
                
                elif self.bypass_mode in [BypassMode.CLOUDFLARE, BypassMode.AGGRESSIVE]:
                    response = self._cloudflare_fetch(url, method, headers, proxies, **kwargs)
                
                elif self.bypass_mode == BypassMode.STEALTH:
                    response = self._stealth_fetch(url, method, headers, proxies, **kwargs)
                
                elif self.bypass_mode == BypassMode.BROWSER_EMULATION:
                    response = self._fetch_with_undetected_browser(url)
                
                else:
                    response = self._aggressive_fetch(url, method, headers, proxies, **kwargs)
                
                if response is None:
                    continue
                
                # Check for protection
                content = response.text if hasattr(response, 'text') else response.content.decode('utf-8', errors='ignore')
                protection = self._detect_protection(response, content)
                
                if protection:
                    logger.info(f"Detected protection: {protection}, attempting bypass...")
                    response = self._handle_protection(url, protection, response)
                    
                    if response is None:
                        continue
                    
                    content = response.text if hasattr(response, 'text') else response.content.decode('utf-8', errors='ignore')
                
                # Success!
                headers_dict = dict(response.headers) if hasattr(response, 'headers') else {}
                content_bytes = response.content if hasattr(response, 'content') else content.encode()
                
                # Store cookies if persistence enabled
                if self.cookie_persistence and hasattr(response, 'cookies'):
                    domain = urlparse(url).netloc
                    self.cookies[domain] = dict(response.cookies)
                
                return content_bytes, headers_dict
                
            except Exception as e:
                last_error = e
                logger.warning(f"Fetch attempt {attempt + 1} failed: {e}")
                
                # Rotate session/proxy on failure
                if self.session_rotation:
                    self._init_clients()
                if self.proxy_rotation and self.proxies:
                    self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        logger.error(f"All fetch attempts failed for {url}: {last_error}")
        return None
    
    def _standard_fetch(self, url: str, method: str, headers: Dict, proxies: Dict, **kwargs) -> Optional[requests.Response]:
        """Standard fetch with requests library"""
        session = self.clients.get('requests')
        return session.request(method, url, headers=headers, proxies=proxies, timeout=30, **kwargs)
    
    def _cloudflare_fetch(self, url: str, method: str, headers: Dict, proxies: Dict, **kwargs) -> Optional[requests.Response]:
        """Fetch with Cloudflare bypass"""
        # Try CloudScraper first
        if CLOUDSCRAPER_AVAILABLE:
            try:
                scraper = self.clients.get('cloudscraper')
                if scraper:
                    return scraper.request(method, url, headers=headers, proxies=proxies, timeout=30, **kwargs)
            except:
                pass
        
        # Try curl_cffi
        if CURL_CFFI_AVAILABLE:
            try:
                return curl_requests.request(
                    method.lower(), url,
                    headers=headers,
                    proxies=proxies,
                    impersonate="chrome120",
                    timeout=30
                )
            except:
                pass
        
        # Fall back to standard
        return self._standard_fetch(url, method, headers, proxies, **kwargs)
    
    def _stealth_fetch(self, url: str, method: str, headers: Dict, proxies: Dict, **kwargs) -> Optional[requests.Response]:
        """Stealth fetch with fingerprint randomization"""
        # Use TLS client for best stealth
        if TLS_CLIENT_AVAILABLE:
            try:
                tls_session = tls_client.Session(
                    client_identifier=random.choice(list(self.TLS_FINGERPRINTS.values())),
                    random_tls_extension_order=True
                )
                return tls_session.request(method, url, headers=headers, proxy=proxies.get('http') if proxies else None)
            except:
                pass
        
        # Fall back to curl_cffi
        if CURL_CFFI_AVAILABLE:
            try:
                browser = random.choice(['chrome120', 'chrome119', 'firefox120', 'safari17_2'])
                return curl_requests.request(method.lower(), url, headers=headers, proxies=proxies, impersonate=browser)
            except:
                pass
        
        return self._standard_fetch(url, method, headers, proxies, **kwargs)
    
    def _aggressive_fetch(self, url: str, method: str, headers: Dict, proxies: Dict, **kwargs) -> Optional[requests.Response]:
        """Aggressive fetch trying all available methods"""
        # Try in order of effectiveness
        methods = [
            ('curl_cffi', lambda: curl_requests.request(method.lower(), url, headers=headers, proxies=proxies, impersonate="chrome120") if CURL_CFFI_AVAILABLE else None),
            ('cloudscraper', lambda: self.clients.get('cloudscraper').request(method, url, headers=headers, proxies=proxies, timeout=30) if CLOUDSCRAPER_AVAILABLE else None),
            ('tls_client', lambda: self.clients.get('tls_client').request(method, url, headers=headers) if TLS_CLIENT_AVAILABLE else None),
            ('httpx', lambda: self.clients.get('httpx').request(method, url, headers=headers) if HTTPX_AVAILABLE else None),
            ('requests', lambda: self._standard_fetch(url, method, headers, proxies, **kwargs)),
            ('browser', lambda: self._fetch_with_undetected_browser(url)),
        ]
        
        for name, fetch_func in methods:
            try:
                response = fetch_func()
                if response and (hasattr(response, 'status_code') and response.status_code == 200):
                    logger.debug(f"Success with {name}")
                    return response
            except Exception as e:
                logger.debug(f"{name} failed: {e}")
                continue
        
        return None
    
    def _handle_protection(self, url: str, protection: str, response) -> Optional[requests.Response]:
        """Handle detected protection"""
        session = self.clients.get('requests')
        
        if protection in ['cloudflare', 'cloudflare_challenge']:
            return self._bypass_cloudflare(url, session)
        
        elif protection in ['akamai', 'akamai_bot_manager']:
            return self._bypass_akamai(url, session)
        
        elif protection == 'imperva':
            return self._bypass_imperva(url, session)
        
        elif protection in ['recaptcha', 'hcaptcha']:
            # Extract site key from response
            content = response.text if hasattr(response, 'text') else response.content.decode()
            site_key = self._extract_captcha_key(content, protection)
            
            if site_key:
                token = self._solve_captcha(protection, site_key, url)
                if token:
                    # Submit with CAPTCHA token
                    return self._submit_captcha_response(url, token, protection)
            
            # Fall back to browser
            return self._fetch_with_undetected_browser(url)
        
        elif protection == 'rate_limited':
            # Wait and retry
            wait_time = self._get_rate_limit_wait(response)
            logger.info(f"Rate limited, waiting {wait_time}s")
            time.sleep(wait_time)
            return self._aggressive_fetch(url, 'GET', self._get_browser_headers(url), self._get_proxy())
        
        elif protection in ['datadome', 'perimeterx', 'distil', 'kasada', 'shape']:
            # These require browser-based bypass
            return self._fetch_with_undetected_browser(url)
        
        else:
            # Generic - try browser
            return self._fetch_with_undetected_browser(url)
    
    def _extract_captcha_key(self, content: str, captcha_type: str) -> Optional[str]:
        """Extract CAPTCHA site key from page content"""
        if captcha_type == 'recaptcha':
            patterns = [
                r'data-sitekey=["\']([^"\']+)["\']',
                r'grecaptcha\.execute\(["\']([^"\']+)["\']',
                r'sitekey:\s*["\']([^"\']+)["\']',
            ]
        else:  # hcaptcha
            patterns = [
                r'data-sitekey=["\']([^"\']+)["\']',
                r'sitekey:\s*["\']([^"\']+)["\']',
            ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        
        return None
    
    def _submit_captcha_response(self, url: str, token: str, captcha_type: str) -> Optional[requests.Response]:
        """Submit page with CAPTCHA response token"""
        # This is a simplified version - actual implementation depends on the site
        session = self.clients.get('requests')
        headers = self._get_browser_headers(url)
        
        # Try POST with token
        data = {
            'g-recaptcha-response': token if captcha_type == 'recaptcha' else None,
            'h-captcha-response': token if captcha_type == 'hcaptcha' else None,
        }
        data = {k: v for k, v in data.items() if v}
        
        return session.post(url, headers=headers, data=data, timeout=30)
    
    def _get_rate_limit_wait(self, response) -> int:
        """Get wait time from rate limit response"""
        # Check Retry-After header
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                return int(retry_after)
            except:
                pass
        
        # Check X-RateLimit-Reset
        reset_time = response.headers.get('X-RateLimit-Reset')
        if reset_time:
            try:
                reset_timestamp = int(reset_time)
                return max(0, reset_timestamp - int(time.time()))
            except:
                pass
        
        # Default wait
        return random.randint(30, 60)


class ScrubMode(Enum):
    """Scrubbing operation modes"""
    REDACT = auto()          # Replace with [REDACTED]
    HASH = auto()            # Replace with hash
    MASK = auto()            # Partial masking (e.g., ****1234)
    ENCRYPT = auto()         # Reversible encryption
    TOKENIZE = auto()        # Replace with token, store mapping
    RANDOM = auto()          # Random replacement
    CUSTOM = auto()          # Custom replacement function
    BLUR = auto()            # For images - blur region
    REMOVE = auto()          # Complete removal
    HIGHLIGHT = auto()       # Highlight for review (no replacement)


class ContentType(Enum):
    """Supported content types"""
    HTML = auto()
    PDF = auto()
    DOCX = auto()
    IMAGE = auto()
    TEXT = auto()
    JSON = auto()
    XML = auto()
    CSV = auto()
    MARKDOWN = auto()
    CODE = auto()
    EMAIL = auto()
    DATABASE = auto()


class PIIType(Enum):
    """Personally Identifiable Information types"""
    EMAIL = auto()
    PHONE = auto()
    SSN = auto()
    CREDIT_CARD = auto()
    IP_ADDRESS = auto()
    ADDRESS = auto()
    NAME = auto()
    DATE_OF_BIRTH = auto()
    PASSPORT = auto()
    DRIVER_LICENSE = auto()
    BANK_ACCOUNT = auto()
    MEDICAL_ID = auto()
    CUSTOM = auto()


@dataclass
class ScrubMatch:
    """Represents a single scrub match"""
    url: str
    tag: Optional[str]
    pattern: str
    matched_text: str
    replacement: str
    context_before: str
    context_after: str
    line_number: Optional[int]
    char_offset: int
    pii_type: Optional[PIIType]
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    content_type: ContentType = ContentType.HTML
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScrubResult:
    """Result of scrubbing operation"""
    url: str
    original_content: str
    scrubbed_content: str
    matches: List[ScrubMatch]
    content_type: ContentType
    processing_time: float
    checksum_before: str
    checksum_after: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEntry:
    """Blockchain-style audit entry"""
    entry_id: str
    timestamp: datetime
    operation: str
    url: str
    matches_count: int
    checksum_before: str
    checksum_after: str
    user: str
    previous_hash: str
    entry_hash: str = ""
    
    def __post_init__(self):
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        data = f"{self.entry_id}{self.timestamp}{self.operation}{self.url}{self.matches_count}{self.checksum_before}{self.checksum_after}{self.user}{self.previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()


class PIIDetector:
    """Advanced PII detection using regex and ML"""
    
    # Comprehensive PII patterns
    PATTERNS = {
        PIIType.EMAIL: [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*\[\s*at\s*\]\s*[A-Za-z0-9.-]+\s*\[\s*dot\s*\]\s*[A-Z|a-z]{2,}\b',
        ],
        PIIType.PHONE: [
            r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            r'\b(?:\+?44[-.\s]?)?\(?0?[0-9]{2,4}\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}\b',
            r'\b(?:\+?[0-9]{1,3}[-.\s]?)?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}\b',
        ],
        PIIType.SSN: [
            r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        ],
        PIIType.CREDIT_CARD: [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b',  # Mastercard
            r'\b3[47][0-9]{13}\b',  # Amex
            r'\b(?:6011|65[0-9]{2}|64[4-9][0-9])[0-9]{12}\b',  # Discover
            r'\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',  # Generic
        ],
        PIIType.IP_ADDRESS: [
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',  # IPv6
        ],
        PIIType.ADDRESS: [
            r'\b\d{1,5}\s+[\w\s]+(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|parkway|pkwy|circle|cir|boulevard|blvd)\b',
        ],
        PIIType.DATE_OF_BIRTH: [
            r'\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b',
            r'\b(?:19|20)\d{2}[/-](?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])\b',
        ],
        PIIType.PASSPORT: [
            r'\b[A-Z]{1,2}[0-9]{6,9}\b',
        ],
        PIIType.BANK_ACCOUNT: [
            r'\b[0-9]{8,17}\b',  # Generic bank account
            r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b',  # IBAN
        ],
    }
    
    def __init__(self, use_ml: bool = True, confidence_threshold: float = 0.7):
        self.use_ml = use_ml and (NLP_AVAILABLE or TRANSFORMERS_AVAILABLE)
        self.confidence_threshold = confidence_threshold
        self.compiled_patterns = self._compile_patterns()
        self.nlp = None
        self.ner_pipeline = None
        
        if self.use_ml:
            self._init_ml_models()
    
    def _compile_patterns(self) -> Dict[PIIType, List[re.Pattern]]:
        compiled = {}
        for pii_type, patterns in self.PATTERNS.items():
            compiled[pii_type] = [re.compile(p, re.IGNORECASE) for p in patterns]
        return compiled
    
    def _init_ml_models(self):
        """Initialize ML models for enhanced PII detection"""
        try:
            if NLP_AVAILABLE:
                self.nlp = spacy.load("en_core_web_sm")
            if TRANSFORMERS_AVAILABLE:
                self.ner_pipeline = pipeline(
                    "ner",
                    model="dslim/bert-base-NER",
                    aggregation_strategy="simple"
                )
        except Exception as e:
            logger.warning(f"Failed to load ML models: {e}")
            self.use_ml = False
    
    def detect(self, text: str) -> List[Tuple[PIIType, str, int, int, float]]:
        """Detect all PII in text, returns list of (type, match, start, end, confidence)"""
        results = []
        
        # Regex-based detection
        for pii_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    confidence = self._calculate_confidence(pii_type, match.group())
                    if confidence >= self.confidence_threshold:
                        results.append((pii_type, match.group(), match.start(), match.end(), confidence))
        
        # ML-based detection
        if self.use_ml:
            ml_results = self._ml_detect(text)
            results.extend(ml_results)
        
        # Deduplicate overlapping matches
        results = self._deduplicate(results)
        
        return results
    
    def _calculate_confidence(self, pii_type: PIIType, match: str) -> float:
        """Calculate confidence score for a match"""
        confidence = 0.8  # Base confidence for regex match
        
        # Adjust based on PII type and validation
        if pii_type == PIIType.CREDIT_CARD:
            if self._luhn_check(match.replace('-', '').replace(' ', '')):
                confidence = 0.95
            else:
                confidence = 0.3
        elif pii_type == PIIType.EMAIL:
            if '@' in match and '.' in match.split('@')[-1]:
                confidence = 0.95
        elif pii_type == PIIType.SSN:
            confidence = 0.85
        elif pii_type == PIIType.PHONE:
            digits = re.sub(r'\D', '', match)
            if 10 <= len(digits) <= 15:
                confidence = 0.85
        
        return confidence
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        try:
            digits = [int(d) for d in card_number if d.isdigit()]
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(divmod(d * 2, 10))
            return checksum % 10 == 0
        except:
            return False
    
    def _ml_detect(self, text: str) -> List[Tuple[PIIType, str, int, int, float]]:
        """Use ML models for PII detection"""
        results = []
        
        if self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                pii_type = self._entity_to_pii_type(ent.label_)
                if pii_type:
                    results.append((pii_type, ent.text, ent.start_char, ent.end_char, 0.85))
        
        if self.ner_pipeline:
            try:
                entities = self.ner_pipeline(text)
                for ent in entities:
                    pii_type = self._entity_to_pii_type(ent['entity_group'])
                    if pii_type:
                        results.append((pii_type, ent['word'], ent['start'], ent['end'], ent['score']))
            except:
                pass
        
        return results
    
    def _entity_to_pii_type(self, entity_label: str) -> Optional[PIIType]:
        """Map NER entity labels to PII types"""
        mapping = {
            'PERSON': PIIType.NAME,
            'PER': PIIType.NAME,
            'ORG': None,
            'GPE': PIIType.ADDRESS,
            'LOC': PIIType.ADDRESS,
            'DATE': PIIType.DATE_OF_BIRTH,
            'CARDINAL': None,
            'EMAIL': PIIType.EMAIL,
        }
        return mapping.get(entity_label)
    
    def _deduplicate(self, results: List[Tuple]) -> List[Tuple]:
        """Remove overlapping matches, keeping highest confidence"""
        if not results:
            return results
        
        # Sort by start position, then by confidence (descending)
        sorted_results = sorted(results, key=lambda x: (x[2], -x[4]))
        
        deduped = []
        last_end = -1
        
        for result in sorted_results:
            if result[2] >= last_end:
                deduped.append(result)
                last_end = result[3]
        
        return deduped


class ContentProcessor:
    """Process different content types for scrubbing"""
    
    def __init__(self):
        self.processors = {
            ContentType.HTML: self._process_html,
            ContentType.PDF: self._process_pdf,
            ContentType.DOCX: self._process_docx,
            ContentType.IMAGE: self._process_image,
            ContentType.TEXT: self._process_text,
            ContentType.JSON: self._process_json,
            ContentType.XML: self._process_xml,
            ContentType.CSV: self._process_csv,
            ContentType.MARKDOWN: self._process_markdown,
            ContentType.EMAIL: self._process_email,
        }
    
    def detect_content_type(self, content: bytes, url: str = "", headers: Dict = None) -> ContentType:
        """Detect content type from content, URL, or headers"""
        headers = headers or {}
        content_type_header = headers.get('Content-Type', '').lower()
        
        if 'text/html' in content_type_header:
            return ContentType.HTML
        elif 'application/json' in content_type_header:
            return ContentType.JSON
        elif 'application/xml' in content_type_header or 'text/xml' in content_type_header:
            return ContentType.XML
        elif 'text/csv' in content_type_header:
            return ContentType.CSV
        elif 'application/pdf' in content_type_header:
            return ContentType.PDF
        elif 'image/' in content_type_header:
            return ContentType.IMAGE
        
        # Check by extension
        ext = Path(urlparse(url).path).suffix.lower()
        ext_mapping = {
            '.html': ContentType.HTML, '.htm': ContentType.HTML,
            '.pdf': ContentType.PDF,
            '.docx': ContentType.DOCX, '.doc': ContentType.DOCX,
            '.json': ContentType.JSON,
            '.xml': ContentType.XML,
            '.csv': ContentType.CSV,
            '.md': ContentType.MARKDOWN,
            '.txt': ContentType.TEXT,
            '.jpg': ContentType.IMAGE, '.jpeg': ContentType.IMAGE,
            '.png': ContentType.IMAGE, '.gif': ContentType.IMAGE,
            '.eml': ContentType.EMAIL, '.msg': ContentType.EMAIL,
        }
        if ext in ext_mapping:
            return ext_mapping[ext]
        
        # Check magic bytes
        if content:
            if content[:4] == b'%PDF':
                return ContentType.PDF
            elif content[:2] == b'PK':
                return ContentType.DOCX
            elif content[:1] in [b'{', b'[']:
                return ContentType.JSON
            elif content[:5] == b'<?xml':
                return ContentType.XML
        
        return ContentType.HTML  # Default
    
    def process(self, content: Union[str, bytes], content_type: ContentType) -> str:
        """Process content and extract text for scrubbing"""
        processor = self.processors.get(content_type, self._process_text)
        return processor(content)
    
    def _process_html(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_pdf(self, content: Union[str, bytes]) -> str:
        if not PDF_AVAILABLE:
            logger.warning("PDF processing not available. Install PyPDF2 and pdfplumber.")
            return ""
        
        if isinstance(content, str):
            content = content.encode()
        
        text = ""
        try:
            with io.BytesIO(content) as f:
                with pdfplumber.open(f) as pdf:
                    for page in pdf.pages:
                        text += page.extract_text() or ""
                        text += "\n"
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
        
        return text
    
    def _process_docx(self, content: Union[str, bytes]) -> str:
        if not DOCX_AVAILABLE:
            logger.warning("DOCX processing not available. Install python-docx.")
            return ""
        
        if isinstance(content, str):
            content = content.encode()
        
        text = ""
        try:
            with io.BytesIO(content) as f:
                doc = DocxDocument(f)
                for para in doc.paragraphs:
                    text += para.text + "\n"
        except Exception as e:
            logger.error(f"DOCX processing error: {e}")
        
        return text
    
    def _process_image(self, content: Union[str, bytes]) -> str:
        if not OCR_AVAILABLE:
            logger.warning("OCR not available. Install pytesseract and Pillow.")
            return ""
        
        if isinstance(content, str):
            content = content.encode()
        
        try:
            image = Image.open(io.BytesIO(content))
            text = pytesseract.image_to_string(image)
            return text
        except Exception as e:
            logger.error(f"Image OCR error: {e}")
            return ""
    
    def _process_text(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_json(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_xml(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_csv(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_markdown(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content
    
    def _process_email(self, content: Union[str, bytes]) -> str:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        return content


class TokenVault:
    """Secure token storage for reversible tokenization"""
    
    def __init__(self, encryption_key: Optional[str] = None, storage_path: Optional[str] = None):
        self.storage_path = storage_path or tempfile.mktemp(suffix='.vault.db')
        self.tokens: Dict[str, str] = {}
        self.reverse_tokens: Dict[str, str] = {}
        self.cipher = None
        
        if encryption_key and CRYPTO_AVAILABLE:
            self._init_encryption(encryption_key)
        
        self._init_storage()
    
    def _init_encryption(self, key: str):
        """Initialize encryption cipher"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'wordscrubber_salt',
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        self.cipher = Fernet(derived_key)
    
    def _init_storage(self):
        """Initialize SQLite storage"""
        self.conn = sqlite3.connect(self.storage_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                original TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')
        self.conn.commit()
    
    def tokenize(self, value: str, prefix: str = "TOK") -> str:
        """Create a token for a value"""
        if value in self.tokens:
            return self.tokens[value]
        
        token = f"[{prefix}_{hashlib.sha256(value.encode()).hexdigest()[:12]}]"
        
        stored_value = value
        if self.cipher:
            stored_value = self.cipher.encrypt(value.encode()).decode()
        
        self.tokens[value] = token
        self.reverse_tokens[token] = stored_value
        
        self.conn.execute(
            'INSERT OR REPLACE INTO tokens (token, original) VALUES (?, ?)',
            (token, stored_value)
        )
        self.conn.commit()
        
        return token
    
    def detokenize(self, token: str) -> Optional[str]:
        """Retrieve original value from token"""
        if token in self.reverse_tokens:
            value = self.reverse_tokens[token]
            if self.cipher:
                value = self.cipher.decrypt(value.encode()).decode()
            return value
        
        cursor = self.conn.execute('SELECT original FROM tokens WHERE token = ?', (token,))
        row = cursor.fetchone()
        if row:
            value = row[0]
            if self.cipher:
                value = self.cipher.decrypt(value.encode()).decode()
            self.reverse_tokens[token] = row[0]
            return value
        
        return None
    
    def export(self, filepath: str, include_originals: bool = False):
        """Export token mappings"""
        data = []
        cursor = self.conn.execute('SELECT token, original, created_at FROM tokens')
        for row in cursor:
            entry = {'token': row[0], 'created_at': row[2]}
            if include_originals:
                value = row[1]
                if self.cipher:
                    value = self.cipher.decrypt(value.encode()).decode()
                entry['original'] = value
            data.append(entry)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def close(self):
        """Close storage connection"""
        self.conn.close()


class AuditChain:
    """Blockchain-style audit trail"""
    
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or tempfile.mktemp(suffix='.audit.db')
        self.chain: List[AuditEntry] = []
        self._init_storage()
        self._load_chain()
    
    def _init_storage(self):
        """Initialize SQLite storage"""
        self.conn = sqlite3.connect(self.storage_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_chain (
                entry_id TEXT PRIMARY KEY,
                timestamp TIMESTAMP,
                operation TEXT,
                url TEXT,
                matches_count INTEGER,
                checksum_before TEXT,
                checksum_after TEXT,
                user TEXT,
                previous_hash TEXT,
                entry_hash TEXT
            )
        ''')
        self.conn.commit()
    
    def _load_chain(self):
        """Load existing chain from storage"""
        cursor = self.conn.execute('SELECT * FROM audit_chain ORDER BY timestamp')
        for row in cursor:
            entry = AuditEntry(
                entry_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                operation=row[2],
                url=row[3],
                matches_count=row[4],
                checksum_before=row[5],
                checksum_after=row[6],
                user=row[7],
                previous_hash=row[8],
                entry_hash=row[9]
            )
            self.chain.append(entry)
    
    def add_entry(self, operation: str, url: str, matches_count: int,
                  checksum_before: str, checksum_after: str, user: str = "system") -> AuditEntry:
        """Add a new audit entry"""
        previous_hash = self.chain[-1].entry_hash if self.chain else "0" * 64
        
        entry = AuditEntry(
            entry_id=hashlib.sha256(f"{datetime.now()}{url}{random.random()}".encode()).hexdigest()[:16],
            timestamp=datetime.now(),
            operation=operation,
            url=url,
            matches_count=matches_count,
            checksum_before=checksum_before,
            checksum_after=checksum_after,
            user=user,
            previous_hash=previous_hash
        )
        
        self.chain.append(entry)
        
        self.conn.execute('''
            INSERT INTO audit_chain VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.entry_id, entry.timestamp.isoformat(), entry.operation,
            entry.url, entry.matches_count, entry.checksum_before,
            entry.checksum_after, entry.user, entry.previous_hash, entry.entry_hash
        ))
        self.conn.commit()
        
        return entry
    
    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify integrity of the audit chain"""
        errors = []
        
        for i, entry in enumerate(self.chain):
            # Verify hash
            expected_hash = entry._compute_hash()
            if entry.entry_hash != expected_hash:
                errors.append(f"Entry {entry.entry_id}: Hash mismatch")
            
            # Verify chain link
            if i > 0:
                if entry.previous_hash != self.chain[i-1].entry_hash:
                    errors.append(f"Entry {entry.entry_id}: Chain link broken")
        
        return len(errors) == 0, errors
    
    def export(self, filepath: str, format: str = 'json'):
        """Export audit chain"""
        data = [asdict(entry) for entry in self.chain]
        
        for entry in data:
            entry['timestamp'] = entry['timestamp'].isoformat()
        
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        elif format == 'csv':
            if data:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
    
    def close(self):
        """Close storage connection"""
        self.conn.close()


class BrowserEngine:
    """Headless browser for JavaScript rendering"""
    
    def __init__(self, engine: str = 'playwright', headless: bool = True):
        self.engine = engine
        self.headless = headless
        self.browser = None
        self.driver = None
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
    
    def start(self):
        """Start browser engine"""
        if self.engine == 'playwright' and PLAYWRIGHT_AVAILABLE:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=self.headless)
        elif self.engine == 'selenium' and SELENIUM_AVAILABLE:
            options = ChromeOptions()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            self.driver = webdriver.Chrome(options=options)
        else:
            raise RuntimeError(f"Browser engine '{self.engine}' not available")
    
    def stop(self):
        """Stop browser engine"""
        if self.browser:
            self.browser.close()
            self.playwright.stop()
        if self.driver:
            self.driver.quit()
    
    def get_page(self, url: str, wait_for: Optional[str] = None, timeout: int = 30000) -> str:
        """Get fully rendered page content"""
        if self.browser:
            page = self.browser.new_page()
            try:
                page.goto(url, timeout=timeout)
                if wait_for:
                    page.wait_for_selector(wait_for, timeout=timeout)
                else:
                    page.wait_for_load_state('networkidle', timeout=timeout)
                content = page.content()
            finally:
                page.close()
            return content
        
        elif self.driver:
            self.driver.get(url)
            if wait_for:
                WebDriverWait(self.driver, timeout // 1000).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, wait_for))
                )
            return self.driver.page_source
        
        raise RuntimeError("No browser engine running")
    
    def execute_script(self, url: str, script: str) -> Any:
        """Execute JavaScript and return result"""
        if self.browser:
            page = self.browser.new_page()
            try:
                page.goto(url)
                result = page.evaluate(script)
            finally:
                page.close()
            return result
        
        elif self.driver:
            self.driver.get(url)
            return self.driver.execute_script(script)
        
        raise RuntimeError("No browser engine running")


class ProxyManager:
    """Manage proxy rotation and TOR integration"""
    
    def __init__(self, proxies: List[str] = None, use_tor: bool = False,
                 rotate_interval: int = 10):
        self.proxies = proxies or []
        self.use_tor = use_tor
        self.rotate_interval = rotate_interval
        self.current_index = 0
        self.request_count = 0
        self.tor_controller = None
        
        if use_tor:
            self._init_tor()
    
    def _init_tor(self):
        """Initialize TOR connection"""
        try:
            from stem import Signal
            from stem.control import Controller
            self.tor_controller = Controller.from_port(port=9051)
            self.tor_controller.authenticate()
            # Add TOR proxy
            self.proxies.insert(0, 'socks5://127.0.0.1:9050')
        except Exception as e:
            logger.warning(f"TOR initialization failed: {e}")
            self.use_tor = False
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get current proxy configuration"""
        if not self.proxies:
            return None
        
        self.request_count += 1
        
        if self.request_count % self.rotate_interval == 0:
            self._rotate()
        
        proxy_url = self.proxies[self.current_index]
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def _rotate(self):
        """Rotate to next proxy"""
        if self.use_tor and self.tor_controller:
            try:
                from stem import Signal
                self.tor_controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Wait for new circuit
                return
            except:
                pass
        
        self.current_index = (self.current_index + 1) % len(self.proxies)
    
    def close(self):
        """Close connections"""
        if self.tor_controller:
            self.tor_controller.close()


class CloudStorageHandler:
    """Handle cloud storage operations (S3, GCS)"""
    
    def __init__(self, aws_credentials: Dict = None, gcs_credentials: str = None):
        self.s3_client = None
        self.gcs_client = None
        
        if aws_credentials and AWS_AVAILABLE:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_credentials.get('access_key'),
                aws_secret_access_key=aws_credentials.get('secret_key'),
                region_name=aws_credentials.get('region', 'us-east-1')
            )
        
        if gcs_credentials and GCS_AVAILABLE:
            self.gcs_client = gcs_storage.Client.from_service_account_json(gcs_credentials)
    
    def fetch_s3(self, bucket: str, key: str) -> bytes:
        """Fetch content from S3"""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        response = self.s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()
    
    def upload_s3(self, bucket: str, key: str, content: bytes, content_type: str = None):
        """Upload content to S3"""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        extra_args = {}
        if content_type:
            extra_args['ContentType'] = content_type
        
        self.s3_client.put_object(Bucket=bucket, Key=key, Body=content, **extra_args)
    
    def fetch_gcs(self, bucket: str, blob_name: str) -> bytes:
        """Fetch content from GCS"""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        bucket_obj = self.gcs_client.bucket(bucket)
        blob = bucket_obj.blob(blob_name)
        return blob.download_as_bytes()
    
    def upload_gcs(self, bucket: str, blob_name: str, content: bytes, content_type: str = None):
        """Upload content to GCS"""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        bucket_obj = self.gcs_client.bucket(bucket)
        blob = bucket_obj.blob(blob_name)
        blob.upload_from_string(content, content_type=content_type)


class ScrubStats:
    """Track scrubbing statistics"""
    
    def __init__(self):
        self.total_urls = 0
        self.processed_urls = 0
        self.failed_urls = 0
        self.total_matches = 0
        self.matches_by_type: Dict[PIIType, int] = defaultdict(int)
        self.matches_by_url: Dict[str, int] = defaultdict(int)
        self.processing_time = 0.0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.bytes_processed = 0
        self.errors: List[Dict] = []
    
    def start(self):
        self.start_time = datetime.now()
    
    def stop(self):
        self.end_time = datetime.now()
        self.processing_time = (self.end_time - self.start_time).total_seconds()
    
    def add_match(self, url: str, pii_type: Optional[PIIType] = None):
        self.total_matches += 1
        self.matches_by_url[url] += 1
        if pii_type:
            self.matches_by_type[pii_type] += 1
    
    def add_error(self, url: str, error: str):
        self.failed_urls += 1
        self.errors.append({'url': url, 'error': error, 'timestamp': datetime.now().isoformat()})
    
    def to_dict(self) -> Dict:
        return {
            'total_urls': self.total_urls,
            'processed_urls': self.processed_urls,
            'failed_urls': self.failed_urls,
            'total_matches': self.total_matches,
            'matches_by_type': {str(k): v for k, v in self.matches_by_type.items()},
            'matches_by_url': dict(self.matches_by_url),
            'processing_time_seconds': self.processing_time,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'bytes_processed': self.bytes_processed,
            'urls_per_second': self.processed_urls / self.processing_time if self.processing_time > 0 else 0,
            'errors': self.errors
        }


class WordScrubber:
    """
    ULTRA ADVANCED Word Scrubbing Engine
    
    Enterprise-grade content filtering with:
    - Multi-protocol support (HTTP/HTTPS/FTP/FILE/S3/GCS)
    - AI-powered PII detection
    - JavaScript rendering
    - Blockchain audit trail
    - Cloud storage integration
    - Parallel/async processing
    - Reversible tokenization
    - Multiple export formats
    """
    
    def __init__(
        self,
        base_url: str,
        targets: List[Union[str, Dict]],
        replacement: Union[str, Callable] = "[REDACTED]",
        max_depth: int = 2,
        same_domain: bool = True,
        context_rules: Dict = None,
        word_boundary: bool = True,
        partial_match: bool = False,
        report: bool = True,
        login: Dict = None,
        session: requests.Session = None,
        rate_limit: float = 0,
        retries: int = 3,
        include_tags: List[str] = None,
        exclude_tags: List[str] = None,
        ignore_urls: List[str] = None,
        include_urls: List[str] = None,
        parallelism: int = 8,
        export_format: str = None,
        verbose: bool = False,
        protocol_handlers: Dict = None,
        # Advanced options
        scrub_mode: ScrubMode = ScrubMode.REDACT,
        detect_pii: bool = True,
        pii_types: List[PIIType] = None,
        use_browser: bool = False,
        browser_engine: str = 'playwright',
        use_ml: bool = True,
        enable_audit: bool = True,
        enable_tokenization: bool = False,
        encryption_key: str = None,
        proxies: List[str] = None,
        use_tor: bool = False,
        user_agent: str = None,
        timeout: int = 30,
        max_content_size: int = 50 * 1024 * 1024,  # 50MB
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        custom_headers: Dict = None,
        cookies: Dict = None,
        process_pdfs: bool = True,
        process_images: bool = True,
        process_documents: bool = True,
        extract_metadata: bool = True,
        scrub_metadata: bool = True,
        preserve_formatting: bool = True,
        case_sensitive: bool = False,
        context_window: int = 50,
        min_confidence: float = 0.7,
        dry_run: bool = False,
        incremental: bool = False,
        cache_enabled: bool = True,
        cache_ttl: int = 3600,
        webhook_url: str = None,
        notification_email: str = None,
        aws_credentials: Dict = None,
        gcs_credentials: str = None,
        storage_path: str = None,
        # PROTOCOL BYPASS OPTIONS - Defeat any website protection
        bypass_mode: BypassMode = BypassMode.AGGRESSIVE,
        enable_bypass: bool = True,
        captcha_solver: str = None,  # '2captcha', 'anticaptcha', 'capsolver'
        captcha_api_key: str = None,
        rotate_user_agents: bool = True,
        rotate_proxies: bool = True,
        proxy_rotation_interval: int = 5,
        impersonate_browser: str = 'chrome_win',  # Browser fingerprint to impersonate
        max_bypass_attempts: int = 5,
        bypass_cloudflare: bool = True,
        bypass_akamai: bool = True,
        bypass_imperva: bool = True,
        bypass_datadome: bool = True,
        bypass_perimeterx: bool = True,
        force_browser_on_block: bool = True,  # Use real browser if blocked
        stealth_mode: bool = True,  # Enable all stealth features
        randomize_timing: bool = True,  # Random delays between requests
        min_request_delay: float = 0.5,
        max_request_delay: float = 3.0,
    ):
        """Initialize the Word Scrubber with extensive configuration options."""
        
        # Core settings
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.targets = self._compile_targets(targets, word_boundary, partial_match, case_sensitive)
        self.replacement = replacement
        self.max_depth = max_depth
        self.same_domain = same_domain
        self.context_rules = context_rules or {"skip_tags": ["script", "style", "noscript"], "only_visible": True}
        self.report_enabled = report
        self.rate_limit = rate_limit
        self.retries = retries
        self.parallelism = parallelism
        self.export_format = export_format
        self.verbose = verbose
        self.timeout = timeout
        self.max_content_size = max_content_size
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.dry_run = dry_run
        self.incremental = incremental
        self.context_window = context_window
        self.preserve_formatting = preserve_formatting
        
        # PROTOCOL BYPASS SETTINGS - Override any website protection
        self.enable_bypass = enable_bypass
        self.bypass_mode = bypass_mode if isinstance(bypass_mode, BypassMode) else BypassMode[bypass_mode.upper()]
        self.captcha_solver = captcha_solver
        self.captcha_api_key = captcha_api_key
        self.rotate_user_agents = rotate_user_agents
        self.rotate_proxies = rotate_proxies
        self.proxy_rotation_interval = proxy_rotation_interval
        self.impersonate_browser = impersonate_browser
        self.max_bypass_attempts = max_bypass_attempts
        self.bypass_cloudflare = bypass_cloudflare
        self.bypass_akamai = bypass_akamai
        self.bypass_imperva = bypass_imperva
        self.bypass_datadome = bypass_datadome
        self.bypass_perimeterx = bypass_perimeterx
        self.force_browser_on_block = force_browser_on_block
        self.stealth_mode = stealth_mode
        self.randomize_timing = randomize_timing
        self.min_request_delay = min_request_delay
        self.max_request_delay = max_request_delay
        
        # URL filtering
        self.include_tags = set(include_tags) if include_tags else None
        self.exclude_tags = set(exclude_tags) if exclude_tags else set(self.context_rules.get("skip_tags", []))
        self.ignore_urls = [re.compile(p) for p in (ignore_urls or [])]
        self.include_urls = [re.compile(p) for p in (include_urls or [])]
        
        # Domain extraction
        self.domain = urlparse(base_url).netloc if base_url else ""
        
        # Advanced mode settings
        self.scrub_mode = scrub_mode if isinstance(scrub_mode, ScrubMode) else ScrubMode[scrub_mode.upper()]
        self.detect_pii = detect_pii
        self.pii_types = pii_types or list(PIIType)
        self.use_browser = use_browser
        self.browser_engine = browser_engine
        self.use_ml = use_ml
        self.enable_audit = enable_audit
        self.enable_tokenization = enable_tokenization
        self.min_confidence = min_confidence
        
        # Content processing settings
        self.process_pdfs = process_pdfs
        self.process_images = process_images
        self.process_documents = process_documents
        self.extract_metadata = extract_metadata
        self.scrub_metadata = scrub_metadata
        
        # Session setup
        self.session = session or requests.Session()
        self._setup_session(user_agent, custom_headers, cookies, login)
        
        # Initialize components
        self.pii_detector = PIIDetector(use_ml=use_ml, confidence_threshold=min_confidence) if detect_pii else None
        self.content_processor = ContentProcessor()
        self.token_vault = TokenVault(encryption_key, storage_path) if enable_tokenization else None
        self.audit_chain = AuditChain(storage_path) if enable_audit else None
        self.proxy_manager = ProxyManager(proxies, use_tor) if proxies or use_tor else None
        self.cloud_handler = CloudStorageHandler(aws_credentials, gcs_credentials) if aws_credentials or gcs_credentials else None
        self.browser = None
        
        # Initialize Protocol Bypass Engine - CORE ANTI-PROTECTION SYSTEM
        self.protocol_bypass = None
        if enable_bypass:
            self.protocol_bypass = ProtocolBypass(
                bypass_mode=self.bypass_mode,
                proxies=proxies,
                use_tor=use_tor,
                captcha_solver=captcha_solver,
                captcha_api_key=captcha_api_key,
                rotate_interval=proxy_rotation_interval,
                timeout=timeout,
                max_retries=retries
            )
            logger.info(f"Protocol Bypass Engine initialized in {self.bypass_mode.name} mode")
        
        # Protocol handlers
        self.protocol_handlers = protocol_handlers or self._default_protocol_handlers()
        
        # State
        self.visited: Set[str] = set()
        self.results: Dict[str, ScrubResult] = {}
        self.scrub_report: List[ScrubMatch] = []
        self.stats = ScrubStats()
        self.lock = threading.Lock()
        
        # Cache
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[datetime, Any]] = {}
        
        # Notifications
        self.webhook_url = webhook_url
        self.notification_email = notification_email
        
        # Logging
        if verbose:
            logging.getLogger(__name__).setLevel(logging.DEBUG)

    def _setup_session(self, user_agent: str, custom_headers: Dict, cookies: Dict, login: Dict):
        """Configure session with authentication and headers"""
        default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        self.session.headers.update({
            'User-Agent': user_agent or default_ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        if cookies:
            self.session.cookies.update(cookies)
        
        if login:
            self._do_login(login)
    
    def _do_login(self, login: Dict):
        """Perform login to obtain session authentication"""
        try:
            login_url = login.get('login_url')
            login_data = login.get('data', {})
            login_headers = login.get('headers', {})
            login_method = login.get('method', 'POST').upper()
            
            if login_method == 'POST':
                resp = self.session.post(
                    login_url,
                    data=login_data,
                    headers=login_headers,
                    timeout=self.timeout
                )
            else:
                resp = self.session.get(
                    login_url,
                    params=login_data,
                    headers=login_headers,
                    timeout=self.timeout
                )
            
            if self.verbose:
                logger.info(f"Login response: {resp.status_code}")
            
            # Handle OAuth token response
            if 'access_token' in resp.text:
                try:
                    token_data = resp.json()
                    self.session.headers['Authorization'] = f"Bearer {token_data['access_token']}"
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Login failed: {e}")

    def _default_protocol_handlers(self) -> Dict[str, Callable]:
        """Get default protocol handlers"""
        return {
            'http': self._fetch_http,
            'https': self._fetch_http,
            'ftp': self._fetch_ftp,
            'file': self._fetch_file,
            's3': self._fetch_s3,
            'gs': self._fetch_gcs,
        }
    
    def _fetch_http(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """
        ULTRA ADVANCED HTTP Fetch with Protocol Bypass
        
        Defeats ANY website protection including:
        - Cloudflare (all versions)
        - Akamai Bot Manager
        - Imperva/Incapsula
        - DataDome
        - PerimeterX
        - reCAPTCHA / hCaptcha
        - Rate limiting
        - WAF/Firewall rules
        - Bot detection
        - Fingerprint analysis
        """
        
        # Apply randomized timing if enabled
        if self.randomize_timing:
            delay = random.uniform(self.min_request_delay, self.max_request_delay)
            time.sleep(delay)
        elif self.rate_limit > 0:
            time.sleep(self.rate_limit)
        
        # USE PROTOCOL BYPASS ENGINE if enabled
        if self.enable_bypass and self.protocol_bypass:
            try:
                logger.debug(f"Using Protocol Bypass Engine for: {url}")
                
                content, headers, status = self.protocol_bypass.fetch(url)
                
                if content:
                    # Check content size
                    if len(content) > self.max_content_size:
                        logger.warning(f"Content exceeded max size: {url}")
                        return None
                    
                    # Convert string content to bytes
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    
                    return content, headers or {}
                else:
                    logger.warning(f"Protocol Bypass failed for {url}, trying fallback methods")
                    
            except Exception as e:
                logger.warning(f"Protocol Bypass error for {url}: {e}")
        
        # FALLBACK: Try with browser if bypass failed and force_browser_on_block is enabled
        if self.force_browser_on_block and (self.use_browser or PLAYWRIGHT_AVAILABLE or SELENIUM_AVAILABLE):
            try:
                result = self._fetch_with_browser(url)
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Browser fallback failed: {e}")
        
        # FINAL FALLBACK: Standard request with retries
        for attempt in range(self.retries):
            try:
                # Get proxy if configured
                proxies = self.proxy_manager.get_proxy() if self.proxy_manager else None
                
                # Make request
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=self.verify_ssl,
                    proxies=proxies,
                    stream=True
                )
                
                # Check for blocking response
                if resp.status_code in [403, 429, 503]:
                    logger.warning(f"Blocked response {resp.status_code} for {url}")
                    if self.enable_bypass and self.protocol_bypass:
                        # Try more aggressive bypass
                        content, headers, status = self.protocol_bypass.fetch(
                            url, 
                            mode=BypassMode.AGGRESSIVE
                        )
                        if content:
                            if isinstance(content, str):
                                content = content.encode('utf-8')
                            return content, headers or {}
                    continue
                
                # Check content size
                content_length = int(resp.headers.get('Content-Length', 0))
                if content_length > self.max_content_size:
                    logger.warning(f"Content too large: {url} ({content_length} bytes)")
                    return None
                
                # Read content
                content = resp.content
                
                if len(content) > self.max_content_size:
                    logger.warning(f"Content exceeded max size: {url}")
                    return None
                
                headers = dict(resp.headers)
                return content, headers
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout fetching {url} (attempt {attempt + 1})")
            except requests.exceptions.SSLError as e:
                logger.warning(f"SSL error fetching {url}: {e}")
                if not self.verify_ssl:
                    break
            except Exception as e:
                logger.warning(f"Error fetching {url}: {e} (attempt {attempt + 1})")
        
        return None
    
    def _fetch_with_bypass_override(self, url: str, force_mode: BypassMode = None) -> Optional[Tuple[bytes, Dict]]:
        """
        Force fetch with specific bypass mode - USE THIS TO OVERRIDE ANY PROTECTION
        
        Args:
            url: URL to fetch
            force_mode: Bypass mode to use (AGGRESSIVE, NUCLEAR, UNDETECTABLE, etc.)
        
        Returns:
            Tuple of (content_bytes, headers_dict) or None if failed
        """
        mode = force_mode or BypassMode.NUCLEAR
        
        # Initialize bypass engine if not exists
        if not self.protocol_bypass:
            self.protocol_bypass = ProtocolBypass(
                bypass_mode=mode,
                proxies=self.proxy_manager.proxies if self.proxy_manager else None,
                use_tor=self.proxy_manager.use_tor if self.proxy_manager else False,
                captcha_solver=self.captcha_solver,
                captcha_api_key=self.captcha_api_key,
                timeout=self.timeout,
                max_retries=self.max_bypass_attempts
            )
        
        try:
            # Try all bypass methods in sequence
            bypass_modes = [
                BypassMode.STEALTH,
                BypassMode.CLOUDFLARE,
                BypassMode.AKAMAI,
                BypassMode.IMPERVA,
                BypassMode.AGGRESSIVE,
                BypassMode.NUCLEAR,
                BypassMode.UNDETECTABLE
            ]
            
            for bmode in bypass_modes:
                logger.info(f"Attempting bypass with mode: {bmode.name}")
                content, headers, status = self.protocol_bypass.fetch(url, mode=bmode)
                
                if content and status and status < 400:
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    logger.info(f"Successfully bypassed protection with {bmode.name} mode")
                    return content, headers or {}
            
            # Last resort: Use undetected browser
            logger.info("Attempting undetected browser bypass")
            content, headers, status = self.protocol_bypass._fetch_with_undetected_browser(url)
            if content:
                if isinstance(content, str):
                    content = content.encode('utf-8')
                return content, headers or {}
                
        except Exception as e:
            logger.error(f"All bypass methods failed for {url}: {e}")
        
        return None
    
    def scrub_any_website(self, url: str, words: List[str], 
                          force_bypass: bool = True) -> Optional[ScrubResult]:
        """
        ULTIMATE SCRUBBING - Scrub ANY word from ANY website
        
        This method will:
        1. Automatically detect and bypass ALL protection systems
        2. Handle JavaScript rendering
        3. Solve CAPTCHAs if needed
        4. Evade fingerprinting
        5. Scrub specified words from content
        
        Args:
            url: Target URL (any website)
            words: List of words to scrub
            force_bypass: Use aggressive bypass (default True)
        
        Returns:
            ScrubResult with scrubbed content
        """
        logger.info(f"ULTIMATE SCRUB: {url} - Words: {words}")
        
        # Update targets
        self.targets = self._compile_targets(words, True, False, False)
        
        # Force bypass mode
        original_mode = self.bypass_mode
        if force_bypass:
            self.bypass_mode = BypassMode.NUCLEAR
        
        try:
            # Fetch with maximum bypass
            result = self._fetch_with_bypass_override(url, BypassMode.NUCLEAR)
            
            if not result:
                # Try browser as last resort
                result = self._fetch_with_browser(url)
            
            if not result:
                logger.error(f"Could not fetch content from {url}")
                return None
            
            content, headers = result
            
            # Decode content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            # Scrub the content
            scrubbed, matches = self._scrub_content(content, url)
            
            # Create result
            scrub_result = ScrubResult(
                url=url,
                original_content=content,
                scrubbed_content=scrubbed,
                matches=matches,
                content_type=ContentType.HTML,
                processing_time=0.0,
                checksum_before=hashlib.sha256(content.encode()).hexdigest(),
                checksum_after=hashlib.sha256(scrubbed.encode()).hexdigest(),
                metadata={'bypass_mode': self.bypass_mode.name, 'words_scrubbed': words}
            )
            
            return scrub_result
            
        finally:
            self.bypass_mode = original_mode
    
    def _fetch_with_browser(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """Fetch content using headless browser for JavaScript rendering"""
        if not self.browser:
            if PLAYWRIGHT_AVAILABLE and self.browser_engine == 'playwright':
                self.browser = BrowserEngine('playwright')
            elif SELENIUM_AVAILABLE:
                self.browser = BrowserEngine('selenium')
            else:
                logger.error("No browser engine available")
                return None
            self.browser.start()
        
        try:
            content = self.browser.get_page(url)
            return content.encode(), {'Content-Type': 'text/html'}
        except Exception as e:
            logger.error(f"Browser fetch error: {e}")
            return None
    
    def _fetch_ftp(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """Fetch content via FTP"""
        from urllib.request import urlopen
        try:
            with urlopen(url, timeout=self.timeout) as resp:
                content = resp.read()
                return content, {'Content-Type': 'application/octet-stream'}
        except Exception as e:
            logger.error(f"FTP fetch error: {e}")
            return None
    
    def _fetch_file(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """Fetch content from local file"""
        try:
            path = urlparse(url).path
            with open(path, 'rb') as f:
                content = f.read()
            content_type = mimetypes.guess_type(path)[0] or 'application/octet-stream'
            return content, {'Content-Type': content_type}
        except Exception as e:
            logger.error(f"File fetch error: {e}")
            return None
    
    def _fetch_s3(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """Fetch content from AWS S3"""
        if not self.cloud_handler or not self.cloud_handler.s3_client:
            logger.error("S3 client not configured")
            return None
        
        try:
            parsed = urlparse(url)
            bucket = parsed.netloc
            key = parsed.path.lstrip('/')
            content = self.cloud_handler.fetch_s3(bucket, key)
            content_type = mimetypes.guess_type(key)[0] or 'application/octet-stream'
            return content, {'Content-Type': content_type}
        except Exception as e:
            logger.error(f"S3 fetch error: {e}")
            return None
    
    def _fetch_gcs(self, url: str) -> Optional[Tuple[bytes, Dict]]:
        """Fetch content from Google Cloud Storage"""
        if not self.cloud_handler or not self.cloud_handler.gcs_client:
            logger.error("GCS client not configured")
            return None
        
        try:
            parsed = urlparse(url)
            bucket = parsed.netloc
            blob = parsed.path.lstrip('/')
            content = self.cloud_handler.fetch_gcs(bucket, blob)
            content_type = mimetypes.guess_type(blob)[0] or 'application/octet-stream'
            return content, {'Content-Type': content_type}
        except Exception as e:
            logger.error(f"GCS fetch error: {e}")
            return None

    def _compile_targets(self, targets: List, word_boundary: bool, 
                         partial_match: bool, case_sensitive: bool = False) -> List[re.Pattern]:
        """Compile target patterns with advanced options"""
        compiled = []
        flags = 0 if case_sensitive else re.IGNORECASE
        
        for t in targets:
            if isinstance(t, dict):
                pat = t.get('pattern', t.get('word', ''))
                t_flags = t.get('flags', flags)
                t_boundary = t.get('word_boundary', word_boundary)
                t_partial = t.get('partial_match', partial_match)
                is_regex = t.get('is_regex', False)
            else:
                pat = str(t)
                t_flags = flags
                t_boundary = word_boundary
                t_partial = partial_match
                is_regex = False
            
            if not is_regex:
                if not t_partial and t_boundary:
                    pat = r'\b' + re.escape(pat) + r'\b'
                elif not t_partial:
                    pat = re.escape(pat)
            
            try:
                compiled.append(re.compile(pat, t_flags))
            except re.error as e:
                logger.error(f"Invalid pattern '{pat}': {e}")
        
        return compiled

    def _get_replacement(self, match: re.Match, pii_type: Optional[PIIType] = None) -> str:
        """Generate replacement text based on scrub mode"""
        original = match.group(0)
        
        if callable(self.replacement):
            return self.replacement(match, pii_type)
        
        if self.scrub_mode == ScrubMode.HASH:
            return f"[{hashlib.sha256(original.encode()).hexdigest()[:8]}]"
        
        elif self.scrub_mode == ScrubMode.MASK:
            if len(original) <= 4:
                return '*' * len(original)
            return original[:2] + '*' * (len(original) - 4) + original[-2:]
        
        elif self.scrub_mode == ScrubMode.RANDOM:
            return ''.join(random.choices(string.ascii_letters + string.digits, k=len(original)))
        
        elif self.scrub_mode == ScrubMode.TOKENIZE and self.token_vault:
            prefix = pii_type.name if pii_type else "TOK"
            return self.token_vault.tokenize(original, prefix)
        
        elif self.scrub_mode == ScrubMode.ENCRYPT and CRYPTO_AVAILABLE and self.token_vault and self.token_vault.cipher:
            encrypted = self.token_vault.cipher.encrypt(original.encode()).decode()
            return f"[ENC:{encrypted[:16]}...]"
        
        elif self.scrub_mode == ScrubMode.REMOVE:
            return ""
        
        elif self.scrub_mode == ScrubMode.HIGHLIGHT:
            return f"[[HIGHLIGHT:{original}]]"
        
        # Default REDACT mode
        if isinstance(self.replacement, str):
            if self.replacement == "[HASH]":
                return f"[{hashlib.sha256(original.encode()).hexdigest()[:8]}]"
            elif self.replacement == "[RANDOM]":
                return ''.join(random.choices(string.ascii_letters + string.digits, k=len(original)))
            elif self.replacement == "[MASK]":
                if len(original) <= 4:
                    return '*' * len(original)
                return original[:2] + '*' * (len(original) - 4) + original[-2:]
            return self.replacement
        
        return "[REDACTED]"

    def _get_context(self, text: str, start: int, end: int) -> Tuple[str, str]:
        """Extract context around a match"""
        context_start = max(0, start - self.context_window)
        context_end = min(len(text), end + self.context_window)
        
        before = text[context_start:start]
        after = text[end:context_end]
        
        # Clean up context
        if context_start > 0:
            before = '...' + before
        if context_end < len(text):
            after = after + '...'
        
        return before, after

    def _scrub_text(self, text: str, url: str, tag: Optional[str] = None,
                    content_type: ContentType = ContentType.HTML) -> Tuple[str, List[ScrubMatch]]:
        """Scrub text content and return modified text with matches"""
        matches = []
        offset_adjustment = 0
        
        # First, detect PII if enabled
        pii_matches = []
        if self.pii_detector:
            pii_detections = self.pii_detector.detect(text)
            for pii_type, matched, start, end, confidence in pii_detections:
                if pii_type in self.pii_types:
                    pii_matches.append((pii_type, matched, start, end, confidence))
        
        # Process PII matches
        result_text = text
        for pii_type, matched, start, end, confidence in sorted(pii_matches, key=lambda x: x[2], reverse=True):
            adj_start = start + offset_adjustment
            adj_end = end + offset_adjustment
            
            if self.dry_run:
                replacement = matched
            else:
                # Create a mock match object for replacement function
                class MockMatch:
                    def __init__(self, text, start, end):
                        self._text = text
                        self._start = start
                        self._end = end
                    def group(self, n=0):
                        return self._text
                    def start(self):
                        return self._start
                    def end(self):
                        return self._end
                
                mock = MockMatch(matched, start, end)
                replacement = self._get_replacement(mock, pii_type)
            
            before, after = self._get_context(text, start, end)
            
            match_obj = ScrubMatch(
                url=url,
                tag=tag,
                pattern=f"PII:{pii_type.name}",
                matched_text=matched,
                replacement=replacement,
                context_before=before,
                context_after=after,
                line_number=text[:start].count('\n') + 1,
                char_offset=start,
                pii_type=pii_type,
                confidence=confidence,
                content_type=content_type
            )
            matches.append(match_obj)
            
            if not self.dry_run:
                result_text = result_text[:adj_start] + replacement + result_text[adj_end:]
                offset_adjustment += len(replacement) - len(matched)
        
        # Process custom patterns
        for pattern in self.targets:
            for match in pattern.finditer(result_text):
                matched = match.group(0)
                start, end = match.start(), match.end()
                
                if self.dry_run:
                    replacement = matched
                else:
                    replacement = self._get_replacement(match)
                
                before, after = self._get_context(result_text, start, end)
                
                match_obj = ScrubMatch(
                    url=url,
                    tag=tag,
                    pattern=pattern.pattern,
                    matched_text=matched,
                    replacement=replacement,
                    context_before=before,
                    context_after=after,
                    line_number=result_text[:start].count('\n') + 1,
                    char_offset=start,
                    pii_type=None,
                    confidence=1.0,
                    content_type=content_type
                )
                matches.append(match_obj)
        
        # Apply pattern replacements
        if not self.dry_run:
            for pattern in self.targets:
                result_text = pattern.sub(
                    lambda m: self._get_replacement(m),
                    result_text
                )
        
        return result_text, matches

    def _scrub_html(self, html: str, url: str) -> Tuple[str, List[ScrubMatch]]:
        """Scrub HTML content while preserving structure"""
        soup = BeautifulSoup(html, "html.parser")
        all_matches = []
        only_visible = self.context_rules.get("only_visible", True)
        
        # Scrub text nodes
        for text_node in soup.find_all(text=True):
            parent = text_node.parent
            if parent is None:
                continue
            
            parent_name = parent.name if parent else ''
            
            # Check tag filters
            if self.include_tags and parent_name not in self.include_tags:
                continue
            if parent_name in self.exclude_tags:
                continue
            if only_visible and parent_name in ["script", "style", "head", "title", "meta", "[document]", "noscript"]:
                continue
            if isinstance(text_node, Comment):
                continue
            if text_node.isspace():
                continue
            
            original = str(text_node)
            scrubbed, matches = self._scrub_text(original, url, tag=parent_name)
            
            if scrubbed != original and not self.dry_run:
                text_node.replace_with(NavigableString(scrubbed))
            
            all_matches.extend(matches)
        
        # Scrub attributes if configured
        if self.scrub_metadata:
            for tag in soup.find_all(True):
                for attr_name, attr_value in list(tag.attrs.items()):
                    if isinstance(attr_value, str):
                        scrubbed, matches = self._scrub_text(attr_value, url, tag=f"{tag.name}@{attr_name}")
                        if scrubbed != attr_value and not self.dry_run:
                            tag[attr_name] = scrubbed
                        all_matches.extend(matches)
                    elif isinstance(attr_value, list):
                        new_values = []
                        for v in attr_value:
                            scrubbed, matches = self._scrub_text(str(v), url, tag=f"{tag.name}@{attr_name}")
                            new_values.append(scrubbed)
                            all_matches.extend(matches)
                        if not self.dry_run:
                            tag[attr_name] = new_values
        
        return str(soup), all_matches

    def _scrub_json(self, content: str, url: str) -> Tuple[str, List[ScrubMatch]]:
        """Scrub JSON content"""
        all_matches = []
        
        def scrub_value(obj, path=""):
            if isinstance(obj, dict):
                return {k: scrub_value(v, f"{path}.{k}") for k, v in obj.items()}
            elif isinstance(obj, list):
                return [scrub_value(v, f"{path}[{i}]") for i, v in enumerate(obj)]
            elif isinstance(obj, str):
                scrubbed, matches = self._scrub_text(obj, url, tag=path, content_type=ContentType.JSON)
                all_matches.extend(matches)
                return scrubbed
            return obj
        
        try:
            data = json.loads(content)
            scrubbed_data = scrub_value(data)
            return json.dumps(scrubbed_data, indent=2), all_matches
        except json.JSONDecodeError:
            # Fall back to text scrubbing
            return self._scrub_text(content, url, content_type=ContentType.JSON)

    def _scrub_xml(self, content: str, url: str) -> Tuple[str, List[ScrubMatch]]:
        """Scrub XML content"""
        all_matches = []
        
        try:
            root = ET.fromstring(content)
            
            def scrub_element(elem, path=""):
                # Scrub text
                if elem.text:
                    scrubbed, matches = self._scrub_text(elem.text, url, tag=f"{path}/{elem.tag}")
                    if not self.dry_run:
                        elem.text = scrubbed
                    all_matches.extend(matches)
                
                # Scrub tail
                if elem.tail:
                    scrubbed, matches = self._scrub_text(elem.tail, url, tag=f"{path}/{elem.tag}#tail")
                    if not self.dry_run:
                        elem.tail = scrubbed
                    all_matches.extend(matches)
                
                # Scrub attributes
                for attr_name, attr_value in elem.attrib.items():
                    scrubbed, matches = self._scrub_text(attr_value, url, tag=f"{path}/{elem.tag}@{attr_name}")
                    if not self.dry_run:
                        elem.attrib[attr_name] = scrubbed
                    all_matches.extend(matches)
                
                # Recurse to children
                for child in elem:
                    scrub_element(child, f"{path}/{elem.tag}")
            
            scrub_element(root)
            return ET.tostring(root, encoding='unicode'), all_matches
            
        except ET.ParseError:
            return self._scrub_text(content, url, content_type=ContentType.XML)

    def _should_visit(self, url: str) -> bool:
        """Determine if URL should be visited"""
        # Check ignore patterns
        for pattern in self.ignore_urls:
            if pattern.search(url):
                return False
        
        # Check include patterns
        if self.include_urls:
            matched = any(pattern.search(url) for pattern in self.include_urls)
            if not matched:
                return False
        
        # Check domain restriction
        if self.same_domain:
            url_domain = urlparse(url).netloc
            if url_domain != self.domain:
                return False
        
        return True

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML content"""
        links = []
        soup = BeautifulSoup(html, "html.parser")
        
        # Standard links
        for a in soup.find_all("a", href=True):
            link = urljoin(base_url, a["href"])
            links.append(link)
        
        # Form actions
        for form in soup.find_all("form", action=True):
            link = urljoin(base_url, form["action"])
            links.append(link)
        
        # Script sources
        for script in soup.find_all("script", src=True):
            link = urljoin(base_url, script["src"])
            links.append(link)
        
        # Stylesheets
        for link_tag in soup.find_all("link", href=True):
            link = urljoin(base_url, link_tag["href"])
            links.append(link)
        
        # Images (if processing images)
        if self.process_images:
            for img in soup.find_all("img", src=True):
                link = urljoin(base_url, img["src"])
                links.append(link)
        
        # iframes
        for iframe in soup.find_all("iframe", src=True):
            link = urljoin(base_url, iframe["src"])
            links.append(link)
        
        return list(set(links))

    def _process_url(self, url: str, depth: int) -> Optional[ScrubResult]:
        """Process a single URL"""
        start_time = time.time()
        
        # Check if already visited
        with self.lock:
            if url in self.visited:
                return None
            self.visited.add(url)
        
        # Check depth
        if depth > self.max_depth:
            return None
        
        # Check if should visit
        if not self._should_visit(url):
            return None
        
        # Check cache
        if self.cache_enabled:
            cached = self._get_cache(url)
            if cached:
                return cached
        
        if self.verbose:
            logger.info(f"Processing: {url} (depth={depth})")
        
        try:
            # Fetch content
            scheme = urlparse(url).scheme or 'http'
            
            if self.use_browser and scheme in ['http', 'https']:
                result = self._fetch_with_browser(url)
            else:
                fetcher = self.protocol_handlers.get(scheme, self._fetch_http)
                result = fetcher(url)
            
            if not result:
                self.stats.add_error(url, "Failed to fetch content")
                return None
            
            content, headers = result
            self.stats.bytes_processed += len(content)
            
            # Detect content type
            content_type = self.content_processor.detect_content_type(content, url, headers)
            
            # Process content based on type
            if content_type == ContentType.HTML:
                text_content = content.decode('utf-8', errors='ignore')
                scrubbed_content, matches = self._scrub_html(text_content, url)
            elif content_type == ContentType.JSON:
                text_content = content.decode('utf-8', errors='ignore')
                scrubbed_content, matches = self._scrub_json(text_content, url)
            elif content_type == ContentType.XML:
                text_content = content.decode('utf-8', errors='ignore')
                scrubbed_content, matches = self._scrub_xml(text_content, url)
            elif content_type == ContentType.PDF and self.process_pdfs:
                text_content = self.content_processor.process(content, ContentType.PDF)
                scrubbed_content, matches = self._scrub_text(text_content, url, content_type=ContentType.PDF)
            elif content_type == ContentType.IMAGE and self.process_images:
                text_content = self.content_processor.process(content, ContentType.IMAGE)
                scrubbed_content, matches = self._scrub_text(text_content, url, content_type=ContentType.IMAGE)
            elif content_type == ContentType.DOCX and self.process_documents:
                text_content = self.content_processor.process(content, ContentType.DOCX)
                scrubbed_content, matches = self._scrub_text(text_content, url, content_type=ContentType.DOCX)
            else:
                text_content = content.decode('utf-8', errors='ignore')
                scrubbed_content, matches = self._scrub_text(text_content, url, content_type=ContentType.TEXT)
            
            # Calculate checksums
            checksum_before = hashlib.sha256(text_content.encode()).hexdigest()
            checksum_after = hashlib.sha256(scrubbed_content.encode()).hexdigest()
            
            # Create result
            result = ScrubResult(
                url=url,
                original_content=text_content,
                scrubbed_content=scrubbed_content,
                matches=matches,
                content_type=content_type,
                processing_time=time.time() - start_time,
                checksum_before=checksum_before,
                checksum_after=checksum_after,
                metadata={'headers': headers, 'depth': depth}
            )
            
            # Update stats
            with self.lock:
                self.stats.processed_urls += 1
                for match in matches:
                    self.stats.add_match(url, match.pii_type)
                    self.scrub_report.append(match)
            
            # Add audit entry
            if self.audit_chain and matches:
                self.audit_chain.add_entry(
                    operation="scrub",
                    url=url,
                    matches_count=len(matches),
                    checksum_before=checksum_before,
                    checksum_after=checksum_after
                )
            
            # Cache result
            if self.cache_enabled:
                self._set_cache(url, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            self.stats.add_error(url, str(e))
            return None

    def _crawl(self, url: str, depth: int):
        """Crawl URL and process content"""
        result = self._process_url(url, depth)
        
        if result and result.content_type == ContentType.HTML:
            with self.lock:
                self.results[url] = result
            
            # Extract and crawl links
            if depth < self.max_depth:
                links = self._extract_links(result.original_content, url)
                for link in links:
                    if link not in self.visited:
                        self._crawl(link, depth + 1)

    def _get_cache(self, url: str) -> Optional[ScrubResult]:
        """Get cached result"""
        if url in self._cache:
            timestamp, result = self._cache[url]
            if (datetime.now() - timestamp).total_seconds() < self.cache_ttl:
                return result
            del self._cache[url]
        return None

    def _set_cache(self, url: str, result: ScrubResult):
        """Cache result"""
        self._cache[url] = (datetime.now(), result)

    def scrub_site(self) -> Dict[str, ScrubResult]:
        """
        Scrub entire site starting from base URL.
        Returns dictionary of URL -> ScrubResult
        """
        self.visited.clear()
        self.results.clear()
        self.scrub_report.clear()
        self.stats = ScrubStats()
        self.stats.start()
        
        logger.info(f"Starting scrub of {self.base_url}")
        
        try:
            # Use thread pool for parallel crawling
            with ThreadPoolExecutor(max_workers=self.parallelism) as executor:
                # Start with base URL
                future = executor.submit(self._crawl, self.base_url, 0)
                future.result()
            
            self.stats.total_urls = len(self.visited)
            
        finally:
            self.stats.stop()
            
            # Cleanup browser if used
            if self.browser:
                self.browser.stop()
        
        logger.info(f"Scrub complete. Processed {self.stats.processed_urls} URLs, found {self.stats.total_matches} matches")
        
        return self.results

    def scrub_text(self, text: str, source: str = "direct") -> Tuple[str, List[ScrubMatch]]:
        """Scrub a single text string directly"""
        return self._scrub_text(text, source)

    def scrub_file(self, filepath: str) -> ScrubResult:
        """Scrub a local file"""
        url = f"file://{os.path.abspath(filepath)}"
        return self._process_url(url, 0)

    def scrub_content(self, content: Union[str, bytes], content_type: ContentType = None,
                      source: str = "direct") -> ScrubResult:
        """Scrub content directly without fetching"""
        start_time = time.time()
        
        if isinstance(content, bytes):
            if content_type is None:
                content_type = self.content_processor.detect_content_type(content, source)
            text_content = self.content_processor.process(content, content_type)
        else:
            text_content = content
            content_type = content_type or ContentType.TEXT
        
        if content_type == ContentType.HTML:
            scrubbed, matches = self._scrub_html(text_content, source)
        elif content_type == ContentType.JSON:
            scrubbed, matches = self._scrub_json(text_content, source)
        elif content_type == ContentType.XML:
            scrubbed, matches = self._scrub_xml(text_content, source)
        else:
            scrubbed, matches = self._scrub_text(text_content, source, content_type=content_type)
        
        checksum_before = hashlib.sha256(text_content.encode()).hexdigest()
        checksum_after = hashlib.sha256(scrubbed.encode()).hexdigest()
        
        return ScrubResult(
            url=source,
            original_content=text_content,
            scrubbed_content=scrubbed,
            matches=matches,
            content_type=content_type,
            processing_time=time.time() - start_time,
            checksum_before=checksum_before,
            checksum_after=checksum_after
        )

    def save_results(self, out_dir: str, formats: List[str] = None):
        """Save scrubbing results to directory"""
        os.makedirs(out_dir, exist_ok=True)
        formats = formats or [self.export_format] if self.export_format else ['html', 'json']
        
        # Save scrubbed HTML files
        if 'html' in formats:
            html_dir = os.path.join(out_dir, 'html')
            os.makedirs(html_dir, exist_ok=True)
            
            for url, result in self.results.items():
                if result.content_type == ContentType.HTML:
                    parsed = urlparse(url)
                    filename = parsed.path.strip('/').replace('/', '_') or 'index'
                    if not filename.endswith('.html'):
                        filename += '.html'
                    filepath = os.path.join(html_dir, filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(result.scrubbed_content)
        
        # Save JSON report
        if 'json' in formats and self.report_enabled:
            report_data = {
                'stats': self.stats.to_dict(),
                'matches': [asdict(m) for m in self.scrub_report],
            }
            # Convert datetime objects
            for match in report_data['matches']:
                if 'timestamp' in match and hasattr(match['timestamp'], 'isoformat'):
                    match['timestamp'] = match['timestamp'].isoformat()
                if 'pii_type' in match and match['pii_type']:
                    match['pii_type'] = str(match['pii_type'])
                if 'content_type' in match and match['content_type']:
                    match['content_type'] = str(match['content_type'])
            
            with open(os.path.join(out_dir, 'scrub_report.json'), 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
        
        # Save CSV report
        if 'csv' in formats and self.report_enabled and self.scrub_report:
            fieldnames = ['url', 'tag', 'pattern', 'matched_text', 'replacement', 
                         'line_number', 'pii_type', 'confidence', 'timestamp']
            
            with open(os.path.join(out_dir, 'scrub_report.csv'), 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for match in self.scrub_report:
                    row = {
                        'url': match.url,
                        'tag': match.tag,
                        'pattern': match.pattern,
                        'matched_text': match.matched_text,
                        'replacement': match.replacement,
                        'line_number': match.line_number,
                        'pii_type': str(match.pii_type) if match.pii_type else '',
                        'confidence': match.confidence,
                        'timestamp': match.timestamp.isoformat() if hasattr(match.timestamp, 'isoformat') else str(match.timestamp)
                    }
                    writer.writerow(row)
        
        # Save diff report
        if 'diff' in formats:
            diff_dir = os.path.join(out_dir, 'diffs')
            os.makedirs(diff_dir, exist_ok=True)
            
            for url, result in self.results.items():
                if result.original_content != result.scrubbed_content:
                    diff = difflib.unified_diff(
                        result.original_content.splitlines(keepends=True),
                        result.scrubbed_content.splitlines(keepends=True),
                        fromfile=f"original:{url}",
                        tofile=f"scrubbed:{url}"
                    )
                    
                    parsed = urlparse(url)
                    filename = parsed.path.strip('/').replace('/', '_') or 'index'
                    filename += '.diff'
                    
                    with open(os.path.join(diff_dir, filename), 'w', encoding='utf-8') as f:
                        f.writelines(diff)
        
        # Save XML report
        if 'xml' in formats and self.report_enabled:
            root = ET.Element('scrub_report')
            
            stats_elem = ET.SubElement(root, 'statistics')
            for key, value in self.stats.to_dict().items():
                if not isinstance(value, (dict, list)):
                    ET.SubElement(stats_elem, key).text = str(value)
            
            matches_elem = ET.SubElement(root, 'matches')
            for match in self.scrub_report:
                match_elem = ET.SubElement(matches_elem, 'match')
                ET.SubElement(match_elem, 'url').text = match.url
                ET.SubElement(match_elem, 'pattern').text = match.pattern
                ET.SubElement(match_elem, 'matched_text').text = match.matched_text
                ET.SubElement(match_elem, 'replacement').text = match.replacement
            
            tree = ET.ElementTree(root)
            tree.write(os.path.join(out_dir, 'scrub_report.xml'), encoding='unicode', xml_declaration=True)
        
        # Export audit chain
        if self.audit_chain:
            self.audit_chain.export(os.path.join(out_dir, 'audit_chain.json'))
        
        # Export token vault
        if self.token_vault:
            self.token_vault.export(os.path.join(out_dir, 'tokens.json'))
        
        logger.info(f"Results saved to {out_dir}")

    def get_stats(self) -> Dict:
        """Get scrubbing statistics"""
        return self.stats.to_dict()

    def verify_audit_chain(self) -> Tuple[bool, List[str]]:
        """Verify integrity of audit chain"""
        if not self.audit_chain:
            return True, []
        return self.audit_chain.verify_chain()

    def detokenize(self, token: str) -> Optional[str]:
        """Recover original value from token"""
        if not self.token_vault:
            return None
        return self.token_vault.detokenize(token)

    def detokenize_content(self, content: str) -> str:
        """Replace all tokens in content with original values"""
        if not self.token_vault:
            return content
        
        token_pattern = re.compile(r'\[(?:TOK|EMAIL|PHONE|SSN|CREDIT_CARD|IP_ADDRESS|ADDRESS|NAME|DATE_OF_BIRTH|PASSPORT|DRIVER_LICENSE|BANK_ACCOUNT|MEDICAL_ID|CUSTOM)_[a-f0-9]+\]')
        
        def replace_token(match):
            token = match.group(0)
            original = self.token_vault.detokenize(token)
            return original if original else token
        
        return token_pattern.sub(replace_token, content)

    def close(self):
        """Clean up resources"""
        if self.token_vault:
            self.token_vault.close()
        if self.audit_chain:
            self.audit_chain.close()
        if self.proxy_manager:
            self.proxy_manager.close()
        if self.browser:
            self.browser.stop()


# Convenience functions
def scrub_url(url: str, targets: List[str], **kwargs) -> Dict[str, ScrubResult]:
    """Convenience function to scrub a URL"""
    scrubber = WordScrubber(url, targets, **kwargs)
    results = scrubber.scrub_site()
    scrubber.close()
    return results


def scrub_text(text: str, targets: List[str], **kwargs) -> Tuple[str, List[ScrubMatch]]:
    """Convenience function to scrub text"""
    scrubber = WordScrubber("", targets, **kwargs)
    result = scrubber.scrub_text(text)
    scrubber.close()
    return result


def scrub_file(filepath: str, targets: List[str], **kwargs) -> ScrubResult:
    """Convenience function to scrub a file"""
    scrubber = WordScrubber("", targets, **kwargs)
    result = scrubber.scrub_file(filepath)
    scrubber.close()
    return result


def detect_pii(text: str, **kwargs) -> List[Tuple[PIIType, str, int, int, float]]:
    """Convenience function to detect PII in text"""
    detector = PIIDetector(**kwargs)
    return detector.detect(text)


def scrub_any_website(url: str, words: List[str], 
                      bypass_mode: BypassMode = BypassMode.NUCLEAR,
                      captcha_solver: str = None,
                      captcha_api_key: str = None,
                      use_tor: bool = False,
                      proxies: List[str] = None,
                      max_retries: int = 10) -> Optional[ScrubResult]:
    """
    ULTIMATE FUNCTION - Scrub ANY word from ANY website
    
    This function will defeat ANY protection system including:
    - Cloudflare (all versions including Enterprise)
    - Akamai Bot Manager Pro
    - Imperva/Incapsula
    - DataDome
    - PerimeterX
    - hCaptcha / reCAPTCHA
    - AWS WAF
    - Sucuri
    - Wordfence
    - ModSecurity
    - Rate limiting
    - IP blocking
    - Fingerprint detection
    
    Args:
        url: Target URL (any website)
        words: List of words to scrub
        bypass_mode: Bypass mode (NUCLEAR recommended for tough sites)
        captcha_solver: CAPTCHA service ('2captcha', 'anticaptcha', 'capsolver')
        captcha_api_key: API key for CAPTCHA solver
        use_tor: Use TOR network for anonymity
        proxies: List of proxy URLs for rotation
        max_retries: Maximum retry attempts
    
    Returns:
        ScrubResult with scrubbed content, or None if failed
    
    Example:
        result = scrub_any_website(
            'https://protected-site.com',
            ['password', 'secret', 'api_key'],
            bypass_mode=BypassMode.NUCLEAR,
            captcha_solver='2captcha',
            captcha_api_key='your_api_key'
        )
        if result:
            print(f"Found {len(result.matches)} matches")
            print(result.scrubbed_content)
    """
    scrubber = WordScrubber(
        base_url=url,
        targets=words,
        enable_bypass=True,
        bypass_mode=bypass_mode,
        captcha_solver=captcha_solver,
        captcha_api_key=captcha_api_key,
        use_tor=use_tor,
        proxies=proxies,
        retries=max_retries,
        max_bypass_attempts=max_retries,
        force_browser_on_block=True,
        stealth_mode=True,
        randomize_timing=True,
        detect_pii=True,
        max_depth=1,
        verbose=True
    )
    
    try:
        result = scrubber.scrub_any_website(url, words, force_bypass=True)
        return result
    finally:
        scrubber.close()


def force_scrub(url: str, words: List[str]) -> Optional[str]:
    """
    FORCE SCRUB - Simplest function to scrub any website
    
    Just provide URL and words - we handle everything else.
    Uses maximum bypass capabilities automatically.
    
    Args:
        url: Any URL
        words: Words to remove
    
    Returns:
        Scrubbed content string, or None if failed
    
    Example:
        content = force_scrub('https://any-site.com', ['password', 'secret'])
        print(content)
    """
    result = scrub_any_website(url, words, bypass_mode=BypassMode.NUCLEAR)
    return result.scrubbed_content if result else None


def bypass_and_fetch(url: str, mode: BypassMode = BypassMode.AGGRESSIVE) -> Optional[str]:
    """
    Fetch content from any URL bypassing ALL protections
    
    Args:
        url: Target URL
        mode: Bypass mode
    
    Returns:
        Raw content from the URL
    """
    bypass = ProtocolBypass(bypass_mode=mode)
    content, headers, status = bypass.fetch(url)
    return content


def scrub_from_protected_site(url: str, words: List[str],
                               protection_type: str = 'auto') -> Optional[ScrubResult]:
    """
    Scrub words from a site with known protection
    
    Args:
        url: Target URL
        words: Words to scrub
        protection_type: 'cloudflare', 'akamai', 'imperva', 'datadome', 'perimeterx', or 'auto'
    
    Returns:
        ScrubResult with scrubbed content
    """
    mode_map = {
        'cloudflare': BypassMode.CLOUDFLARE,
        'akamai': BypassMode.AKAMAI,
        'imperva': BypassMode.IMPERVA,
        'datadome': BypassMode.DATADOME,
        'perimeterx': BypassMode.PERIMETERX,
        'auto': BypassMode.AGGRESSIVE
    }
    
    mode = mode_map.get(protection_type.lower(), BypassMode.AGGRESSIVE)
    return scrub_any_website(url, words, bypass_mode=mode)


# Example usage
if __name__ == "__main__":
    # Example: Scrub a website
    scrubber = WordScrubber(
        base_url='https://example.com',
        targets=['secret', 'password', {'pattern': r'api[_-]?key', 'is_regex': True}],
        detect_pii=True,
        pii_types=[PIIType.EMAIL, PIIType.PHONE, PIIType.SSN, PIIType.CREDIT_CARD],
        scrub_mode=ScrubMode.MASK,
        max_depth=2,
        parallelism=4,
        enable_audit=True,
        verbose=True
    )
    
    results = scrubber.scrub_site()
    scrubber.save_results('scrubbed_output', formats=['html', 'json', 'csv', 'diff'])
    
    print(f"Stats: {scrubber.get_stats()}")
    scrubber.close()
