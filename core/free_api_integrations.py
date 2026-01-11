"""Free API Integrations

This module centralizes integrations with *free* (no API key required) endpoints.

Goal:
- Provide a consistent async client interface for modules that currently depend on
  paid API keys (or where a "real" external API is needed).
- Keep behavior conservative: short timeouts, graceful failures, no hardcoded keys.

Notes:
- These integrations are best-effort and may be rate-limited by providers.
- Callers should treat results as enrichment, not ground truth.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp


DEFAULT_TIMEOUT_S = 12
DEFAULT_UA = "HydraRecon/2.0 (+https://localhost)"


@dataclass
class FreeAPIResult:
    ok: bool
    source: str
    fetched_at: datetime
    status: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class FreeAPIClient:
    """Async client for free endpoints.

    This class owns an aiohttp session so callers can reuse connections.
    """

    def __init__(self, *, timeout_s: int = DEFAULT_TIMEOUT_S, user_agent: str = DEFAULT_UA):
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._headers = {"User-Agent": user_agent}
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "FreeAPIClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self._timeout, headers=self._headers)
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def _get_json(self, url: str, *, params: Optional[Dict[str, Any]] = None, source: str) -> FreeAPIResult:
        fetched_at = datetime.utcnow()
        try:
            session = await self._ensure_session()
            async with session.get(url, params=params) as resp:
                status = resp.status
                if status != 200:
                    return FreeAPIResult(ok=False, source=source, fetched_at=fetched_at, status=status, error=f"HTTP {status}")
                # Some providers return text/html errors with 200; guard with content-type.
                ct = (resp.headers.get("Content-Type") or "").lower()
                if "json" not in ct:
                    text = await resp.text()
                    return FreeAPIResult(ok=False, source=source, fetched_at=fetched_at, status=status, error=f"Non-JSON response: {ct}", data={"raw": text[:1000]})
                data = await resp.json()
                if isinstance(data, dict):
                    return FreeAPIResult(ok=True, source=source, fetched_at=fetched_at, status=status, data=data)
                return FreeAPIResult(ok=True, source=source, fetched_at=fetched_at, status=status, data={"value": data})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return FreeAPIResult(ok=False, source=source, fetched_at=fetched_at, error=str(e))

    # --- Enrichment endpoints (no API key) ---

    async def ip_geolocation(self, ip: str) -> FreeAPIResult:
        """IP geolocation via ip-api.com (free tier, no key).

        Docs: http://ip-api.com/docs/api:json
        """
        return await self._get_json("http://ip-api.com/json/" + ip, source="ip-api")

    async def ipwhois_rdap(self, ip: str) -> FreeAPIResult:
        """IP WHOIS/RDAP via rdap.org.

        This is a public RDAP proxy. Rate limits may apply.
        """
        return await self._get_json(f"https://rdap.org/ip/{ip}", source="rdap")

    async def email_reputation(self, email: str) -> FreeAPIResult:
        """Email reputation via emailrep.io (free, no key)."""
        # emailrep expects URL-encoded email; aiohttp will encode params but not path.
        from urllib.parse import quote

        return await self._get_json(f"https://emailrep.io/{quote(email)}", source="emailrep")

    async def urlscan_search(self, query: str) -> FreeAPIResult:
        """URLScan public search (works without key for many queries; key increases limits)."""
        return await self._get_json("https://urlscan.io/api/v1/search/", params={"q": query}, source="urlscan")

    async def threatfox_search(self, ioc: str) -> FreeAPIResult:
        """Abuse.ch ThreatFox IOC search (free).

        Docs: https://threatfox.abuse.ch/api/
        """
        payload = {"query": "search_ioc", "search_term": ioc}
        fetched_at = datetime.utcnow()
        try:
            session = await self._ensure_session()
            async with session.post("https://threatfox-api.abuse.ch/api/v1/", json=payload) as resp:
                status = resp.status
                if status != 200:
                    return FreeAPIResult(ok=False, source="threatfox", fetched_at=fetched_at, status=status, error=f"HTTP {status}")
                data = await resp.json()
                if isinstance(data, dict):
                    return FreeAPIResult(ok=True, source="threatfox", fetched_at=fetched_at, status=status, data=data)
                return FreeAPIResult(ok=True, source="threatfox", fetched_at=fetched_at, status=status, data={"value": data})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return FreeAPIResult(ok=False, source="threatfox", fetched_at=fetched_at, error=str(e))

    async def malwarebazaar_hash(self, sha256: str) -> FreeAPIResult:
        """Abuse.ch MalwareBazaar hash lookup (free).

        Docs: https://bazaar.abuse.ch/api/
        """
        payload = {"query": "get_info", "hash": sha256}
        fetched_at = datetime.utcnow()
        try:
            session = await self._ensure_session()
            async with session.post("https://mb-api.abuse.ch/api/v1/", data=payload) as resp:
                status = resp.status
                if status != 200:
                    return FreeAPIResult(ok=False, source="malwarebazaar", fetched_at=fetched_at, status=status, error=f"HTTP {status}")
                ct = (resp.headers.get("Content-Type") or "").lower()
                if "json" not in ct:
                    text = await resp.text()
                    return FreeAPIResult(ok=False, source="malwarebazaar", fetched_at=fetched_at, status=status, error=f"Non-JSON response: {ct}", data={"raw": text[:1000]})
                data = await resp.json()
                if isinstance(data, dict):
                    return FreeAPIResult(ok=True, source="malwarebazaar", fetched_at=fetched_at, status=status, data=data)
                return FreeAPIResult(ok=True, source="malwarebazaar", fetched_at=fetched_at, status=status, data={"value": data})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return FreeAPIResult(ok=False, source="malwarebazaar", fetched_at=fetched_at, error=str(e))
