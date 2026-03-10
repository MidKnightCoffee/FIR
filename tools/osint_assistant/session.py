"""
session.py — HumanSession: stealth HTTP client that mimics human browsing.

Provides:
  • Realistic browser-profile headers (Chrome, Firefox, Safari on Win/Mac/Linux)
  • User-agent rotation via fake-useragent
  • Cookie persistence (acts like a real browser session)
  • Referrer chain simulation
  • Gaussian-distributed inter-request timing jitter
  • CAPTCHA / rate-limit detection with exponential back-off
  • Optional proxy list rotation
"""

from __future__ import annotations

import logging
import random
import time
from typing import Dict, List, Optional

import requests
from fake_useragent import UserAgent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timing constants
# ---------------------------------------------------------------------------
DELAY_MEAN: float = 3.5
DELAY_STD: float = 1.5
DELAY_MIN: float = 1.5
DELAY_MAX: float = 10.0

BACKOFF_BASE: float = 2.0
BACKOFF_MAX: float = 120.0
BACKOFF_JITTER: float = 0.4

MAX_ATTEMPTS: int = 5

# ---------------------------------------------------------------------------
# CAPTCHA / block markers
# ---------------------------------------------------------------------------
CAPTCHA_MARKERS = [
    "our systems have detected unusual traffic",
    "captcha",
    "/sorry/",
    "detected unusual traffic",
    "please solve this puzzle",
    "access denied",
    "robot check",
    "automated queries",
]

# ---------------------------------------------------------------------------
# Browser profiles — coherent header sets for Chrome, Firefox, Safari
# ---------------------------------------------------------------------------
BROWSER_PROFILES: List[Dict[str, str]] = [
    # Chrome 122 — Windows 11
    {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Cache-Control": "max-age=0",
    },
    # Chrome 122 — macOS
    {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"macOS"',
        "Cache-Control": "max-age=0",
    },
    # Firefox 123 — Windows
    {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    # Safari 17 — macOS
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-us",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # Chrome 120 — Linux
    {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Linux"',
    },
    # Edge 121 — Windows 11
    {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/webp,image/apng,*/*;"
            "q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-CH-UA": '"Microsoft Edge";v="121", "Not A(Brand";v="99", "Chromium";v="121"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    },
]


class HumanSession:
    """
    A stealth HTTP client that simulates human browsing behaviour.

    All engines in the OSINT assistant use a shared HumanSession so they
    appear to come from the same persistent browser session, which is more
    realistic than per-engine sessions.

    Parameters
    ----------
    proxies:
        Optional list of proxy strings in the format ``http://host:port`` or
        ``socks5://user:pass@host:port``.  When multiple proxies are provided
        they are used in round-robin order.
    """

    def __init__(self, proxies: Optional[List[str]] = None) -> None:
        self._ua_gen = UserAgent(browsers=["chrome", "firefox", "safari", "edge"])
        self._proxies: List[str] = proxies or []
        self._proxy_index: int = 0
        self._session: Optional[requests.Session] = None
        self._profile: Optional[Dict[str, str]] = None
        self._rotate_profile()

    # ------------------------------------------------------------------
    # Profile / session management
    # ------------------------------------------------------------------
    def _rotate_profile(self) -> None:
        """Pick a random browser profile + UA and rebuild the underlying session."""
        self._profile = random.choice(BROWSER_PROFILES)
        try:
            ua = self._ua_gen.random
        except Exception:
            ua = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )

        if self._session:
            self._session.close()

        self._session = requests.Session()
        self._session.headers.update(self._profile)
        self._session.headers["User-Agent"] = ua
        self._session.cookies.clear()
        logger.debug("Rotated browser profile — UA: %s", ua[:60])

    def _next_proxy(self) -> Optional[Dict[str, str]]:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return {"http": proxy, "https": proxy}

    # ------------------------------------------------------------------
    # Human-like timing
    # ------------------------------------------------------------------
    def _human_delay(self, extra: float = 0.0) -> None:
        """Sleep for a Gaussian-distributed, human-realistic interval.

        Subclasses may override this method to inject cancellation checks or
        other side-effects without monkey-patching.
        """
        delay = random.gauss(DELAY_MEAN, DELAY_STD)
        delay = max(DELAY_MIN, min(DELAY_MAX, delay)) + extra
        logger.debug("Human delay: %.2fs", delay)
        time.sleep(delay)

    # ------------------------------------------------------------------
    # Simulated interaction events (scroll/hover/click patterns)
    # ------------------------------------------------------------------
    def _simulate_page_interaction(self) -> None:
        """
        Simulate brief page-interaction timing (scroll delay + hover latency)
        without actually controlling a browser.  Adds a short random sleep
        representing the time a human takes to read a page before navigating.
        """
        read_time = random.uniform(0.3, 1.8)  # quick glance → brief read
        time.sleep(read_time)

    # ------------------------------------------------------------------
    # HTTP GET with back-off
    # ------------------------------------------------------------------
    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        referer: Optional[str] = None,
        attempt: int = 0,
    ) -> requests.Response:
        """
        Issue a GET request with stealth measures and automatic retry/back-off.

        Raises RuntimeError after MAX_ATTEMPTS consecutive blocked requests.
        """
        if attempt >= MAX_ATTEMPTS:
            raise RuntimeError(
                f"Request to {url!r} blocked after {MAX_ATTEMPTS} attempts. "
                "Try again later, use a proxy, or switch engines."
            )

        if attempt > 0:
            wait = self._backoff_delay(attempt)
            logger.warning("Back-off %.1fs (attempt %d) for %s", wait, attempt, url)
            time.sleep(wait)
            self._rotate_profile()

        if referer:
            self._session.headers["Referer"] = referer  # type: ignore[union-attr]
        elif self._session and "Referer" in self._session.headers:
            del self._session.headers["Referer"]

        if headers:
            self._session.headers.update(headers)  # type: ignore[union-attr]

        proxy = self._next_proxy()

        try:
            response = self._session.get(  # type: ignore[union-attr]
                url,
                params=params,
                proxies=proxy,
                timeout=20,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            logger.warning("Request error: %s — retrying", exc)
            return self.get(url, params=params, headers=headers,
                            referer=referer, attempt=attempt + 1)

        if self._is_blocked(response):
            logger.warning("Block/CAPTCHA detected on attempt %d", attempt + 1)
            return self.get(url, params=params, headers=headers,
                            referer=referer, attempt=attempt + 1)

        return response

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _backoff_delay(attempt: int) -> float:
        """Capped, jittered exponential back-off delay."""
        base = BACKOFF_BASE ** attempt
        jitter = random.uniform(0, BACKOFF_JITTER * base)
        return min(base + jitter, BACKOFF_MAX)

    @staticmethod
    def _is_blocked(response: requests.Response) -> bool:
        """Return True if the response looks like a CAPTCHA or block page."""
        if response.status_code in (429, 503):
            return True
        if response.status_code == 200:
            body_lower = response.text[:4096].lower()
            return any(m in body_lower for m in CAPTCHA_MARKERS)
        return False

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
