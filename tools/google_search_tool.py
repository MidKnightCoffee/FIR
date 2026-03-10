"""
FIR - Stealth Google Search Tool
=================================
Performs a Google search and retrieves up to 100 results with:
  • Strong anti-detection (realistic browser profiles, randomised timing,
    session/cookie management, CAPTCHA detection, exponential back-off,
    optional proxy rotation)
  • Deduplication (URL normalisation + content fingerprinting)
  • Relevancy weighting (rank-decay + keyword TF-IDF boost)
  • Tkinter GUI (search bar, progress bar, sortable results table, log panel)

Usage:
    python3 google_search_tool.py

Dependencies (see tools/requirements.txt):
    pip install beautifulsoup4 lxml fake-useragent requests
"""

from __future__ import annotations

import hashlib
import html
import logging
import math
import queue
import random
import re
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
import tkinter as tk
from tkinter import messagebox, ttk

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GOOGLE_SEARCH_URL = "https://www.google.com/search"
MAX_RESULTS = 100
RESULTS_PER_PAGE = 10          # Google default
MAX_PAGES = MAX_RESULTS // RESULTS_PER_PAGE   # = 10

# Delay ranges (seconds) — drawn from Gaussian distribution
DELAY_MEAN = 4.5
DELAY_STD = 1.8
DELAY_MIN = 2.0
DELAY_MAX = 12.0

# Exponential back-off settings
BACKOFF_BASE = 2.0
BACKOFF_MAX = 120.0
BACKOFF_JITTER = 0.4           # fraction of computed delay added as jitter

# Probability of adding pws=0 (personalisation-off) to query params.
# Real users occasionally have this set in browser history/preferences, so
# varying it 50/50 makes requests look more organic.
PWS_OFF_PROBABILITY = 0.5

# CAPTCHA / block indicators
CAPTCHA_MARKERS = [
    "our systems have detected unusual traffic",
    "captcha",
    "/sorry/",
    "detected unusual traffic",
    "blocked",
    "please solve this puzzle",
]


# ---------------------------------------------------------------------------
# Browser profiles
# Carefully crafted header sets that mimic real Chrome / Firefox / Safari on
# Windows, macOS and Linux.  Each profile is a complete, coherent unit.
# ---------------------------------------------------------------------------
BROWSER_PROFILES: List[Dict[str, str]] = [
    # Chrome 122 on Windows 11
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
    # Chrome 122 on macOS
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
    # Firefox 123 on Windows
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    # Safari 17 on macOS
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-us",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
    # Chrome 120 on Linux
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
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(order=False)
class SearchResult:
    rank: int                  # 1-based position in raw Google response
    title: str
    url: str
    snippet: str
    score: float = 0.0         # computed relevancy score (higher = more relevant)
    _url_fingerprint: str = field(default="", init=False, repr=False)
    _content_fingerprint: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self._url_fingerprint = _normalise_url(self.url)
        content = f"{self.title.lower().strip()} {self.snippet.lower().strip()}"
        self._content_fingerprint = hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# URL normalisation helpers
# ---------------------------------------------------------------------------
_STRIP_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                 "utm_content", "ref", "referrer", "source"}


def _normalise_url(url: str) -> str:
    """Return a canonical form of *url* used only for dedup comparison."""
    try:
        parsed = urllib.parse.urlparse(url.lower().strip())
        # Remove fragment; sort & filter query params
        params = urllib.parse.parse_qsl(parsed.query)
        params = [(k, v) for k, v in params if k not in _STRIP_PARAMS]
        params.sort()
        normalised = parsed._replace(
            fragment="",
            query=urllib.parse.urlencode(params),
        )
        # Strip trailing slash from path
        path = normalised.path.rstrip("/") or "/"
        return urllib.parse.urlunparse(normalised._replace(path=path))
    except Exception:
        return url.lower().strip()


# ---------------------------------------------------------------------------
# Relevancy scoring
# ---------------------------------------------------------------------------
def _compute_score(result: SearchResult, query_terms: List[str]) -> float:
    """
    Composite relevancy score:
      - Rank-decay component:  score ∝ 1 / log2(rank + 1)
        (first result gets the highest baseline)
      - Keyword boost: TF-like score for query-term matches in title/snippet
        (title hits weighted 3×, snippet hits weighted 1×)
    """
    # 1. Rank-decay (normalised so rank=1 → 1.0)
    rank_score = 1.0 / math.log2(result.rank + 1)

    # 2. Keyword boost
    title_tokens = re.findall(r"\w+", result.title.lower())
    snippet_tokens = re.findall(r"\w+", result.snippet.lower())
    title_len = max(len(title_tokens), 1)
    snippet_len = max(len(snippet_tokens), 1)

    title_hits = sum(title_tokens.count(t) for t in query_terms)
    snippet_hits = sum(snippet_tokens.count(t) for t in query_terms)

    # TF (term frequency)
    tf_title = title_hits / title_len
    tf_snippet = snippet_hits / snippet_len

    keyword_score = (3.0 * tf_title + 1.0 * tf_snippet) / 4.0

    # Combine: rank contributes 60 %, keyword 40 %
    return 0.60 * rank_score + 0.40 * keyword_score


# ---------------------------------------------------------------------------
# Stealth HTTP client
# ---------------------------------------------------------------------------
class StealthSession:
    """
    Wraps a requests.Session with anti-detection measures:
      - Rotating browser user-agents
      - Coherent browser-profile headers (UA matched to profile)
      - Persistent cookies (behaves like a real browser session)
      - Referrer chain simulation
      - Gaussian-distributed inter-request delays
      - CAPTCHA / rate-limit detection with exponential back-off
      - Optional proxy list rotation
    """

    def __init__(self, proxies: Optional[List[str]] = None) -> None:
        self._ua_gen = UserAgent(browsers=["chrome", "firefox", "safari", "edge"])
        self._proxies = proxies or []
        self._proxy_index = 0
        self._session: Optional[requests.Session] = None
        self._profile: Optional[Dict[str, str]] = None
        self._last_url: Optional[str] = None
        self._rotate_profile()

    # ------------------------------------------------------------------
    # Profile / session management
    # ------------------------------------------------------------------
    def _rotate_profile(self) -> None:
        """Pick a new browser profile + matching user-agent and rebuild the session."""
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

        # Accept cookies (behaves like a real browser)
        self._session.cookies.clear()
        logger.debug("Rotated browser profile — UA: %s", ua[:60])

    def _next_proxy(self) -> Optional[Dict[str, str]]:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return {"http": proxy, "https": proxy}

    # ------------------------------------------------------------------
    # Human-like delay
    # ------------------------------------------------------------------
    def _human_delay(self, extra: float = 0.0) -> None:
        """Sleep for a Gaussian-distributed human-like interval.

        Instance method (not static) so subclasses or the GUI layer can
        override it — e.g. to inject a cancellation check — without any
        monkey-patching.
        """
        delay = random.gauss(DELAY_MEAN, DELAY_STD)
        delay = max(DELAY_MIN, min(DELAY_MAX, delay)) + extra
        logger.debug("Sleeping %.2fs (human delay)", delay)
        time.sleep(delay)

    # ------------------------------------------------------------------
    # Request with back-off
    # ------------------------------------------------------------------
    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        referer: Optional[str] = None,
        attempt: int = 0,
    ) -> requests.Response:
        """
        Issue a GET request with full stealth measures.  Raises RuntimeError
        after repeated CAPTCHA / block detections.
        """
        if attempt > 4:
            raise RuntimeError(
                "Google blocked all requests after 5 attempts. "
                "Try again later, rotate proxies, or use a VPN."
            )

        if attempt > 0:
            wait = self._backoff_delay(attempt)
            logger.warning("Back-off wait: %.1fs (attempt %d)", wait, attempt)
            time.sleep(wait)
            # Rotate profile on retry to change fingerprint
            self._rotate_profile()

        # Simulate a referrer chain (first hit has no referer, subsequent have Google itself)
        if referer:
            self._session.headers["Referer"] = referer
        elif "Referer" in self._session.headers:
            del self._session.headers["Referer"]

        proxy = self._next_proxy()

        try:
            response = self._session.get(
                url,
                params=params,
                proxies=proxy,
                timeout=20,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            logger.warning("Request error: %s — retrying", exc)
            return self.get(url, params=params, referer=referer, attempt=attempt + 1)

        # Detect CAPTCHA / soft block
        if self._is_blocked(response):
            logger.warning("CAPTCHA / block detected on attempt %d", attempt + 1)
            return self.get(url, params=params, referer=referer, attempt=attempt + 1)

        self._last_url = response.url
        return response

    @staticmethod
    def _backoff_delay(attempt: int) -> float:
        """Return the capped, jittered exponential back-off delay for *attempt*."""
        base_wait = BACKOFF_BASE ** attempt
        jitter = random.uniform(0, BACKOFF_JITTER * base_wait)
        return min(base_wait + jitter, BACKOFF_MAX)

    @staticmethod
    def _is_blocked(response: requests.Response) -> bool:
        """Return True if Google is showing a CAPTCHA or block page."""
        if response.status_code in (429, 503):
            return True
        if response.status_code == 200:
            body_lower = response.text.lower()
            return any(marker in body_lower for marker in CAPTCHA_MARKERS)
        return False

    def close(self) -> None:
        if self._session:
            self._session.close()


# ---------------------------------------------------------------------------
# Google scraper
# ---------------------------------------------------------------------------
class GoogleScraper:
    """
    Scrapes Google search results pages to collect up to *max_results* links.
    Uses multiple CSS / attribute selector strategies so it degrades gracefully
    if Google changes its HTML structure.
    """

    def __init__(
        self,
        session: StealthSession,
        progress_cb=None,
        log_cb=None,
    ) -> None:
        self._session = session
        self._progress_cb = progress_cb or (lambda v, t: None)
        self._log_cb = log_cb or (lambda msg: None)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def search(self, query: str, max_results: int = MAX_RESULTS) -> List[SearchResult]:
        """
        Return up to *max_results* SearchResult objects, scored and deduplicated.
        """
        query_terms = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]
        raw_results: List[SearchResult] = []
        seen_url_fps: set = set()
        seen_content_fps: set = set()

        pages_needed = math.ceil(max_results / RESULTS_PER_PAGE)
        referer: Optional[str] = None

        for page_num in range(pages_needed):
            start = page_num * RESULTS_PER_PAGE
            self._log_cb(f"Fetching page {page_num + 1}/{pages_needed} (start={start}) …")

            params = self._build_params(query, start)
            try:
                response = self._session.get(
                    GOOGLE_SEARCH_URL,
                    params=params,
                    referer=referer,
                )
            except RuntimeError as exc:
                self._log_cb(f"⛔ {exc}")
                break

            referer = response.url   # simulate real referrer chain
            page_results = self._parse_page(response.text, start)

            if not page_results:
                self._log_cb("No more results found — stopping early.")
                break

            # Deduplication
            for result in page_results:
                if result._url_fingerprint in seen_url_fps:
                    continue
                if result._content_fingerprint in seen_content_fps:
                    continue
                seen_url_fps.add(result._url_fingerprint)
                seen_content_fps.add(result._content_fingerprint)
                raw_results.append(result)

            collected = len(raw_results)
            self._progress_cb(collected, max_results)
            self._log_cb(f"  → {collected} unique results so far.")

            if collected >= max_results:
                break

            # Only delay between pages, not after the last one
            if page_num < pages_needed - 1:
                self._session._human_delay()

        # Score and sort
        for result in raw_results:
            result.score = _compute_score(result, query_terms)

        raw_results.sort(key=lambda r: r.score, reverse=True)

        # Renumber ranks after dedup + sort
        for idx, result in enumerate(raw_results, start=1):
            result.rank = idx

        return raw_results[:max_results]

    # ------------------------------------------------------------------
    # Request parameter builder
    # ------------------------------------------------------------------
    @staticmethod
    def _build_params(query: str, start: int) -> Dict[str, str]:
        """
        Build Google search query parameters.  Extra parameters (hl, gl, etc.)
        mimic what a real browser with location/language settings sends.
        """
        params: Dict[str, str] = {
            "q": query,
            "num": str(RESULTS_PER_PAGE),
            "start": str(start),
            "hl": "en",
            "gl": "us",
            "ie": "UTF-8",
            "oe": "UTF-8",
            # Disable Google Instant to get consistent HTML
            "nfpr": "1",
            # Safe search off for research use
            "safe": "off",
        }
        # Occasionally add pws=0 (personalisation off) — real users do this
        if random.random() < PWS_OFF_PROBABILITY:
            params["pws"] = "0"
        return params

    # ------------------------------------------------------------------
    # HTML parser — multiple fallback strategies
    # ------------------------------------------------------------------
    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        """
        Parse a Google SERP page with several CSS selector strategies.
        Falls back gracefully if Google's HTML structure changes.
        """
        soup = BeautifulSoup(html_text, "lxml")
        results: List[SearchResult] = []

        # Strategy 1: Modern Google (div.g containers)
        results = self._strategy_div_g(soup, start)

        # Strategy 2: Fallback — anchor tags inside search result wrappers
        if not results:
            results = self._strategy_anchors(soup, start)

        return results

    @staticmethod
    def _strategy_div_g(soup: BeautifulSoup, start: int) -> List[SearchResult]:
        """Parse using div.g — the primary modern Google structure."""
        results: List[SearchResult] = []
        containers = soup.select("div.g, div[data-sokoban-container], div[jscontroller]")

        rank = start + 1
        for container in containers:
            # Title + URL from the first anchor with an h3
            h3 = container.find("h3")
            if not h3:
                continue
            anchor = h3.find_parent("a") or h3.find("a")
            if not anchor:
                # Try the first <a> inside the container
                anchor = container.find("a", href=True)
            if not anchor:
                continue

            href = anchor.get("href", "")
            url = _extract_real_url(href)
            if not url or not url.startswith("http"):
                continue

            title = h3.get_text(separator=" ", strip=True)
            if not title:
                continue

            # Snippet — several possible selectors
            snippet = ""
            for sel in [
                "div[data-sncf]",
                "span.aCOpRe",
                "div.VwiC3b",
                "span[class*='st']",
                "div[class*='st']",
            ]:
                node = container.select_one(sel)
                if node:
                    snippet = node.get_text(separator=" ", strip=True)
                    break

            results.append(
                SearchResult(
                    rank=rank,
                    title=html.unescape(title),
                    url=url,
                    snippet=html.unescape(snippet),
                )
            )
            rank += 1

        return results

    @staticmethod
    def _strategy_anchors(soup: BeautifulSoup, start: int) -> List[SearchResult]:
        """Fallback: scan all anchors that look like organic results."""
        results: List[SearchResult] = []
        seen: set = set()
        rank = start + 1

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href", "")
            url = _extract_real_url(href)
            if not url or not url.startswith("http"):
                continue
            if url in seen:
                continue
            # Skip Google's own internal links
            if _is_google_internal(url):
                continue

            # Try to get a title from an h3 sibling/child or the link text
            h3 = anchor.find("h3")
            if h3:
                title = h3.get_text(strip=True)
            else:
                title = anchor.get_text(strip=True)

            if not title or len(title) < 5:
                continue

            seen.add(url)
            results.append(
                SearchResult(rank=rank, title=html.unescape(title), url=url, snippet="")
            )
            rank += 1

        return results


def _extract_real_url(href: str) -> str:
    """
    Google sometimes wraps URLs in /url?q=… redirects or uses relative paths.
    Extract and return the actual destination URL.
    """
    if not href:
        return ""
    if href.startswith("/url?"):
        parsed = urllib.parse.urlparse(href)
        qs = urllib.parse.parse_qs(parsed.query)
        if "q" in qs:
            return urllib.parse.unquote(qs["q"][0])
    if href.startswith("http"):
        return href
    return ""


_GOOGLE_HOSTS = {"google.com", "www.google.com", "accounts.google.com", "support.google.com"}


def _is_google_internal(url: str) -> bool:
    """Return True if the URL points to a Google-owned host."""
    try:
        host = urllib.parse.urlparse(url).netloc.lower()
        return host in _GOOGLE_HOSTS or host.endswith(".google.com")
    except Exception:
        return True


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class SearchApp(tk.Tk):
    """Main application window."""

    COL_RANK = "Rank"
    COL_SCORE = "Score"
    COL_TITLE = "Title"
    COL_URL = "URL"
    COL_SNIPPET = "Snippet"

    COLUMNS = (COL_RANK, COL_SCORE, COL_TITLE, COL_URL, COL_SNIPPET)
    COL_WIDTHS = {
        COL_RANK: 50,
        COL_SCORE: 60,
        COL_TITLE: 260,
        COL_URL: 300,
        COL_SNIPPET: 380,
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("FIR — Stealth Google Search Tool")
        self.geometry("1280x780")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")

        self._results: List[SearchResult] = []
        self._sort_col: str = self.COL_RANK
        self._sort_asc: bool = True
        self._search_thread: Optional[threading.Thread] = None
        self._queue: queue.Queue = queue.Queue()

        self._build_ui()
        self._poll_queue()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#1e1e2e")
        style.configure(
            "TLabel",
            background="#1e1e2e",
            foreground="#cdd6f4",
            font=("Helvetica", 11),
        )
        style.configure(
            "TButton",
            background="#89b4fa",
            foreground="#1e1e2e",
            font=("Helvetica", 11, "bold"),
            padding=6,
        )
        style.map("TButton", background=[("active", "#74c7ec")])
        style.configure(
            "Treeview",
            background="#181825",
            foreground="#cdd6f4",
            fieldbackground="#181825",
            rowheight=24,
            font=("Helvetica", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#313244",
            foreground="#cba6f7",
            font=("Helvetica", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#45475a")])
        style.configure(
            "red.Horizontal.TProgressbar",
            troughcolor="#313244",
            background="#a6e3a1",
        )

        # ---- Top bar ----
        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill=tk.X)

        ttk.Label(top, text="Query:").pack(side=tk.LEFT)
        self._query_var = tk.StringVar()
        self._query_entry = ttk.Entry(top, textvariable=self._query_var, width=55,
                                      font=("Helvetica", 12))
        self._query_entry.pack(side=tk.LEFT, padx=(8, 12))
        self._query_entry.bind("<Return>", lambda _e: self._start_search())

        ttk.Label(top, text="Max results:").pack(side=tk.LEFT)
        self._max_var = tk.StringVar(value="100")
        max_spin = ttk.Spinbox(top, from_=10, to=100, increment=10,
                               textvariable=self._max_var, width=5,
                               font=("Helvetica", 11))
        max_spin.pack(side=tk.LEFT, padx=(4, 16))

        ttk.Label(top, text="Proxies (one per line, optional):").pack(side=tk.LEFT)
        self._proxy_btn = ttk.Button(top, text="⚙ Configure", command=self._show_proxy_dialog)
        self._proxy_btn.pack(side=tk.LEFT, padx=(4, 16))

        self._search_btn = ttk.Button(top, text="🔍 Search", command=self._start_search)
        self._search_btn.pack(side=tk.LEFT)

        self._cancel_btn = ttk.Button(top, text="✖ Cancel", command=self._cancel_search,
                                      state=tk.DISABLED)
        self._cancel_btn.pack(side=tk.LEFT, padx=(8, 0))

        # ---- Progress bar ----
        prog_frame = ttk.Frame(self, padding=(12, 0, 12, 4))
        prog_frame.pack(fill=tk.X)
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(
            prog_frame,
            variable=self._progress_var,
            maximum=100,
            mode="determinate",
            style="red.Horizontal.TProgressbar",
        )
        self._progress_bar.pack(fill=tk.X)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(prog_frame, textvariable=self._status_var,
                  font=("Helvetica", 9)).pack(anchor=tk.W)

        # ---- Results table ----
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 0))

        scroll_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        scroll_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)

        self._tree = ttk.Treeview(
            table_frame,
            columns=self.COLUMNS,
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            selectmode="browse",
        )
        scroll_y.config(command=self._tree.yview)
        scroll_x.config(command=self._tree.xview)

        for col in self.COLUMNS:
            self._tree.heading(
                col,
                text=col,
                command=lambda c=col: self._sort_by(c),
            )
            self._tree.column(col, width=self.COL_WIDTHS[col], minwidth=40, stretch=True)

        self._tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Row double-click → open URL
        self._tree.bind("<Double-1>", self._on_row_double_click)

        # ---- Log panel ----
        log_frame = ttk.Frame(self)
        log_frame.pack(fill=tk.X, padx=12, pady=(6, 8))

        ttk.Label(log_frame, text="Activity log:", font=("Helvetica", 9, "bold")).pack(anchor=tk.W)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL)
        self._log_text = tk.Text(
            log_frame,
            height=6,
            bg="#11111b",
            fg="#a6e3a1",
            font=("Courier", 9),
            state=tk.DISABLED,
            yscrollcommand=log_scroll.set,
            wrap=tk.WORD,
        )
        log_scroll.config(command=self._log_text.yview)
        self._log_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Store proxy list (populated via dialog)
        self._proxy_list: List[str] = []

    # ------------------------------------------------------------------
    # Proxy config dialog
    # ------------------------------------------------------------------
    def _show_proxy_dialog(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("Proxy Configuration")
        dlg.geometry("480x320")
        dlg.configure(bg="#1e1e2e")
        dlg.grab_set()

        tk.Label(
            dlg,
            text="Enter proxies (one per line).\nFormats: http://host:port  |  socks5://user:pass@host:port",
            bg="#1e1e2e",
            fg="#cdd6f4",
            font=("Helvetica", 10),
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=12, pady=(10, 4))

        txt = tk.Text(dlg, height=10, bg="#181825", fg="#cdd6f4",
                      font=("Courier", 10), insertbackground="#cdd6f4")
        txt.pack(fill=tk.BOTH, expand=True, padx=12)
        txt.insert("1.0", "\n".join(self._proxy_list))

        def _save() -> None:
            raw = txt.get("1.0", tk.END).strip()
            self._proxy_list = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            self._log(f"Proxy list updated: {len(self._proxy_list)} proxies configured.")
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="Save", command=_save).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Search control
    # ------------------------------------------------------------------
    def _start_search(self) -> None:
        query = self._query_var.get().strip()
        if not query:
            messagebox.showwarning("No query", "Please enter a search query.")
            return
        if self._search_thread and self._search_thread.is_alive():
            messagebox.showinfo("Busy", "A search is already running.")
            return

        try:
            max_results = max(10, min(100, int(self._max_var.get())))
        except ValueError:
            max_results = 100
        self._max_var.set(str(max_results))

        # Reset UI
        self._clear_results()
        self._progress_var.set(0)
        self._progress_bar.config(maximum=max_results)
        self._status_var.set("Starting search …")
        self._search_btn.config(state=tk.DISABLED)
        self._cancel_btn.config(state=tk.NORMAL)
        self._cancelled = False

        self._search_thread = threading.Thread(
            target=self._run_search,
            args=(query, max_results, list(self._proxy_list)),
            daemon=True,
        )
        self._search_thread.start()

    def _cancel_search(self) -> None:
        self._cancelled = True
        self._log("⚠ Cancellation requested …")

    def _run_search(self, query: str, max_results: int, proxies: List[str]) -> None:
        """Runs in a background thread."""
        def _progress(collected: int, total: int) -> None:
            self._queue.put(("progress", collected, total))

        def _log(msg: str) -> None:
            self._queue.put(("log", msg))

        cancelled_flag = self  # captured for the inner class

        class _CancellableSession(StealthSession):
            """StealthSession subclass that honours the GUI's cancellation flag."""

            def _human_delay(self, extra: float = 0.0) -> None:
                if cancelled_flag._cancelled:
                    raise InterruptedError("Search cancelled by user.")
                super()._human_delay(extra)

        session = _CancellableSession(proxies=proxies or None)
        scraper = GoogleScraper(session=session, progress_cb=_progress, log_cb=_log)

        try:
            results = scraper.search(query, max_results=max_results)
            self._queue.put(("done", results))
        except InterruptedError:
            self._queue.put(("cancelled",))
        except Exception as exc:
            self._queue.put(("error", str(exc)))
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Queue polling (runs on main thread)
    # ------------------------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, collected, total = msg
                    self._progress_var.set(collected)
                    self._status_var.set(f"Collected {collected} / {total} results …")
                elif kind == "log":
                    self._log(msg[1])
                elif kind == "done":
                    self._on_search_done(msg[1])
                elif kind == "cancelled":
                    self._status_var.set("Search cancelled.")
                    self._log("Search cancelled.")
                    self._reset_buttons()
                elif kind == "error":
                    self._status_var.set(f"Error: {msg[1]}")
                    self._log(f"⛔ Error: {msg[1]}")
                    self._reset_buttons()
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _on_search_done(self, results: List[SearchResult]) -> None:
        self._results = results
        self._populate_table(results)
        self._status_var.set(
            f"Done — {len(results)} unique results (sorted by relevancy score)."
        )
        self._log(f"✅ Search complete. {len(results)} unique results returned.")
        self._reset_buttons()

    def _reset_buttons(self) -> None:
        self._search_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------
    def _clear_results(self) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._results = []

    def _populate_table(self, results: List[SearchResult]) -> None:
        self._clear_results()
        for r in results:
            self._tree.insert(
                "",
                tk.END,
                values=(
                    r.rank,
                    f"{r.score:.4f}",
                    r.title,
                    r.url,
                    r.snippet,
                ),
            )

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        numeric_cols = {self.COL_RANK, self.COL_SCORE}
        reverse = not self._sort_asc

        def _key(r: SearchResult):
            if col in numeric_cols:
                return r.rank if col == self.COL_RANK else r.score
            if col == self.COL_TITLE:
                return r.title.lower()
            if col == self.COL_URL:
                return r.url.lower()
            if col == self.COL_SNIPPET:
                return r.snippet.lower()
            return 0

        sorted_results = sorted(self._results, key=_key, reverse=reverse)
        self._populate_table(sorted_results)
        arrow = " ▲" if self._sort_asc else " ▼"
        for c in self.COLUMNS:
            self._tree.heading(c, text=c + (arrow if c == col else ""))

    def _on_row_double_click(self, event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        values = self._tree.item(sel[0], "values")
        if values and len(values) >= 4:
            url = values[3]
            webbrowser.open(url)

    # ------------------------------------------------------------------
    # Log helper
    # ------------------------------------------------------------------
    def _log(self, message: str) -> None:
        self._log_text.config(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        self._log_text.insert(tk.END, f"[{ts}] {message}\n")
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    app = SearchApp()
    app.mainloop()


if __name__ == "__main__":
    main()
