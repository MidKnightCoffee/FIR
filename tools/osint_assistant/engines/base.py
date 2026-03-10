"""
engines/base.py — Abstract base class for all search engines.
"""

from __future__ import annotations

import html
import logging
import re
import urllib.parse
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

from bs4 import BeautifulSoup

from ..models import SearchResult
from ..session import HumanSession

logger = logging.getLogger(__name__)

# Common Google-internal hosts to skip
_INTERNAL_HOSTS = {
    "google.com", "www.google.com", "accounts.google.com",
    "support.google.com", "maps.google.com", "translate.google.com",
    "bing.com", "www.bing.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "yandex.com", "yandex.ru", "www.yandex.com", "www.yandex.ru",
    "qwant.com", "www.qwant.com",
    "baidu.com", "www.baidu.com",
}


def is_engine_internal(url: str, engine_host: str = "") -> bool:
    """Return True if the URL points to an engine-internal page."""
    try:
        host = urllib.parse.urlparse(url).netloc.lower()
        if host in _INTERNAL_HOSTS:
            return True
        if engine_host and host.endswith(engine_host):
            return True
        return False
    except Exception:
        return True


def extract_url_from_redirect(href: str, param: str = "q") -> str:
    """
    Extract the real destination URL from a search-engine redirect link.

    Many engines wrap results in ``/url?q=https://...`` or similar patterns.
    """
    if not href:
        return ""
    if href.startswith("http"):
        return href
    if "?" in href:
        try:
            parsed = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed.query)
            for key in (param, "url", "u", "link"):
                if key in qs:
                    return urllib.parse.unquote(qs[key][0])
        except Exception:
            pass
    return ""


def clean_text(node) -> str:
    """Return normalised text from a BeautifulSoup node (or empty string)."""
    if node is None:
        return ""
    raw = html.unescape(node.get_text(separator=" ", strip=True))
    # Collapse any run of whitespace (including non-breaking spaces) to one space
    return " ".join(raw.split())


class BaseEngine(ABC):
    """
    Abstract base class for all OSINT search engines.

    Subclasses must implement :meth:`_fetch_page` and :meth:`_parse_page`.
    """

    #: Engine name used in SearchResult.engine
    name: str = "base"

    #: Maximum results to collect per query variation
    max_results_per_query: int = 10

    def __init__(
        self,
        session: HumanSession,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._session = session
        self._log_cb = log_cb or (lambda msg: None)

    def _log(self, msg: str) -> None:
        logger.info("[%s] %s", self.name, msg)
        self._log_cb(f"[{self.name}] {msg}")

    def search(self, query: str, max_results: int = 10) -> List[SearchResult]:
        """
        Fetch and parse results for a single *query* string.

        Returns up to *max_results* :class:`SearchResult` objects.
        """
        results: List[SearchResult] = []
        page = 0
        referer: Optional[str] = None

        while len(results) < max_results:
            try:
                html_text, next_referer = self._fetch_page(query, page, referer)
            except RuntimeError as exc:
                self._log(f"⛔ {exc}")
                break

            page_results = self._parse_page(html_text, start=len(results))
            if not page_results:
                self._log(f"No results on page {page + 1}; stopping.")
                break

            results.extend(page_results)
            referer = next_referer
            page += 1

            if len(results) >= max_results:
                break

            self._session._human_delay()

        # Attach query + engine metadata
        for r in results:
            r.engine = self.name
            r.query = query

        return results[:max_results]

    @abstractmethod
    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        """
        Fetch one SERP page.

        Returns (html_text, response_url).  The response URL is used as the
        referrer for the next page request.
        """

    @abstractmethod
    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        """Parse a SERP HTML page and return a list of SearchResult objects."""

    # ------------------------------------------------------------------
    # Shared HTML parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _soup(html_text: str) -> BeautifulSoup:
        return BeautifulSoup(html_text, "lxml")

    @staticmethod
    def _make_result(
        rank: int, title: str, url: str, snippet: str,
        engine: str, query: str = "",
    ) -> Optional[SearchResult]:
        """Construct a SearchResult, returning None if the URL is invalid."""
        if not url.startswith("http") or not title:
            return None
        return SearchResult(
            rank=rank,
            title=title,
            url=url,
            snippet=snippet,
            engine=engine,
            query=query,
        )
