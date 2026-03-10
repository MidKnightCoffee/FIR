"""
engines/google.py — Google search engine scraper.
"""

from __future__ import annotations

import html as _html
import random
from typing import List, Optional

from ..models import SearchResult
from ..session import HumanSession
from .base import BaseEngine, clean_text, extract_url_from_redirect, is_engine_internal

_SEARCH_URL = "https://www.google.com/search"
_RESULTS_PER_PAGE = 10
_PWS_OFF_PROB = 0.5


class GoogleEngine(BaseEngine):
    """Scrapes Google organic search results."""

    name = "google"
    max_results_per_query = 10

    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        start = page * _RESULTS_PER_PAGE
        params = {
            "q": query,
            "num": str(_RESULTS_PER_PAGE),
            "start": str(start),
            "hl": "en",
            "gl": "us",
            "ie": "UTF-8",
            "oe": "UTF-8",
            "nfpr": "1",
            "safe": "off",
        }
        if random.random() < _PWS_OFF_PROB:
            params["pws"] = "0"

        self._log(f"Fetching page {page + 1} (start={start})")
        response = self._session.get(_SEARCH_URL, params=params, referer=referer)
        return response.text, response.url

    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        soup = self._soup(html_text)
        results: List[SearchResult] = []

        # Strategy 1: div.g containers
        containers = soup.select(
            "div.g, div[data-sokoban-container], div[jscontroller]"
        )
        rank = start + 1
        for container in containers:
            h3 = container.find("h3")
            if not h3:
                continue
            anchor = h3.find_parent("a") or h3.find("a") or container.find("a", href=True)
            if not anchor:
                continue
            href = anchor.get("href", "")
            url = extract_url_from_redirect(href, param="q")
            if not url or not url.startswith("http"):
                continue
            if is_engine_internal(url, ".google.com"):
                continue

            title = clean_text(h3)
            if not title:
                continue

            snippet = ""
            for sel in ["div[data-sncf]", "span.aCOpRe", "div.VwiC3b",
                         "span[class*='st']", "div[class*='st']"]:
                node = container.select_one(sel)
                if node:
                    snippet = clean_text(node)
                    break

            r = self._make_result(rank, title, url, snippet, self.name)
            if r:
                results.append(r)
                rank += 1

        # Strategy 2: fallback anchor scan
        if not results:
            seen: set = set()
            rank = start + 1
            for anchor in soup.find_all("a", href=True):
                href = anchor.get("href", "")
                url = extract_url_from_redirect(href, param="q")
                if not url or not url.startswith("http") or url in seen:
                    continue
                if is_engine_internal(url, ".google.com"):
                    continue
                h3 = anchor.find("h3")
                title = clean_text(h3) if h3 else clean_text(anchor)
                if not title or len(title) < 5:
                    continue
                seen.add(url)
                r = self._make_result(rank, _html.unescape(title), url, "", self.name)
                if r:
                    results.append(r)
                    rank += 1

        return results
