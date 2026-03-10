"""
engines/bing.py — Bing search engine scraper.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import SearchResult
from .base import BaseEngine, clean_text, extract_url_from_redirect, is_engine_internal

_SEARCH_URL = "https://www.bing.com/search"
_RESULTS_PER_PAGE = 10


class BingEngine(BaseEngine):
    """Scrapes Bing organic search results."""

    name = "bing"
    max_results_per_query = 10

    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        first = page * _RESULTS_PER_PAGE + 1
        params = {
            "q": query,
            "first": str(first),
            "count": str(_RESULTS_PER_PAGE),
            "setlang": "en-US",
            "cc": "US",
            "FORM": "PERE",
        }
        self._log(f"Fetching page {page + 1} (first={first})")
        response = self._session.get(_SEARCH_URL, params=params, referer=referer)
        return response.text, response.url

    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        soup = self._soup(html_text)
        results: List[SearchResult] = []
        rank = start + 1

        # Primary: li.b_algo containers
        for item in soup.select("li.b_algo"):
            h2 = item.find("h2")
            if not h2:
                continue
            anchor = h2.find("a", href=True) or item.find("a", href=True)
            if not anchor:
                continue
            url = anchor.get("href", "")
            if not url.startswith("http"):
                url = extract_url_from_redirect(url, param="url")
            if not url.startswith("http"):
                continue
            if is_engine_internal(url, "bing.com"):
                continue

            title = clean_text(h2)
            if not title:
                continue

            snippet = ""
            for sel in ["div.b_caption p", "p.b_lineclamp2", "div.b_snippet",
                         "p[class*='b_']", "div[class*='snippet']"]:
                node = item.select_one(sel)
                if node:
                    snippet = clean_text(node)
                    break

            r = self._make_result(rank, title, url, snippet, self.name)
            if r:
                results.append(r)
                rank += 1

        # Fallback: any anchor with a title child
        if not results:
            seen: set = set()
            rank = start + 1
            for anchor in soup.find_all("a", href=True):
                url = anchor.get("href", "")
                if not url.startswith("http") or url in seen:
                    continue
                if is_engine_internal(url, "bing.com"):
                    continue
                title = clean_text(anchor)
                if not title or len(title) < 5:
                    continue
                seen.add(url)
                r = self._make_result(rank, title, url, "", self.name)
                if r:
                    results.append(r)
                    rank += 1

        return results
