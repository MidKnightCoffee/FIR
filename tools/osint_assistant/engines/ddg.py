"""
engines/ddg.py — DuckDuckGo search engine scraper.

DuckDuckGo's HTML interface (html.duckduckgo.com) is used to avoid
JavaScript-heavy pages and stay within scraping best practices.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import SearchResult
from .base import BaseEngine, clean_text, extract_url_from_redirect, is_engine_internal

# DuckDuckGo's non-JS HTML interface
_SEARCH_URL = "https://html.duckduckgo.com/html/"
_RESULTS_PER_PAGE = 10


class DuckDuckGoEngine(BaseEngine):
    """Scrapes DuckDuckGo HTML search results."""

    name = "ddg"
    max_results_per_query = 10

    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        # DDG HTML interface uses POST with s= offset
        params = {
            "q": query,
            "b": "",          # blank = first page
            "kl": "us-en",    # region
            "df": "",         # date filter: off
        }
        if page > 0:
            params["s"] = str(page * _RESULTS_PER_PAGE)
            params["dc"] = str(page * _RESULTS_PER_PAGE + 1)
            params["b"] = f"p{page + 1}"

        self._log(f"Fetching page {page + 1}")
        # DDG HTML interface responds to POST as well as GET
        response = self._session.get(
            _SEARCH_URL,
            params=params,
            referer=referer or "https://duckduckgo.com/",
        )
        return response.text, response.url

    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        soup = self._soup(html_text)
        results: List[SearchResult] = []
        rank = start + 1

        # Primary: div.result containers
        for item in soup.select("div.result, div.web-result"):
            # Title + URL
            title_node = item.select_one(
                "a.result__a, h2.result__title a, a[class*='result__a']"
            )
            if not title_node:
                continue
            href = title_node.get("href", "")
            url = extract_url_from_redirect(href, param="uddg") or href
            if not url.startswith("http"):
                continue
            if is_engine_internal(url, "duckduckgo.com"):
                continue

            title = clean_text(title_node)
            if not title:
                continue

            snippet = ""
            for sel in ["a.result__snippet", "div.result__snippet",
                         "div[class*='snippet']", "span[class*='snippet']"]:
                node = item.select_one(sel)
                if node:
                    snippet = clean_text(node)
                    break

            r = self._make_result(rank, title, url, snippet, self.name)
            if r:
                results.append(r)
                rank += 1

        # Fallback
        if not results:
            seen: set = set()
            rank = start + 1
            for anchor in soup.find_all("a", href=True):
                href = anchor.get("href", "")
                url = extract_url_from_redirect(href, param="uddg") or href
                if not url.startswith("http") or url in seen:
                    continue
                if is_engine_internal(url, "duckduckgo.com"):
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
