"""
engines/yandex.py — Yandex search engine scraper.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import SearchResult
from .base import BaseEngine, clean_text, extract_url_from_redirect, is_engine_internal

_SEARCH_URL = "https://yandex.com/search/"
_RESULTS_PER_PAGE = 10


class YandexEngine(BaseEngine):
    """Scrapes Yandex organic search results."""

    name = "yandex"
    max_results_per_query = 10

    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        params = {
            "text": query,
            "p": str(page),       # page number (0-based)
            "numdoc": str(_RESULTS_PER_PAGE),
            "lang": "en",
            "lr": "213",          # Moscow region code (broad results)
        }
        self._log(f"Fetching page {page + 1}")
        response = self._session.get(
            _SEARCH_URL,
            params=params,
            referer=referer or "https://yandex.com/",
        )
        return response.text, response.url

    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        soup = self._soup(html_text)
        results: List[SearchResult] = []
        rank = start + 1

        # Primary: li.serp-item or div.serp-item
        for item in soup.select(
            "li.serp-item, div.serp-item, div[class*='serp-item'], "
            "div.organic, div[class*='organic__']"
        ):
            # Title anchor
            title_node = item.select_one(
                "a.organic__url, h2 a, a[class*='organic__title-link'], "
                "a[class*='title__link'], a.b-serp-url__title"
            )
            if not title_node:
                title_node = item.find("h2")
                if title_node:
                    title_node = title_node.find("a") or title_node

            if not title_node:
                continue

            href = title_node.get("href", "") if hasattr(title_node, "get") else ""
            url = extract_url_from_redirect(href, param="url") or href
            if not url.startswith("http"):
                continue
            if is_engine_internal(url, "yandex."):
                continue

            title = clean_text(title_node)
            if not title:
                continue

            snippet = ""
            for sel in [
                "div.organic__content-wrapper",
                "div[class*='text-container']",
                "div.b-serp-item__content",
                "span[class*='extended-text']",
                "div[class*='snippet']",
            ]:
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
                url = extract_url_from_redirect(href, param="url") or href
                if not url.startswith("http") or url in seen:
                    continue
                if is_engine_internal(url, "yandex."):
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
