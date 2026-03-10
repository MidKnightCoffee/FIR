"""
engines/baidu.py — Baidu search engine scraper.
"""

from __future__ import annotations

import urllib.parse
from typing import List, Optional

from ..models import SearchResult
from .base import BaseEngine, clean_text, is_engine_internal

_SEARCH_URL = "https://www.baidu.com/s"
_RESULTS_PER_PAGE = 10


def _extract_baidu_url(href: str) -> str:
    """
    Baidu wraps result URLs in redirect links (//www.baidu.com/link?url=…).
    Return the href as-is if it looks like a real external URL, otherwise
    return the href unchanged so the GUI can display it.
    """
    if not href:
        return ""
    if href.startswith("http") and "baidu.com/link" not in href:
        return href
    # Baidu link redirects — keep as-is (real URL only known after redirect)
    if href.startswith("//"):
        href = "https:" + href
    if "baidu.com/link" in href:
        return href   # caller will still display it; redirect resolves in browser
    return href


class BaiduEngine(BaseEngine):
    """Scrapes Baidu organic search results."""

    name = "baidu"
    max_results_per_query = 10

    def _fetch_page(
        self, query: str, page: int, referer: Optional[str]
    ) -> tuple[str, str]:
        pn = page * _RESULTS_PER_PAGE
        params = {
            "wd": query,
            "pn": str(pn),
            "rn": str(_RESULTS_PER_PAGE),
            "ie": "utf-8",
            "usm": "1",
            "rsv_pq": "1",
            "rsv_t": "1",
            "cl": "3",
            "tn": "baidu",
        }
        self._log(f"Fetching page {page + 1} (pn={pn})")
        response = self._session.get(
            _SEARCH_URL,
            params=params,
            referer=referer or "https://www.baidu.com/",
            headers={"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
        )
        return response.text, response.url

    def _parse_page(self, html_text: str, start: int) -> List[SearchResult]:
        soup = self._soup(html_text)
        results: List[SearchResult] = []
        rank = start + 1

        # Primary: div.result or div.c-container
        for item in soup.select(
            "div.result, div.c-container, div[class*='result'], "
            "div[tpl*='se_com_default'], div[tpl*='bk_polysemy']"
        ):
            # Title anchor
            title_node = item.select_one(
                "h3.t a, h3 a, a.c-title-text, "
                "a[class*='title'], div.c-title a"
            )
            if not title_node:
                continue

            href = title_node.get("href", "")
            url = _extract_baidu_url(href)
            if not url or not url.startswith("http"):
                continue
            if is_engine_internal(url, "baidu.com") and "baidu.com/link" not in url:
                continue

            title = clean_text(title_node)
            if not title:
                continue

            snippet = ""
            for sel in [
                "div.c-abstract", "span.c-gap-top-small",
                "div[class*='abstract']", "div.c-span-last",
                "span[class*='content']",
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
                url = _extract_baidu_url(href)
                if not url.startswith("http") or url in seen:
                    continue
                if is_engine_internal(url, "baidu.com") and "baidu.com/link" not in url:
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
