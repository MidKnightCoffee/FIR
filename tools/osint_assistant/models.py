"""
models.py — Shared data models for the OSINT Research Assistant.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Set

# Query-string keys stripped before URL fingerprinting
_STRIP_PARAMS: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term",
    "utm_content", "ref", "referrer", "source",
}


def _normalise_url(url: str) -> str:
    """Return a canonical URL used only for deduplication comparison."""
    try:
        parsed = urllib.parse.urlparse(url.lower().strip())
        params = urllib.parse.parse_qsl(parsed.query)
        params = [(k, v) for k, v in params if k not in _STRIP_PARAMS]
        params.sort()
        normalised = parsed._replace(
            fragment="",
            query=urllib.parse.urlencode(params),
        )
        path = normalised.path.rstrip("/") or "/"
        return urllib.parse.urlunparse(normalised._replace(path=path))
    except Exception:
        return url.lower().strip()


@dataclass(order=False)
class SearchResult:
    """A single search result from any engine."""

    rank: int           # 1-based position within the engine's raw response
    title: str
    url: str
    snippet: str
    engine: str         # e.g. "google", "bing", "ddg", "yandex", "qwant", "baidu"
    query: str = ""     # the query variation that produced this result
    score: float = 0.0  # relevancy score (higher = more relevant)

    # Internal fingerprints — not serialised
    _url_fingerprint: str = field(default="", init=False, repr=False)
    _content_fingerprint: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self._url_fingerprint = _normalise_url(self.url)
        content = f"{self.title.lower().strip()} {self.snippet.lower().strip()}"
        self._content_fingerprint = hashlib.sha256(content.encode()).hexdigest()
