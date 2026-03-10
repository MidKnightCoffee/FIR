"""
deduplicator.py — Cross-engine result deduplication and relevancy scoring.

Provides:
  • URL-normalisation-based deduplication
  • Content-fingerprint deduplication (catches reposts with the same text)
  • TF-rank composite relevancy score
  • Final sort + renumbering
"""

from __future__ import annotations

import math
import re
from typing import List, Set

from .models import SearchResult


def compute_score(result: SearchResult, query_terms: List[str]) -> float:
    """
    Composite relevancy score:
      - Rank-decay (60 %):   score ∝ 1 / log2(rank + 1)
      - Keyword boost (40 %): TF-like score (title hits weighted 3×)
    """
    # Rank-decay — normalised so rank=1 → 1.0
    rank_score = 1.0 / math.log2(result.rank + 1)

    title_tokens = re.findall(r"\w+", result.title.lower())
    snippet_tokens = re.findall(r"\w+", result.snippet.lower())
    title_len = max(len(title_tokens), 1)
    snippet_len = max(len(snippet_tokens), 1)

    title_hits = sum(title_tokens.count(t) for t in query_terms)
    snippet_hits = sum(snippet_tokens.count(t) for t in query_terms)

    tf_title = title_hits / title_len
    tf_snippet = snippet_hits / snippet_len
    keyword_score = (3.0 * tf_title + 1.0 * tf_snippet) / 4.0

    return 0.60 * rank_score + 0.40 * keyword_score


def deduplicate(
    results: List[SearchResult],
    query: str = "",
) -> List[SearchResult]:
    """
    Deduplicate and score *results*, returning a sorted, renumbered list.

    Deduplication is performed on two levels:
      1. Normalised URL fingerprint (same URL after stripping tracking params)
      2. Content fingerprint (same title + snippet hash)

    Parameters
    ----------
    results:
        Raw results from one or more engines (may contain duplicates).
    query:
        Original user query, used for relevancy scoring.
    """
    query_terms = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]

    seen_url: Set[str] = set()
    seen_content: Set[str] = set()
    unique: List[SearchResult] = []

    for r in results:
        if r._url_fingerprint in seen_url:
            continue
        if r._content_fingerprint in seen_content:
            continue
        seen_url.add(r._url_fingerprint)
        seen_content.add(r._content_fingerprint)
        unique.append(r)

    for r in unique:
        r.score = compute_score(r, query_terms)

    unique.sort(key=lambda r: r.score, reverse=True)

    for idx, r in enumerate(unique, start=1):
        r.rank = idx

    return unique
