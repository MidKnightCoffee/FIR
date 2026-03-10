"""
query_builder.py — Query variation engine for OSINT-style coverage.

Provides:
  • Automatic language detection (via langdetect)
  • Engine-specific search operator syntax
  • Synonym expansion for broader discovery
  • 20+ query variations per engine per query
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
try:
    from langdetect import detect as _langdetect
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _LANGDETECT_AVAILABLE = False
    logger.warning("langdetect not installed; language detection disabled.")


def detect_language(text: str) -> str:
    """
    Return a BCP-47 language code for *text* (e.g. ``"en"``, ``"fr"``).
    Falls back to ``"en"`` if langdetect is unavailable or detection fails.
    """
    if not _LANGDETECT_AVAILABLE or not text.strip():
        return "en"
    try:
        return _langdetect(text)
    except Exception:
        return "en"


# ---------------------------------------------------------------------------
# Synonym dictionary
# OSINT-focused: common research topics → relevant synonyms / related terms
# ---------------------------------------------------------------------------
_SYNONYMS: Dict[str, List[str]] = {
    # Identity / person
    "person": ["individual", "subject", "target", "profile"],
    "name": ["alias", "identity", "username", "handle"],
    "email": ["e-mail", "electronic mail", "contact", "address"],
    "phone": ["telephone", "mobile", "cell", "number"],
    # Organisations
    "company": ["corporation", "organisation", "organization", "firm", "enterprise"],
    "government": ["gov", "federal", "state", "ministry", "agency"],
    # Security / threat intel
    "vulnerability": ["CVE", "exploit", "weakness", "flaw", "security hole"],
    "malware": ["virus", "ransomware", "trojan", "spyware", "backdoor"],
    "hacker": ["threat actor", "adversary", "attacker", "cracker"],
    "breach": ["leak", "exposure", "incident", "compromise", "dump"],
    "password": ["credential", "passphrase", "secret", "token"],
    "database": ["db", "dataset", "data store", "repository"],
    # Social media
    "social media": ["twitter", "facebook", "instagram", "linkedin", "reddit"],
    "post": ["tweet", "status", "message", "update", "entry"],
    # Finance
    "money": ["funds", "payment", "finance", "transaction", "transfer"],
    "cryptocurrency": ["bitcoin", "crypto", "ethereum", "blockchain", "wallet"],
    # Legal / criminal
    "crime": ["fraud", "scam", "illegal", "criminal", "felony"],
    "lawsuit": ["litigation", "court case", "legal action", "suit", "charges"],
    # Location
    "location": ["address", "coordinates", "GPS", "geolocation", "place"],
    "ip address": ["IP", "inet", "netblock", "CIDR", "ASN"],
    # Files
    "document": ["file", "report", "record", "form", "paper"],
    "pdf": ["filetype:pdf", "portable document", ".pdf"],
    "spreadsheet": ["filetype:xlsx", "filetype:csv", "excel", ".xlsx"],
}


def expand_synonyms(query: str, max_synonyms: int = 3) -> List[str]:
    """
    Return a list of synonyms/related terms found in *query*.

    Parameters
    ----------
    query:      The search query.
    max_synonyms: Maximum number of synonym strings to return.
    """
    found: List[str] = []
    query_lower = query.lower()
    for term, syns in _SYNONYMS.items():
        if term in query_lower:
            found.extend(syns[:max_synonyms])
    return list(dict.fromkeys(found))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Engine-specific operator sets
# ---------------------------------------------------------------------------
# Each entry is (operator_template, description).
# {q} is replaced with the base query; {term} with a synonym/file type etc.
_GOOGLE_OPERATORS: List[Tuple[str, str]] = [
    ("{q}", "bare query"),
    ('"{q}"', "exact phrase"),
    ("{q} site:reddit.com", "reddit discussions"),
    ("{q} site:github.com", "github"),
    ("{q} site:pastebin.com", "pastebin leaks"),
    ("{q} site:twitter.com OR site:x.com", "twitter/X"),
    ("{q} site:linkedin.com", "linkedin profiles"),
    ("{q} site:gov", "government sites"),
    ("{q} site:edu", "educational sites"),
    ("{q} filetype:pdf", "PDF documents"),
    ("{q} filetype:xlsx OR filetype:csv", "spreadsheets"),
    ("{q} filetype:docx OR filetype:doc", "Word documents"),
    ("{q} inurl:admin", "admin pages"),
    ("{q} inurl:login", "login pages"),
    ("{q} intitle:{q}", "title-focused"),
    ("{q} intext:{q}", "body-text focused"),
    ("{q} after:2020-01-01", "recent (post-2020)"),
    ("{q} after:2023-01-01", "very recent (post-2023)"),
    ("{q} -ads -sponsored", "exclude ads"),
    ("{q} related:{q}", "related sites"),
    ("{q} cache:{q}", "cached pages"),
]

_BING_OPERATORS: List[Tuple[str, str]] = [
    ("{q}", "bare query"),
    ('"{q}"', "exact phrase"),
    ("{q} site:reddit.com", "reddit"),
    ("{q} site:github.com", "github"),
    ("{q} site:pastebin.com", "pastebin"),
    ("{q} site:twitter.com OR site:x.com", "twitter/X"),
    ("{q} site:linkedin.com", "linkedin"),
    ("{q} site:gov", "government"),
    ("{q} site:edu", "educational"),
    ("{q} filetype:pdf", "PDF"),
    ("{q} filetype:xlsx", "Excel"),
    ("{q} filetype:docx", "Word"),
    ("{q} inurl:admin", "admin"),
    ("{q} inurl:login", "login"),
    ("{q} intitle:{q}", "title"),
    ("{q} language:en", "English"),
    ("{q} contains:pdf", "contains PDF link"),
    ("{q} ip:1.1.1.1", "IP lookup syntax"),
    ("{q} loc:us", "US results"),
    ("{q} feed:{q}", "RSS/Atom feeds"),
    ("{q} hasfeed:{q}", "pages with feeds"),
]

_DDG_OPERATORS: List[Tuple[str, str]] = [
    ("{q}", "bare query"),
    ('"{q}"', "exact phrase"),
    ("{q} site:reddit.com", "reddit"),
    ("{q} site:github.com", "github"),
    ("{q} site:pastebin.com", "pastebin"),
    ("{q} site:twitter.com", "twitter"),
    ("{q} site:linkedin.com", "linkedin"),
    ("{q} site:gov", "government"),
    ("{q} site:edu", "educational"),
    ("{q} filetype:pdf", "PDF"),
    ("{q} filetype:xlsx", "Excel"),
    ("{q} inurl:admin", "admin"),
    ("{q} inurl:login", "login"),
    ("{q} intitle:{q}", "title-focused"),
    ("{q} -site:google.com", "exclude google"),
    ("{q} region:us-en", "US English region"),
    ("{q} region:gb-en", "UK English region"),
    ("{q} !g", "route to Google"),
    ("{q} !gh", "route to GitHub"),
    ("{q} !so", "route to Stack Overflow"),
    ("{q} !reddit", "route to Reddit"),
]

_YANDEX_OPERATORS: List[Tuple[str, str]] = [
    ("{q}", "bare query"),
    ('"{q}"', "exact phrase"),
    ("{q} site:reddit.com", "reddit"),
    ("{q} site:github.com", "github"),
    ("{q} url:{q}", "URL keyword"),
    ("{q} mime:pdf", "PDF (Yandex mime)"),
    ("{q} mime:xlsx", "Excel (Yandex mime)"),
    ("{q} lang:en", "English"),
    ("{q} lang:ru", "Russian"),
    ("{q} lang:de", "German"),
    ("{q} lang:fr", "French"),
    ("{q} lang:zh", "Chinese"),
    ("{q} host:github.com", "GitHub host"),
    ("{q} host:pastebin.com", "Pastebin host"),
    ("{q} date:week", "this week"),
    ("{q} date:month", "this month"),
    ("{q} date:year", "this year"),
    ("{q} rhost:com", "commercial domains"),
    ("{q} rhost:gov", "government domains"),
    ("{q} rhost:edu", "educational domains"),
    ("{q} title:{q}", "title"),
]

_BAIDU_OPERATORS: List[Tuple[str, str]] = [
    ("{q}", "bare query"),
    ('"{q}"', "exact phrase"),
    ("{q} site:github.com", "github"),
    ("{q} site:zhihu.com", "zhihu (Q&A)"),
    ("{q} site:weibo.com", "weibo"),
    ("{q} site:baidu.com", "baidu own"),
    ("{q} site:gov.cn", "Chinese government"),
    ("{q} site:edu.cn", "Chinese education"),
    ("{q} filetype:pdf", "PDF"),
    ("{q} filetype:doc", "Word"),
    ("{q} filetype:xls", "Excel"),
    ("{q} inurl:admin", "admin"),
    ("{q} inurl:login", "login"),
    ("{q} intitle:{q}", "title"),
    ("{q} inanchor:{q}", "anchor text"),
    ("{q} time:week", "this week"),
    ("{q} time:month", "this month"),
    ("{q} time:year", "this year"),
    ("{q} -site:baidu.com", "exclude baidu"),
    ("{q} 中文", "Chinese language"),
]

_ENGINE_OPERATORS: Dict[str, List[Tuple[str, str]]] = {
    "google": _GOOGLE_OPERATORS,
    "bing": _BING_OPERATORS,
    "ddg": _DDG_OPERATORS,
    "yandex": _YANDEX_OPERATORS,
    "baidu": _BAIDU_OPERATORS,
}

# Language-specific operator adjustments
_LANG_SUFFIXES: Dict[str, str] = {
    "fr": " lang:fr",
    "de": " lang:de",
    "es": " lang:es",
    "ru": " lang:ru",
    "zh": " lang:zh",
    "ja": " lang:ja",
    "ar": " lang:ar",
    "pt": " lang:pt",
    "it": " lang:it",
    "nl": " lang:nl",
}


def _format_variation(template: str, query: str) -> str:
    """Substitute {q} placeholders in a template with the query text."""
    # Strip filetype operators from the {q} substitution inside operators
    base = re.sub(r"\bfiletype:\S+", "", query).strip()
    try:
        return template.format(q=base)
    except (KeyError, ValueError):
        return f"{base} {template}"


class QueryBuilder:
    """
    Builds OSINT-optimised query variations for a given search engine.

    Parameters
    ----------
    engine:
        One of ``"google"``, ``"bing"``, ``"ddg"``, ``"yandex"``,
        ``"baidu"``.
    """

    def __init__(self, engine: str) -> None:
        self._engine = engine.lower()
        self._operators = _ENGINE_OPERATORS.get(self._engine, _GOOGLE_OPERATORS)

    def build(
        self,
        query: str,
        max_variations: int = 20,
        include_synonyms: bool = True,
        language: Optional[str] = None,
    ) -> List[str]:
        """
        Return up to *max_variations* unique query strings.

        Parameters
        ----------
        query:
            The raw user query.
        max_variations:
            Maximum number of query strings to produce.
        include_synonyms:
            When True, extra variations using synonyms are appended.
        language:
            Override language detection; auto-detected when ``None``.
        """
        lang = language or detect_language(query)
        lang_suffix = _LANG_SUFFIXES.get(lang, "")

        variations: List[str] = []
        seen: set = set()

        def _add(v: str) -> None:
            v = v.strip()
            if v and v not in seen:
                seen.add(v)
                variations.append(v)

        # 1. Operator-based variations from the engine's operator table
        for template, _desc in self._operators:
            _add(_format_variation(template, query))

        # 2. Language-adjusted bare query (if non-English detected)
        if lang_suffix:
            _add(f"{query}{lang_suffix}")

        # 3. Synonym-expanded variations
        if include_synonyms:
            synonyms = expand_synonyms(query)
            for syn in synonyms[:5]:
                _add(f'"{query}" OR "{syn}"')
                _add(f"{query} {syn}")

        return variations[:max_variations]

    def build_all_engines(
        self,
        query: str,
        max_variations: int = 20,
        include_synonyms: bool = True,
        language: Optional[str] = None,
    ) -> Dict[str, List[str]]:
        """
        Return a dict mapping each engine name to its query variation list.
        Uses the current engine's operator table for all engines in one call.
        """
        result: Dict[str, List[str]] = {}
        for engine in _ENGINE_OPERATORS:
            builder = QueryBuilder(engine)
            result[engine] = builder.build(
                query,
                max_variations=max_variations,
                include_synonyms=include_synonyms,
                language=language,
            )
        return result
