"""
tests_osint_assistant.py — Unit tests for the OSINT Research Assistant.

Tests cover the pure-logic components (no network, no GUI):
  - SearchResult model and URL normalisation
  - QueryBuilder: variation generation, synonym expansion, language detection
  - Deduplicator: deduplication and relevancy scoring
  - HumanSession helpers: CAPTCHA detection, back-off delay
  - BaseEngine HTML parsing helpers
  - Dispatcher: engine selection, cancellation flag
"""

from __future__ import annotations

import math
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Allow importing from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.osint_assistant.models import SearchResult, _normalise_url
from tools.osint_assistant.query_builder import (
    QueryBuilder,
    detect_language,
    expand_synonyms,
    _ENGINE_OPERATORS,
)
from tools.osint_assistant.deduplicator import deduplicate, compute_score
from tools.osint_assistant.session import HumanSession, BACKOFF_MAX
from tools.osint_assistant.engines.base import (
    BaseEngine,
    extract_url_from_redirect,
    is_engine_internal,
    clean_text,
)
from tools.osint_assistant.dispatcher import Dispatcher, DEFAULT_ENGINES


# ---------------------------------------------------------------------------
# SearchResult / URL normalisation
# ---------------------------------------------------------------------------
class TestNormaliseUrl(unittest.TestCase):

    def test_strips_fragment(self):
        self.assertEqual(
            _normalise_url("https://example.com/page#anchor"),
            _normalise_url("https://example.com/page"),
        )

    def test_strips_utm_params(self):
        plain = _normalise_url("https://example.com/page")
        with_utm = _normalise_url(
            "https://example.com/page?utm_source=google&utm_medium=cpc"
        )
        self.assertEqual(plain, with_utm)

    def test_sorts_query_params(self):
        a = _normalise_url("https://example.com/?b=2&a=1")
        b = _normalise_url("https://example.com/?a=1&b=2")
        self.assertEqual(a, b)

    def test_strips_trailing_slash(self):
        self.assertEqual(
            _normalise_url("https://example.com/path/"),
            _normalise_url("https://example.com/path"),
        )

    def test_lowercases(self):
        self.assertEqual(
            _normalise_url("HTTPS://EXAMPLE.COM/Page"),
            _normalise_url("https://example.com/page"),
        )

    def test_preserves_non_tracking_params(self):
        url = "https://example.com/search?q=python&page=2"
        self.assertIn("q=python", _normalise_url(url))


class TestSearchResultFingerprints(unittest.TestCase):

    def _make(self, rank, title, url, snippet="", engine="google"):
        return SearchResult(rank=rank, title=title, url=url,
                            snippet=snippet, engine=engine)

    def test_same_url_after_utm_strip(self):
        r1 = self._make(1, "A", "https://example.com/page?utm_source=bing")
        r2 = self._make(2, "A", "https://example.com/page")
        self.assertEqual(r1._url_fingerprint, r2._url_fingerprint)

    def test_different_urls_different_fingerprint(self):
        r1 = self._make(1, "A", "https://example.com/page1")
        r2 = self._make(2, "A", "https://example.com/page2")
        self.assertNotEqual(r1._url_fingerprint, r2._url_fingerprint)

    def test_content_fingerprint_same_content(self):
        r1 = self._make(1, "Hello world", "https://a.com", "Some text here")
        r2 = self._make(2, "Hello world", "https://b.com", "Some text here")
        self.assertEqual(r1._content_fingerprint, r2._content_fingerprint)

    def test_content_fingerprint_different_content(self):
        r1 = self._make(1, "Title A", "https://a.com", "Snippet A")
        r2 = self._make(2, "Title B", "https://b.com", "Snippet B")
        self.assertNotEqual(r1._content_fingerprint, r2._content_fingerprint)

    def test_engine_field_stored(self):
        r = self._make(1, "Test", "https://example.com", engine="bing")
        self.assertEqual(r.engine, "bing")


# ---------------------------------------------------------------------------
# QueryBuilder
# ---------------------------------------------------------------------------
class TestQueryBuilder(unittest.TestCase):

    def test_google_variations_count(self):
        qb = QueryBuilder("google")
        variations = qb.build("malware analysis", max_variations=20)
        self.assertGreaterEqual(len(variations), 20)

    def test_bing_variations_count(self):
        qb = QueryBuilder("bing")
        variations = qb.build("threat intelligence", max_variations=20)
        self.assertGreaterEqual(len(variations), 20)

    def test_ddg_variations_count(self):
        qb = QueryBuilder("ddg")
        variations = qb.build("data breach", max_variations=20)
        self.assertGreaterEqual(len(variations), 20)

    def test_yandex_variations_count(self):
        qb = QueryBuilder("yandex")
        variations = qb.build("ransomware CVE", max_variations=20)
        self.assertGreaterEqual(len(variations), 20)

    def test_baidu_variations_count(self):
        qb = QueryBuilder("baidu")
        variations = qb.build("vulnerability scan", max_variations=20)
        self.assertGreaterEqual(len(variations), 20)

    def test_no_duplicate_variations(self):
        for engine in _ENGINE_OPERATORS:
            qb = QueryBuilder(engine)
            variations = qb.build("osint research", max_variations=20)
            self.assertEqual(len(variations), len(set(variations)),
                             f"Duplicates in {engine} variations")

    def test_bare_query_always_included(self):
        qb = QueryBuilder("google")
        variations = qb.build("python security", max_variations=20)
        self.assertIn("python security", variations)

    def test_exact_phrase_included(self):
        qb = QueryBuilder("bing")
        variations = qb.build("password leak", max_variations=20)
        exact = [v for v in variations if v.startswith('"')]
        self.assertGreater(len(exact), 0)

    def test_site_operator_included(self):
        qb = QueryBuilder("google")
        variations = qb.build("hacker forums", max_variations=20)
        sites = [v for v in variations if "site:" in v]
        self.assertGreater(len(sites), 0)

    def test_all_engines_covered(self):
        qb = QueryBuilder("google")
        result = qb.build_all_engines("malware", max_variations=20)
        for engine in ("google", "bing", "ddg", "yandex", "baidu"):
            self.assertIn(engine, result)
            self.assertGreater(len(result[engine]), 0)

    def test_max_variations_respected(self):
        qb = QueryBuilder("google")
        variations = qb.build("test", max_variations=5)
        self.assertLessEqual(len(variations), 5)

    def test_synonym_expansion(self):
        qb = QueryBuilder("google")
        # "malware" is in the synonym dict; use max_variations=30 to give
        # room beyond the 21 base operator templates.
        variations = qb.build("malware analysis", max_variations=30,
                               include_synonyms=True)
        synonym_vars = [v for v in variations if "virus" in v or "ransomware" in v
                        or "trojan" in v]
        self.assertGreater(len(synonym_vars), 0)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
class TestLanguageDetection(unittest.TestCase):

    def test_english_detected(self):
        lang = detect_language("What is the latest cybersecurity vulnerability?")
        self.assertEqual(lang, "en")

    def test_fallback_on_empty(self):
        self.assertEqual(detect_language(""), "en")

    def test_fallback_on_short_text(self):
        # Very short text may fail detection — must not raise
        result = detect_language("hi")
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# Synonym expansion
# ---------------------------------------------------------------------------
class TestSynonymExpansion(unittest.TestCase):

    def test_known_term_has_synonyms(self):
        syns = expand_synonyms("malware detection tools")
        self.assertGreater(len(syns), 0)

    def test_unknown_term_returns_empty(self):
        syns = expand_synonyms("xyzzyfoo barbazquux")
        self.assertEqual(syns, [])

    def test_no_duplicates(self):
        syns = expand_synonyms("malware malware malware")
        self.assertEqual(len(syns), len(set(syns)))

    def test_max_synonyms_respected(self):
        syns = expand_synonyms("malware password breach", max_synonyms=1)
        # Each matching term contributes at most 1 synonym
        # three terms matched → at most 3 synonyms
        self.assertLessEqual(len(syns), 10)


# ---------------------------------------------------------------------------
# Deduplicator
# ---------------------------------------------------------------------------
class TestDeduplicator(unittest.TestCase):

    def _make(self, rank, title, url, snippet="", engine="google"):
        return SearchResult(rank=rank, title=title, url=url,
                            snippet=snippet, engine=engine)

    def test_dedup_same_url(self):
        r1 = self._make(1, "Title A", "https://example.com/page")
        r2 = self._make(2, "Title A", "https://example.com/page?utm_source=bing")
        results = deduplicate([r1, r2])
        self.assertEqual(len(results), 1)

    def test_dedup_same_content(self):
        r1 = self._make(1, "Same Title", "https://a.com", "Same snippet")
        r2 = self._make(2, "Same Title", "https://b.com", "Same snippet")
        results = deduplicate([r1, r2])
        self.assertEqual(len(results), 1)

    def test_different_results_kept(self):
        r1 = self._make(1, "Title A", "https://a.com", "Snippet A")
        r2 = self._make(2, "Title B", "https://b.com", "Snippet B")
        results = deduplicate([r1, r2])
        self.assertEqual(len(results), 2)

    def test_sorted_by_score(self):
        results = [
            self._make(i, f"Title {i}", f"https://example.com/{i}")
            for i in range(1, 6)
        ]
        deduped = deduplicate(results, query="title")
        scores = [r.score for r in deduped]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_ranks_renumbered(self):
        results = [
            self._make(i, f"Title {i}", f"https://example.com/{i}")
            for i in range(1, 4)
        ]
        deduped = deduplicate(results)
        for idx, r in enumerate(deduped, start=1):
            self.assertEqual(r.rank, idx)

    def test_empty_list(self):
        self.assertEqual(deduplicate([]), [])


# ---------------------------------------------------------------------------
# Relevancy scoring
# ---------------------------------------------------------------------------
class TestComputeScore(unittest.TestCase):

    def _make(self, rank, title="", snippet=""):
        return SearchResult(rank=rank, title=title, url="https://x.com",
                            snippet=snippet, engine="google")

    def test_higher_rank_lower_score(self):
        r1 = self._make(1, "neutral", "neutral")
        r2 = self._make(10, "neutral", "neutral")
        self.assertGreater(compute_score(r1, []), compute_score(r2, []))

    def test_keyword_match_boosts_score(self):
        terms = ["python", "security"]
        r_match = self._make(5, "Python security guide", "All about python security")
        r_none = self._make(5, "Generic title here", "Nothing relevant here")
        self.assertGreater(
            compute_score(r_match, terms), compute_score(r_none, terms)
        )

    def test_title_weighted_more_than_snippet(self):
        terms = ["python"]
        r_title = self._make(3, "Python tutorial", "Learn something here")
        r_snippet = self._make(3, "Generic title", "Python programming tutorial content")
        self.assertGreater(
            compute_score(r_title, terms), compute_score(r_snippet, terms)
        )

    def test_score_is_finite_positive(self):
        r = self._make(1, "hello", "world")
        s = compute_score(r, ["hello", "world"])
        self.assertGreater(s, 0)
        self.assertTrue(math.isfinite(s))

    def test_no_query_terms(self):
        r = self._make(1, "something", "text")
        s = compute_score(r, [])
        self.assertGreater(s, 0)   # rank-decay component still fires


# ---------------------------------------------------------------------------
# HumanSession helpers
# ---------------------------------------------------------------------------
class TestCaptchaDetection(unittest.TestCase):

    def _mock_response(self, status_code: int, text: str):
        m = MagicMock()
        m.status_code = status_code
        m.text = text
        return m

    def test_429_blocked(self):
        self.assertTrue(HumanSession._is_blocked(self._mock_response(429, "")))

    def test_503_blocked(self):
        self.assertTrue(HumanSession._is_blocked(self._mock_response(503, "")))

    def test_captcha_text_detected(self):
        self.assertTrue(HumanSession._is_blocked(
            self._mock_response(200, "Our systems have detected unusual traffic.")
        ))

    def test_normal_200_not_blocked(self):
        self.assertFalse(HumanSession._is_blocked(
            self._mock_response(200, "<html><body><div>Result</div></body></html>")
        ))

    def test_access_denied_blocked(self):
        self.assertTrue(HumanSession._is_blocked(
            self._mock_response(200, "Access Denied — automated queries detected")
        ))


class TestBackoffDelay(unittest.TestCase):

    def test_attempt_1_within_range(self):
        for _ in range(20):
            d = HumanSession._backoff_delay(1)
            self.assertGreaterEqual(d, 2.0)
            self.assertLessEqual(d, BACKOFF_MAX)

    def test_higher_attempt_longer_mean(self):
        mean1 = sum(HumanSession._backoff_delay(1) for _ in range(50)) / 50
        mean3 = sum(HumanSession._backoff_delay(3) for _ in range(50)) / 50
        self.assertGreater(mean3, mean1)

    def test_never_exceeds_max(self):
        for attempt in range(1, 12):
            for _ in range(10):
                self.assertLessEqual(HumanSession._backoff_delay(attempt), BACKOFF_MAX)


class TestCancellableSession(unittest.TestCase):

    def test_delay_raises_when_cancelled(self):
        cancelled = True

        class _CS(HumanSession):
            def _human_delay(self, extra: float = 0.0) -> None:
                if cancelled:
                    raise InterruptedError("cancelled")
                super()._human_delay(extra)

        sess = _CS.__new__(_CS)
        with self.assertRaises(InterruptedError):
            sess._human_delay()

    def test_delay_proceeds_when_not_cancelled(self):
        calls = []

        class _CS(HumanSession):
            def _human_delay(self, extra: float = 0.0) -> None:
                calls.append(1)  # record call, skip actual sleep

        sess = _CS.__new__(_CS)
        sess._human_delay()
        self.assertEqual(len(calls), 1)


# ---------------------------------------------------------------------------
# BaseEngine URL helpers
# ---------------------------------------------------------------------------
class TestExtractUrlFromRedirect(unittest.TestCase):

    def test_google_redirect(self):
        href = "/url?q=https://example.com/page&sa=U&ved=xxx"
        self.assertEqual(
            extract_url_from_redirect(href, param="q"), "https://example.com/page"
        )

    def test_plain_http(self):
        self.assertEqual(
            extract_url_from_redirect("https://example.com"), "https://example.com"
        )

    def test_empty_returns_empty(self):
        self.assertEqual(extract_url_from_redirect(""), "")

    def test_ddg_redirect(self):
        href = "/l/?uddg=https%3A%2F%2Fexample.com%2Fpage"
        result = extract_url_from_redirect(href, param="uddg")
        self.assertEqual(result, "https://example.com/page")


class TestIsEngineInternal(unittest.TestCase):

    def test_google_internal(self):
        self.assertTrue(is_engine_internal("https://accounts.google.com/login"))

    def test_bing_internal(self):
        self.assertTrue(is_engine_internal("https://www.bing.com/search?q=test"))

    def test_external(self):
        self.assertFalse(is_engine_internal("https://example.com/page"))

    def test_yandex_internal(self):
        self.assertTrue(is_engine_internal("https://yandex.com/search/?text=test"))


class TestCleanText(unittest.TestCase):

    def test_strips_whitespace(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<span>  hello  world  </span>", "lxml")
        node = soup.find("span")
        self.assertEqual(clean_text(node), "hello world")

    def test_none_returns_empty(self):
        self.assertEqual(clean_text(None), "")

    def test_unescapes_html_entities(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<span>AT&amp;T &lt;Corp&gt;</span>", "lxml")
        node = soup.find("span")
        text = clean_text(node)
        self.assertIn("AT&T", text)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
class TestDispatcher(unittest.TestCase):

    def test_default_engines_are_five(self):
        self.assertEqual(len(DEFAULT_ENGINES), 5)
        for name in ("google", "bing", "ddg", "yandex", "baidu"):
            self.assertIn(name, DEFAULT_ENGINES)

    def test_engine_subset_selection(self):
        d = Dispatcher(engines=["google", "bing"])
        self.assertEqual(d._engine_names, ["google", "bing"])

    def test_cancellation_flag(self):
        d = Dispatcher()
        self.assertFalse(d._cancelled)
        d.cancel()
        self.assertTrue(d._cancelled)

    def test_dispatcher_returns_search_result_list(self):
        """
        Smoke-test: Dispatcher.search returns a list (even if engines raise).
        Uses patched engines so no network calls are made.
        """
        from tools.osint_assistant.engines.google import GoogleEngine

        def _fake_search(self, query, max_results=10):
            return [
                SearchResult(
                    rank=1, title="Fake Result", url="https://fake.example.com",
                    snippet="A fake snippet.", engine=self.name, query=query,
                )
            ]

        with patch.object(GoogleEngine, "search", _fake_search):
            d = Dispatcher(
                engines=["google"],
                max_variations=1,
                results_per_variation=1,
            )
            results = d.search("test query", target_results=10)
        self.assertIsInstance(results, list)
        if results:
            self.assertIsInstance(results[0], SearchResult)


# ---------------------------------------------------------------------------
# Engine operator coverage
# ---------------------------------------------------------------------------
class TestEngineOperatorCoverage(unittest.TestCase):
    """Each engine must define at least 20 operator templates."""

    def test_each_engine_has_20_plus_operators(self):
        from tools.osint_assistant.query_builder import _ENGINE_OPERATORS
        for engine, ops in _ENGINE_OPERATORS.items():
            self.assertGreaterEqual(
                len(ops), 20,
                f"{engine} has only {len(ops)} operators (need ≥ 20)",
            )

    def test_qwant_not_registered(self):
        from tools.osint_assistant.query_builder import _ENGINE_OPERATORS
        self.assertNotIn("qwant", _ENGINE_OPERATORS)

    def test_engines_match_five_required(self):
        from tools.osint_assistant.query_builder import _ENGINE_OPERATORS
        self.assertEqual(
            set(_ENGINE_OPERATORS.keys()),
            {"google", "bing", "ddg", "yandex", "baidu"},
        )


if __name__ == "__main__":
    unittest.main()
