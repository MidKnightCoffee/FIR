"""
Unit tests for the FIR Stealth Google Search Tool.
Tests cover the pure-logic components (no network, no GUI):
  - URL normalisation / deduplication
  - Relevancy scoring
  - HTML parsing strategies
  - Stealth session helpers (CAPTCHA detection, back-off params)
"""

import math
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Allow importing from tools/ without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.google_search_tool import (
    BACKOFF_MAX,
    CAPTCHA_MARKERS,
    SearchResult,
    StealthSession,
    GoogleScraper,
    _normalise_url,
    _compute_score,
    _extract_real_url,
    _is_google_internal,
)


# ---------------------------------------------------------------------------
# URL normalisation
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


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------
class TestExtractRealUrl(unittest.TestCase):

    def test_google_redirect(self):
        href = "/url?q=https://example.com/page&sa=U&ved=xxx"
        self.assertEqual(_extract_real_url(href), "https://example.com/page")

    def test_plain_http(self):
        self.assertEqual(_extract_real_url("https://example.com"), "https://example.com")

    def test_relative_path(self):
        # Relative paths are not real URLs we want
        self.assertEqual(_extract_real_url("/search?q=test"), "")

    def test_empty(self):
        self.assertEqual(_extract_real_url(""), "")


# ---------------------------------------------------------------------------
# Google-internal URL detection
# ---------------------------------------------------------------------------
class TestIsGoogleInternal(unittest.TestCase):

    def test_accounts(self):
        self.assertTrue(_is_google_internal("https://accounts.google.com/login"))

    def test_support(self):
        self.assertTrue(_is_google_internal("https://support.google.com/answer/1234"))

    def test_external(self):
        self.assertFalse(_is_google_internal("https://example.com"))

    def test_google_subdomain(self):
        self.assertTrue(_is_google_internal("https://maps.google.com/maps?q=london"))


# ---------------------------------------------------------------------------
# Deduplication via SearchResult fingerprinting
# ---------------------------------------------------------------------------
class TestDeduplication(unittest.TestCase):

    def _make(self, rank, title, url, snippet=""):
        r = SearchResult(rank=rank, title=title, url=url, snippet=snippet)
        return r

    def test_same_url_fingerprint(self):
        r1 = self._make(1, "A", "https://example.com/page?utm_source=google")
        r2 = self._make(2, "A", "https://example.com/page")
        self.assertEqual(r1._url_fingerprint, r2._url_fingerprint)

    def test_different_urls(self):
        r1 = self._make(1, "A", "https://example.com/page1")
        r2 = self._make(2, "A", "https://example.com/page2")
        self.assertNotEqual(r1._url_fingerprint, r2._url_fingerprint)

    def test_content_fingerprint_same_content(self):
        r1 = self._make(1, "Hello world", "https://a.com", snippet="Some text here")
        r2 = self._make(2, "Hello world", "https://b.com", snippet="Some text here")
        self.assertEqual(r1._content_fingerprint, r2._content_fingerprint)

    def test_content_fingerprint_different_content(self):
        r1 = self._make(1, "Title A", "https://a.com", snippet="Snippet A")
        r2 = self._make(2, "Title B", "https://b.com", snippet="Snippet B")
        self.assertNotEqual(r1._content_fingerprint, r2._content_fingerprint)


# ---------------------------------------------------------------------------
# Relevancy scoring
# ---------------------------------------------------------------------------
class TestComputeScore(unittest.TestCase):

    def _make(self, rank, title="", snippet=""):
        r = SearchResult(rank=rank, title=title, url="https://x.com", snippet=snippet)
        return r

    def test_higher_rank_gets_lower_score_without_keywords(self):
        r1 = self._make(1, "neutral", "neutral")
        r2 = self._make(10, "neutral", "neutral")
        r1.score = _compute_score(r1, [])
        r2.score = _compute_score(r2, [])
        self.assertGreater(r1.score, r2.score)

    def test_keyword_match_boosts_score(self):
        terms = ["python", "security"]
        r_match = self._make(5, "Python security guide", "All about python security tools")
        r_none = self._make(5, "Generic page title here", "Nothing relevant in this text")
        r_match.score = _compute_score(r_match, terms)
        r_none.score = _compute_score(r_none, terms)
        self.assertGreater(r_match.score, r_none.score)

    def test_title_keyword_weighted_more_than_snippet(self):
        terms = ["python"]
        r_title = self._make(3, "Python tutorial", "Learn something here")
        r_snippet = self._make(3, "Generic title page", "Python programming language tutorial content")
        r_title.score = _compute_score(r_title, terms)
        r_snippet.score = _compute_score(r_snippet, terms)
        self.assertGreater(r_title.score, r_snippet.score)

    def test_score_range(self):
        # Score should be a finite non-negative float
        r = self._make(1, "hello", "world")
        r.score = _compute_score(r, ["hello", "world"])
        self.assertGreater(r.score, 0)
        self.assertTrue(math.isfinite(r.score))

    def test_no_query_terms(self):
        r = self._make(1, "something", "text")
        r.score = _compute_score(r, [])
        self.assertGreater(r.score, 0)   # rank-decay component still fires


# ---------------------------------------------------------------------------
# CAPTCHA detection
# ---------------------------------------------------------------------------
class TestCaptchaDetection(unittest.TestCase):

    def _mock_response(self, status_code: int, text: str):
        mock = MagicMock()
        mock.status_code = status_code
        mock.text = text
        return mock

    def test_429_is_blocked(self):
        r = self._mock_response(429, "")
        self.assertTrue(StealthSession._is_blocked(r))

    def test_503_is_blocked(self):
        r = self._mock_response(503, "")
        self.assertTrue(StealthSession._is_blocked(r))

    def test_captcha_text_detected(self):
        r = self._mock_response(200, "Our systems have detected unusual traffic from your network.")
        self.assertTrue(StealthSession._is_blocked(r))

    def test_normal_200_not_blocked(self):
        r = self._mock_response(200, "<html><body><div class='g'><h3>Result</h3></div></body></html>")
        self.assertFalse(StealthSession._is_blocked(r))


# ---------------------------------------------------------------------------
# HTML parsing strategies
# ---------------------------------------------------------------------------
SAMPLE_SERP_HTML = """
<html><body>
  <div class="g">
    <a href="/url?q=https://example.com/page1&sa=U">
      <h3>Example Page One</h3>
    </a>
    <div class="VwiC3b">Snippet text for page one about python security.</div>
  </div>
  <div class="g">
    <a href="https://example.org/article">
      <h3>Example Org Article</h3>
    </a>
    <div class="VwiC3b">Another snippet about cybersecurity tools.</div>
  </div>
</body></html>
"""


class TestHtmlParsing(unittest.TestCase):

    def setUp(self):
        # Build a scraper with a no-op session (no real HTTP)
        mock_session = MagicMock(spec=StealthSession)
        self._scraper = GoogleScraper(session=mock_session)

    def test_parses_results(self):
        results = self._scraper._parse_page(SAMPLE_SERP_HTML, start=0)
        self.assertGreaterEqual(len(results), 1)

    def test_result_fields_populated(self):
        results = self._scraper._parse_page(SAMPLE_SERP_HTML, start=0)
        for r in results:
            self.assertTrue(r.url.startswith("http"), msg=f"Bad URL: {r.url!r}")
            self.assertGreater(len(r.title), 0, msg="Title is empty")

    def test_ranks_are_sequential_from_start(self):
        results = self._scraper._parse_page(SAMPLE_SERP_HTML, start=0)
        for idx, r in enumerate(results, start=1):
            self.assertEqual(r.rank, idx)

    def test_offset_start(self):
        results = self._scraper._parse_page(SAMPLE_SERP_HTML, start=10)
        if results:
            self.assertEqual(results[0].rank, 11)


# ---------------------------------------------------------------------------
# Query param builder
# ---------------------------------------------------------------------------
class TestBuildParams(unittest.TestCase):

    def test_includes_required_keys(self):
        params = GoogleScraper._build_params("test query", 0)
        self.assertIn("q", params)
        self.assertEqual(params["q"], "test query")
        self.assertIn("num", params)
        self.assertIn("start", params)
        self.assertEqual(params["start"], "0")

    def test_page_2_offset(self):
        params = GoogleScraper._build_params("test", 10)
        self.assertEqual(params["start"], "10")


# ---------------------------------------------------------------------------
# Backoff delay helper
# ---------------------------------------------------------------------------
class TestBackoffDelay(unittest.TestCase):

    def test_attempt_1_within_range(self):
        for _ in range(20):
            d = StealthSession._backoff_delay(1)
            self.assertGreaterEqual(d, 2.0)
            self.assertLessEqual(d, BACKOFF_MAX)

    def test_higher_attempt_means_longer_wait(self):
        # With enough samples, mean of attempt-3 > mean of attempt-1
        mean1 = sum(StealthSession._backoff_delay(1) for _ in range(50)) / 50
        mean3 = sum(StealthSession._backoff_delay(3) for _ in range(50)) / 50
        self.assertGreater(mean3, mean1)

    def test_never_exceeds_backoff_max(self):
        from tools.google_search_tool import BACKOFF_MAX
        for attempt in range(1, 10):
            for _ in range(10):
                self.assertLessEqual(StealthSession._backoff_delay(attempt), BACKOFF_MAX)


# ---------------------------------------------------------------------------
# CancellableSession (subclass) delay
# ---------------------------------------------------------------------------
class TestCancellableSession(unittest.TestCase):

    def test_delay_raises_when_cancelled(self):
        """_human_delay must raise InterruptedError if a cancellation flag is set."""

        class _FakeApp:
            _cancelled = True

        cancelled_flag = _FakeApp()

        class _CancellableSession(StealthSession):
            def _human_delay(self, extra: float = 0.0) -> None:
                if cancelled_flag._cancelled:
                    raise InterruptedError("cancelled")
                super()._human_delay(extra)

        sess = _CancellableSession.__new__(_CancellableSession)
        with self.assertRaises(InterruptedError):
            sess._human_delay()

    def test_delay_proceeds_when_not_cancelled(self):
        class _FakeApp:
            _cancelled = False

        cancelled_flag = _FakeApp()
        call_count = []

        class _CancellableSession(StealthSession):
            def _human_delay(self, extra: float = 0.0) -> None:
                if cancelled_flag._cancelled:
                    raise InterruptedError("cancelled")
                call_count.append(1)

        sess = _CancellableSession.__new__(_CancellableSession)
        sess._human_delay()
        self.assertEqual(len(call_count), 1)


if __name__ == "__main__":
    unittest.main()
