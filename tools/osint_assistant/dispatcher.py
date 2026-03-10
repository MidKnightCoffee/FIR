"""
dispatcher.py — Central orchestrator for parallel multi-engine OSINT searches.

The Dispatcher:
  1. Builds 20+ query variations per engine via QueryBuilder
  2. Runs all engines in parallel using a thread pool
  3. Collects, deduplicates, and scores results across engines
  4. Returns a clean, ranked, structured list of SearchResult objects
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Type

from .deduplicator import deduplicate
from .engines import ALL_ENGINES
from .engines.base import BaseEngine
from .models import SearchResult
from .query_builder import QueryBuilder
from .session import HumanSession

logger = logging.getLogger(__name__)

# Default engines to use (all five supported engines)
DEFAULT_ENGINES = list(ALL_ENGINES.keys())  # google, bing, ddg, yandex, baidu


class Dispatcher:
    """
    Orchestrates parallel searches across multiple engines.

    Parameters
    ----------
    engines:
        List of engine names to use. Defaults to all five supported engines.
        Valid values: ``"google"``, ``"bing"``, ``"ddg"``, ``"yandex"``,
        ``"baidu"``.
    max_workers:
        Maximum number of concurrent threads (one per engine).
    max_variations:
        Maximum number of query variations to run per engine.
    results_per_variation:
        Maximum results to collect per query variation.
    proxies:
        Optional proxy list (``http://host:port``).
    log_cb:
        Optional callback ``(message: str) -> None`` called from worker threads.
    progress_cb:
        Optional callback ``(collected: int, total_target: int) -> None``.
    """

    def __init__(
        self,
        engines: Optional[List[str]] = None,
        max_workers: int = 5,
        max_variations: int = 20,
        results_per_variation: int = 10,
        proxies: Optional[List[str]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self._engine_names: List[str] = engines or DEFAULT_ENGINES
        self._max_workers = max_workers
        self._max_variations = max_variations
        self._results_per_variation = results_per_variation
        self._proxies = proxies
        self._log_cb = log_cb or (lambda msg: None)
        self._progress_cb = progress_cb or (lambda c, t: None)
        self._cancelled: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def search(self, query: str, target_results: int = 200) -> List[SearchResult]:
        """
        Run OSINT search across all configured engines in parallel.

        Parameters
        ----------
        query:
            The raw user query.
        target_results:
            Approximate target number of unique results to collect
            (after deduplication).

        Returns
        -------
        List[SearchResult]
            Deduplicated, scored, and ranked results sorted by relevancy.
        """
        self._cancelled = False
        self._log(f"Starting multi-engine search for: {query!r}")
        self._log(
            f"Engines: {', '.join(self._engine_names)} | "
            f"Max variations: {self._max_variations} | "
            f"Target: {target_results} results"
        )

        # Build query variations for each engine
        variations_by_engine: Dict[str, List[str]] = {}
        for engine_name in self._engine_names:
            builder = QueryBuilder(engine_name)
            variations = builder.build(query, max_variations=self._max_variations)
            variations_by_engine[engine_name] = variations
            self._log(
                f"[{engine_name}] {len(variations)} query variations generated."
            )

        # Create a single shared session (realistic: one browser, many tabs)
        session = self._make_session()

        all_results: List[SearchResult] = []

        try:
            # Run each engine in its own thread
            futures = {}
            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                for engine_name in self._engine_names:
                    if self._cancelled:
                        break
                    engine_cls: Type[BaseEngine] = ALL_ENGINES[engine_name]
                    engine_session = self._make_session()  # per-engine session
                    engine = engine_cls(session=engine_session, log_cb=self._log_cb)
                    variations = variations_by_engine[engine_name]
                    fut = pool.submit(
                        self._run_engine,
                        engine,
                        engine_session,
                        variations,
                        self._results_per_variation,
                    )
                    futures[fut] = engine_name

                for fut in as_completed(futures):
                    engine_name = futures[fut]
                    try:
                        engine_results = fut.result()
                        all_results.extend(engine_results)
                        self._log(
                            f"[{engine_name}] Collected {len(engine_results)} "
                            f"raw results. Total so far: {len(all_results)}."
                        )
                        self._progress_cb(len(all_results), target_results)
                    except InterruptedError:
                        self._log(f"[{engine_name}] Cancelled.")
                    except Exception as exc:
                        self._log(f"[{engine_name}] Error: {exc}")
        finally:
            session.close()

        self._log(
            f"Raw results collected: {len(all_results)}. "
            "Deduplicating and scoring …"
        )
        unique = deduplicate(all_results, query=query)
        self._log(
            f"✅ Done — {len(unique)} unique results after deduplication."
        )
        self._progress_cb(len(unique), target_results)
        return unique

    def cancel(self) -> None:
        """Signal all running engine threads to stop at the next delay point."""
        self._cancelled = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _make_session(self) -> HumanSession:
        """Factory: creates a HumanSession, injecting a cancellation check."""
        dispatcher_ref = self

        class _CancellableSession(HumanSession):
            def _human_delay(self, extra: float = 0.0) -> None:
                if dispatcher_ref._cancelled:
                    raise InterruptedError("Search cancelled.")
                super()._human_delay(extra)

        return _CancellableSession(proxies=self._proxies)

    def _run_engine(
        self,
        engine: BaseEngine,
        session: HumanSession,
        variations: List[str],
        results_per_variation: int,
    ) -> List[SearchResult]:
        """
        Run *engine* over all *variations*, collecting results.
        Called inside a thread by the ThreadPoolExecutor.
        """
        collected: List[SearchResult] = []
        try:
            for i, variation in enumerate(variations):
                if self._cancelled:
                    break
                self._log(
                    f"[{engine.name}] Variation {i + 1}/{len(variations)}: "
                    f"{variation!r}"
                )
                try:
                    results = engine.search(variation, max_results=results_per_variation)
                    collected.extend(results)
                    self._log(
                        f"[{engine.name}] +{len(results)} results "
                        f"(total: {len(collected)})"
                    )
                except InterruptedError:
                    raise
                except Exception as exc:
                    self._log(f"[{engine.name}] Variation error: {exc}")
        finally:
            session.close()
        return collected

    def _log(self, msg: str) -> None:
        logger.info(msg)
        self._log_cb(msg)
