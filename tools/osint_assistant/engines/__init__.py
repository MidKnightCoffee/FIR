"""
engines/__init__.py — Engine registry for the OSINT Research Assistant.

Supported engines: Google, Bing, DuckDuckGo, Yandex, Baidu.
"""

from .google import GoogleEngine
from .bing import BingEngine
from .ddg import DuckDuckGoEngine
from .yandex import YandexEngine
from .baidu import BaiduEngine

ALL_ENGINES = {
    "google": GoogleEngine,
    "bing": BingEngine,
    "ddg": DuckDuckGoEngine,
    "yandex": YandexEngine,
    "baidu": BaiduEngine,
}

__all__ = [
    "GoogleEngine",
    "BingEngine",
    "DuckDuckGoEngine",
    "YandexEngine",
    "BaiduEngine",
    "ALL_ENGINES",
]
