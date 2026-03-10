"""
FIR OSINT Research Assistant
=============================
A multi-engine OSINT research assistant that performs deep, intelligent web
searches while mimicking human browsing behavior.

Engines: Google, Bing, DuckDuckGo, Yandex, Baidu
"""

from .models import SearchResult
from .dispatcher import Dispatcher

__all__ = ["SearchResult", "Dispatcher"]
__version__ = "1.0.0"
