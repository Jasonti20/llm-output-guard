from __future__ import annotations
from typing import Any, Callable, Awaitable, Dict, Optional
import codecs

from starlette.types import ASGIApp, Scope, Receive, Send, Message

from llm_output_guard.core.adapter import apply_text

TEXT_CT_PREFIXES = ("text/", "text/event-stream")
JSON_CT = "application/json"
ROLLING_BYTES = 8 * 1024  # 8 KB window to catch cross-chunk patterns
