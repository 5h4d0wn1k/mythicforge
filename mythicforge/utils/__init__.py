"""Utility functions for mythicforge."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def format_tokens(count: int) -> str:
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    elif count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


def format_cost(usd: float) -> str:
    if usd < 0.01:
        return f"${usd:.6f}"
    elif usd < 1.0:
        return f"${usd:.4f}"
    return f"${usd:.2f}"


def format_duration(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.0f}ms"
    elif ms < 60000:
        return f"{ms / 1000:.1f}s"
    return f"{ms / 60000:.1f}min"


def ensure_dir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_json(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def save_json(data: Any, path: str, indent: int = 2):
    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        json.dump(data, f, indent=indent, default=str)


def get_timestamp() -> str:
    return datetime.now().isoformat()


def safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


class Timer:
    def __init__(self):
        self._start = time.time()
        self._laps: List[float] = []

    def lap(self) -> float:
        now = time.time()
        lap_time = now - (self._laps[-1] if self._laps else self._start)
        self._laps.append(now)
        return lap_time

    def elapsed(self) -> float:
        return time.time() - self._start

    def reset(self):
        self._start = time.time()
        self._laps = []
