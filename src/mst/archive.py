"""Timestamped run archive helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path


def re_safe(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", label.strip())
    return cleaned[:64] or "scan"


def make_run_dir(
    base: Path | str = "runs",
    label: str | None = None,
) -> Path:
    """Create and return ``runs/<timestamp>_<label>/``."""
    base = Path(base)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re_safe(label) if label else "scan"
    run_dir = base / f"{stamp}_{safe}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir
