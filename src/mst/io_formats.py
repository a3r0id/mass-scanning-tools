"""Parse and write scan I/O formats (zmap JSON/list, JSONL, plain IPs)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


def load_ips(path: Path | str) -> list[str]:
    """Load IPs from a zmap JSON output, NDJSON, or plain one-IP-per-line file."""
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    ips: list[str] = []
    for line in lines:
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get("saddr") or obj.get("ip") or obj.get("host")
            if ip:
                ips.append(str(ip))
            continue
        # Plain IP / host line (ignore comments)
        if line.startswith("#"):
            continue
        ips.append(line.split()[0])

    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def write_lines(path: Path | str, lines: Iterable[str]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_jsonl(path: Path | str, records: Iterable[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_json(path: Path | str, data: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
