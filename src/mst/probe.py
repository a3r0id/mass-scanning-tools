"""Banner matching helpers used to optionally filter ZGrab2 JSON transcripts.

Application-layer grabbing itself is performed by ZGrab2 via ``mst.zgrab2_ops``.
"""

from __future__ import annotations

import codecs
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Literal, Pattern

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn

ProbeMode = Literal["raw", "telnet"]
PatternKind = Literal["word", "regex"]

# Telnet IAC negotiation (stdlib telnetlib removed in Python 3.13+)
IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251


@dataclass
class ProbeHit:
    ip: str
    port: int
    mode: str
    banner: str
    matched: list[str]


@dataclass(frozen=True)
class CompiledPattern:
    """A compiled banner matcher (literal substring or regex)."""

    label: str
    kind: PatternKind
    needle: str | None = None
    regex: Pattern[str] | None = None


def decode_hit_word(word: str) -> str:
    """Decode hit words; supports escape sequences like ``\\x1b``."""
    try:
        return codecs.decode(word, "unicode_escape")
    except Exception:
        return word


def normalize_hit_words(words: list[str]) -> list[str]:
    return [decode_hit_word(w).lower() for w in words if w]


def compile_patterns(
    hit_words: list[str] | None = None,
    hit_regexes: list[str] | None = None,
) -> list[CompiledPattern]:
    """Build matchers from literal hit-words and/or regex patterns."""
    patterns: list[CompiledPattern] = []
    for word in hit_words or []:
        if not word:
            continue
        needle = decode_hit_word(word).lower()
        if needle:
            patterns.append(CompiledPattern(label=word, kind="word", needle=needle))

    for expr in hit_regexes or []:
        if not expr:
            continue
        try:
            regex = re.compile(expr, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            raise ValueError(f"Invalid hit-regex {expr!r}: {exc}") from exc
        patterns.append(CompiledPattern(label=expr, kind="regex", regex=regex))

    if not patterns:
        raise ValueError("At least one --hit-words or --hit-regex pattern is required")
    return patterns


def match_banner(
    banner: str,
    patterns: list[CompiledPattern] | list[str],
) -> list[str]:
    """Return labels of patterns that match ``banner``.

    Accepts compiled patterns, or a legacy list of lowercase literal strings.
    """
    if patterns and isinstance(patterns[0], str):
        # Back-compat for callers/tests passing plain hit-word strings
        lowered = banner.lower()
        return [w for w in patterns if w and w in lowered]  # type: ignore[misc]

    matched: list[str] = []
    lowered = banner.lower()
    for pat in patterns:  # type: ignore[assignment]
        assert isinstance(pat, CompiledPattern)
        if pat.kind == "word":
            if pat.needle and pat.needle in lowered:
                matched.append(pat.label)
        elif pat.regex is not None and pat.regex.search(banner):
            matched.append(pat.label)
    return matched


def _recv_banner_raw(ip: str, port: int, timeout: float) -> str:
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        chunks: list[bytes] = []
        # A couple of short reads — many banners arrive immediately
        for _ in range(2):
            try:
                data = sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                break
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) >= 1024:
                break
        return repr(b"".join(chunks))[2:-1]


def _strip_telnet_iac(data: bytes, sock: socket.socket) -> bytes:
    """Strip IAC sequences; reply WONT/DONT to WILL/DO offers."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                opt = data[i + 2]
                if cmd == DO:
                    sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == WILL:
                    sock.sendall(bytes([IAC, DONT, opt]))
                i += 3
                continue
            i += 2
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def _recv_banner_telnet(ip: str, port: int, timeout: float) -> str:
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        chunks: list[bytes] = []
        for _ in range(3):
            try:
                data = sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                break
            if not data:
                break
            chunks.append(_strip_telnet_iac(data, sock))
            joined = b"".join(chunks)
            if b"\n" in joined or len(joined) >= 1024:
                break
        return repr(b"".join(chunks))[2:-1]


def probe_one(
    ip: str,
    port: int,
    mode: ProbeMode,
    timeout: float,
    patterns: list[CompiledPattern],
) -> ProbeHit | None:
    try:
        if mode == "telnet":
            banner = _recv_banner_telnet(ip, port, timeout)
        else:
            banner = _recv_banner_raw(ip, port, timeout)
    except (OSError, EOFError, socket.timeout, TimeoutError):
        return None

    matched = match_banner(banner, patterns)
    if not matched:
        return None
    return ProbeHit(ip=ip, port=port, mode=mode, banner=banner, matched=matched)


def load_config(path: Path | str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def run_probe(
    ips: list[str],
    port: int,
    mode: ProbeMode = "raw",
    timeout: float = 1.0,
    hit_words: list[str] | None = None,
    hit_regexes: list[str] | None = None,
    workers: int = 100,
    console: Console | None = None,
    on_hit: Callable[[ProbeHit], None] | None = None,
) -> list[ProbeHit]:
    console = console or Console()
    patterns = compile_patterns(hit_words=hit_words, hit_regexes=hit_regexes)
    if workers < 1:
        raise ValueError("workers must be >= 1")

    hits: list[ProbeHit] = []
    total = len(ips)
    if total == 0:
        console.print("[yellow]No IPs to probe.[/yellow]")
        return hits

    workers = min(workers, total)

    with Progress(
        TextColumn("[bold blue]probe"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("* {task.fields[hits]} hits"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("probing", total=total, hits=0)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(probe_one, ip, port, mode, timeout, patterns): ip
                for ip in ips
            }
            for fut in as_completed(futures):
                result = fut.result()
                progress.advance(task)
                if result is not None:
                    hits.append(result)
                    progress.update(task, hits=len(hits))
                    if on_hit:
                        on_hit(result)
                    else:
                        console.print(
                            f"[green]HIT[/green] {result.ip}:{result.port} "
                            f"matched={result.matched}"
                        )

    return hits


def hits_to_records(hits: list[ProbeHit]) -> list[dict]:
    return [asdict(h) for h in hits]
