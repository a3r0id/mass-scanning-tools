"""ASN → CIDR resolution via RADB whois."""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from typing import Iterable

CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:3[0-2]|[12]?\d)\b"
)

RADB_HOST = "whois.radb.net"
RADB_PORT = 43


def normalize_asn(asn: str) -> str:
    asn = asn.strip().upper()
    if not asn.startswith("AS"):
        asn = f"AS{asn}"
    if not re.fullmatch(r"AS\d+", asn):
        raise ValueError(f"Invalid ASN: {asn!r} (expected AS12345 or 12345)")
    return asn


def _query_whois_binary(asn: str) -> str:
    cmd = ["whois", "-h", RADB_HOST, "--", f"-i origin {asn}"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0 and not result.stdout:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"whois failed for {asn}: {err or 'unknown error'}")
    return result.stdout


def _query_whois_socket(asn: str) -> str:
    query = f"-i origin {asn}\r\n"
    with socket.create_connection((RADB_HOST, RADB_PORT), timeout=30) as sock:
        sock.sendall(query.encode("ascii"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def query_radb(asn: str) -> str:
    """Return raw RADB whois response for an ASN."""
    asn = normalize_asn(asn)
    if shutil.which("whois"):
        try:
            return _query_whois_binary(asn)
        except (OSError, subprocess.TimeoutExpired, RuntimeError):
            pass
    return _query_whois_socket(asn)


def extract_cidrs(whois_text: str) -> list[str]:
    found = CIDR_RE.findall(whois_text)
    # Deduplicate, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in found:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def asn_to_cidrs(asn: str) -> list[str]:
    text = query_radb(asn)
    if re.search(r"\bnot\b", text, re.IGNORECASE) and "route:" not in text.lower():
        # Keep going — RADB sometimes includes "not" in unrelated text
        pass
    cidrs = extract_cidrs(text)
    if not cidrs:
        raise RuntimeError(f"No IPv4 CIDRs found for {normalize_asn(asn)}")
    return cidrs


def write_cidrs(path: str, cidrs: Iterable[str]) -> None:
    from mst.io_formats import write_lines

    write_lines(path, cidrs)
