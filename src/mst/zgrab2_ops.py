"""ZGrab2 detection, guided install, invocation, and result parsing."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from rich.console import Console
from rich.prompt import Confirm

from mst.probe import compile_patterns, match_banner

# Official protocol modules from https://github.com/zmap/zgrab2 (plus default ports).
# Port None means the caller must supply -p / --port.
ZGRAB2_MODULES: dict[str, int | None] = {
    "amqp": 5672,
    "amqp091": 5672,
    "bacnet": 47808,
    "banner": None,
    "checkpoint": 264,
    "codesys2": 1200,
    "dnp3": 20000,
    "drda": 50000,
    "enip": 44818,
    "fox": 1911,
    "ftp": 21,
    "http": 80,
    "imap": 143,
    "ipp": 631,
    "jarm": 443,
    "managesieve": 4190,
    "memcached": 11211,
    "modbus": 502,
    "mongodb": 27017,
    "mqtt": 1883,
    "mssql": 1433,
    "mysql": 3306,
    "ntp": 123,
    "omronfins": 9600,
    "oracle": 1521,
    "pop3": 110,
    "postgres": 5432,
    "pptp": 1723,
    "rdp": 3389,
    "redis": 6379,
    "siemens": 102,
    "smb": 445,
    "smtp": 25,
    "socks5": 1080,
    "ssh": 22,
    "telnet": 23,
    "tls": 443,
}

GO_TARBALL_VERSION = "1.23.6"


@dataclass
class InstallPlan:
    platform_name: str
    commands: list[list[str]]
    notes: str = ""
    env: dict[str, str] | None = None


def find_zgrab2() -> str | None:
    path = shutil.which("zgrab2")
    if path:
        return path
    # Common go-install locations
    home = Path.home()
    for candidate in (
        home / "go" / "bin" / "zgrab2",
        Path("/usr/local/go/bin/zgrab2"),
        Path("/go/bin/zgrab2"),
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    gopath = os.environ.get("GOPATH")
    if gopath:
        cand = Path(gopath) / "bin" / "zgrab2"
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def find_go() -> str | None:
    path = shutil.which("go")
    if path:
        return path
    for candidate in (Path("/usr/local/go/bin/go"), Path.home() / "go" / "bin" / "go"):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def known_modules() -> list[str]:
    return sorted(ZGRAB2_MODULES)


def default_port(module: str) -> int | None:
    return ZGRAB2_MODULES.get(module.lower())


def discover_modules(zgrab2: str | None = None) -> list[str]:
    """Ask the installed binary which modules it knows; fall back to the static list."""
    zgrab2 = zgrab2 or find_zgrab2()
    if not zgrab2:
        return known_modules()
    try:
        proc = subprocess.run(
            [zgrab2, "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return known_modules()
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    # Help lists Available commands / modules as indented names
    found: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^\s{2,}([a-z][a-z0-9-]*)\s{2,}", line)
        if not m:
            continue
        name = m.group(1)
        if name in {"help", "completion", "multiple"}:
            continue
        if name in ZGRAB2_MODULES or name.replace("-", "") in {
            k.replace("-", "") for k in ZGRAB2_MODULES
        }:
            found.add(name)
        # Also accept any lowercase protocol-looking command listed near Known modules
        elif re.fullmatch(r"[a-z][a-z0-9]{1,20}", name) and name not in {
            "version",
            "flags",
            "command",
        }:
            # Only keep if it appears as a Available command entry with a description
            if "  " in line.strip()[len(name) :]:
                found.add(name)
    return sorted(found) if found else known_modules()


def validate_module(module: str, *, zgrab2: str | None = None) -> str:
    name = module.lower().strip()
    available = set(discover_modules(zgrab2)) | set(ZGRAB2_MODULES)
    # alias postgres <-> postgresql if either exists
    aliases = {"postgresql": "postgres", "postgres": "postgres"}
    name = aliases.get(name, name)
    if name == "multiple":
        return name
    if name not in available:
        sample = ", ".join(sorted(available)[:12])
        raise ValueError(
            f"Unknown zgrab2 module {module!r}. Known modules include: {sample}, ..."
        )
    return name


def _go_install_commands() -> list[list[str]]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    if system != "linux" or not arch:
        return []
    tarball = f"go{GO_TARBALL_VERSION}.linux-{arch}.tar.gz"
    url = f"https://go.dev/dl/{tarball}"
    return [
        ["sudo", "rm", "-rf", "/usr/local/go"],
        [
            "bash",
            "-lc",
            f"curl -fsSL {url} -o /tmp/{tarball} && "
            f"sudo tar -C /usr/local -xzf /tmp/{tarball} && rm -f /tmp/{tarball}",
        ],
    ]


def detect_install_plan() -> InstallPlan:
    system = platform.system().lower()
    if system == "windows":
        return InstallPlan(
            platform_name="Windows",
            commands=[],
            notes=(
                "ZGrab2 is not supported natively on Windows. "
                "Install WSL2, then run `mst doctor` and install zgrab2 there."
            ),
        )

    go = find_go()
    commands: list[list[str]] = []
    notes_parts: list[str] = []

    if not go:
        go_cmds = _go_install_commands()
        if go_cmds:
            commands.extend(go_cmds)
            notes_parts.append(
                f"Installs Go {GO_TARBALL_VERSION} to /usr/local/go (required to build zgrab2)."
            )
        elif system == "darwin":
            if shutil.which("brew"):
                commands.append(["brew", "install", "go"])
            else:
                return InstallPlan(
                    platform_name="macOS",
                    commands=[],
                    notes="Install Homebrew + Go (https://go.dev/dl), then re-run `mst doctor`.",
                )
        else:
            return InstallPlan(
                platform_name=f"Linux ({platform.platform()})",
                commands=[],
                notes="Install Go 1.23+ from https://go.dev/dl, then re-run `mst doctor`.",
            )

    # Prefer upstream make install from a shallow clone for full module set
    build = (
        "export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH; "
        "tmpdir=$(mktemp -d); "
        "git clone --depth 1 https://github.com/zmap/zgrab2.git \"$tmpdir/zgrab2\" && "
        "make -C \"$tmpdir/zgrab2\" && make -C \"$tmpdir/zgrab2\" install && "
        "rm -rf \"$tmpdir\""
    )
    commands.append(["bash", "-lc", build])
    notes_parts.append(
        "Builds zgrab2 from https://github.com/zmap/zgrab2 and installs to $GOPATH/bin "
        "(usually ~/go/bin). Ensure that directory is on your PATH."
    )

    return InstallPlan(
        platform_name=platform.system(),
        commands=commands,
        notes=" ".join(notes_parts),
        env={"PATH": f"/usr/local/go/bin:{Path.home() / 'go' / 'bin'}:{os.environ.get('PATH', '')}"},
    )


def offer_install_zgrab2(console: Console | None = None, *, assume_yes: bool = False) -> bool:
    """Prompt and attempt to install zgrab2. Returns True if available afterward."""
    console = console or Console()
    if find_zgrab2():
        console.print(f"[green]zgrab2 found:[/green] {find_zgrab2()}")
        return True

    plan = detect_install_plan()
    console.print(f"[yellow]zgrab2 not found on PATH.[/yellow] Detected: {plan.platform_name}")
    if plan.notes:
        console.print(f"[dim]{plan.notes}[/dim]")
    if not plan.commands:
        return False

    console.print("Install commands:")
    for cmd in plan.commands:
        console.print(f"  [cyan]{' '.join(cmd)}[/cyan]")

    if not assume_yes:
        if not Confirm.ask("Run these install commands now?", default=True):
            console.print("[yellow]Skipped zgrab2 install.[/yellow]")
            return False

    env = os.environ.copy()
    if plan.env:
        env.update(plan.env)

    for cmd in plan.commands:
        console.print(f"[bold]$ {' '.join(cmd)}[/bold]")
        try:
            result = subprocess.run(cmd, check=False, env=env)
        except OSError as exc:
            console.print(f"[red]Failed to run {' '.join(cmd)}: {exc}[/red]")
            return False
        if result.returncode != 0:
            console.print(f"[red]Command failed with exit {result.returncode}[/red]")
            return False

    # Refresh PATH for this process so find_zgrab2 can see ~/go/bin
    go_bin = str(Path.home() / "go" / "bin")
    local_go = "/usr/local/go/bin"
    os.environ["PATH"] = f"{local_go}:{go_bin}:{os.environ.get('PATH', '')}"

    path = find_zgrab2()
    if path:
        console.print(f"[green]zgrab2 installed:[/green] {path}")
        return True
    console.print(
        "[yellow]Install finished but zgrab2 still not on PATH. "
        "Add ~/go/bin (and /usr/local/go/bin) to PATH, then re-run.[/yellow]"
    )
    return False


def ensure_zgrab2(console: Console | None = None, *, assume_yes: bool = False) -> str:
    console = console or Console()
    path = find_zgrab2()
    if path:
        return path
    if offer_install_zgrab2(console, assume_yes=assume_yes):
        path = find_zgrab2()
        if path:
            return path
    raise RuntimeError(
        "zgrab2 is required but not available. Install from "
        "https://github.com/zmap/zgrab2 then re-run."
    )


def write_targets_file(ips: Iterable[str], path: Path | str | None = None) -> Path:
    """Write zgrab2 input (one IP per line)."""
    lines = [ip.strip() for ip in ips if ip and str(ip).strip()]
    if path is None:
        fd, name = tempfile.mkstemp(prefix="mst-zgrab2-", suffix=".txt")
        os.close(fd)
        path = Path(name)
    else:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def run_zgrab2(
    module: str,
    targets: Path | str | Iterable[str],
    output: Path | str,
    *,
    port: int | None = None,
    senders: int = 50,
    timeout: int = 10,
    multiple_config: Path | str | None = None,
    extra_args: list[str] | None = None,
    console: Console | None = None,
    assume_yes: bool = False,
) -> Path:
    """
    Run zgrab2 against targets and write full JSONL transcripts to ``output``.

    Pass module-specific flags via ``extra_args`` (e.g. ``["--endpoint=/"]``).
    Use ``multiple_config`` to run ``zgrab2 multiple -c ...`` instead of a single module.
    """
    console = console or Console()
    zgrab2 = ensure_zgrab2(console, assume_yes=assume_yes)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    tmp_input: Path | None = None

    def _resolve_input() -> Path | None:
        nonlocal tmp_input
        if isinstance(targets, (str, Path)):
            input_path = Path(targets)
            if not input_path.is_file():
                raise FileNotFoundError(f"Targets file not found: {input_path}")
            return input_path
        targets_list = list(targets)
        if not targets_list:
            return None
        tmp_input = write_targets_file(targets_list)
        return tmp_input

    # zgrab2 flags: -f input-file, -o output-file, -s senders, -p port,
    # -t target-timeout (duration), --connect-timeout (duration)
    if multiple_config is not None:
        cfg = Path(multiple_config)
        if not cfg.is_file():
            raise FileNotFoundError(f"ZGrab2 multiple config not found: {cfg}")
        cmd = [
            zgrab2,
            "multiple",
            "-c",
            str(cfg),
            "-o",
            str(output),
            "-s",
            str(senders),
        ]
        input_path = _resolve_input()
        if input_path is not None:
            cmd.extend(["-f", str(input_path)])
        if extra_args:
            cmd.extend(extra_args)
    else:
        mod = validate_module(module, zgrab2=zgrab2)
        input_path = _resolve_input()
        if input_path is None:
            raise ValueError("No targets provided for zgrab2")
        resolved_port = port if port is not None else default_port(mod)
        if resolved_port is None:
            raise ValueError(
                f"Module {mod!r} has no default port; pass --port / -p."
            )

        cmd = [
            zgrab2,
            mod,
            "-p",
            str(resolved_port),
            "-f",
            str(input_path),
            "-o",
            str(output),
            "-s",
            str(senders),
            "-t",
            f"{int(timeout)}s",
            "--connect-timeout",
            f"{int(timeout)}s",
        ]
        if extra_args:
            cmd.extend(extra_args)

    console.print(f"[bold]$ {' '.join(cmd)}[/bold]")
    try:
        result = subprocess.run(cmd, check=False)
    finally:
        if tmp_input is not None:
            try:
                tmp_input.unlink(missing_ok=True)
            except OSError:
                pass

    if result.returncode != 0:
        raise RuntimeError(f"zgrab2 exited with code {result.returncode}")
    if not output.exists():
        output.touch()
    return output


def iter_zgrab2_records(path: Path | str) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects from a zgrab2 JSONL output file."""
    path = Path(path)
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def record_statuses(record: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """
    Return ``(module_name, status, module_blob)`` for each protocol entry in a record.

    ZGrab2 shape: ``{"ip": "...", "data": {"http": {"status": "success", "result": {...}}}}``
    """
    data = record.get("data")
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str, dict[str, Any]]] = []
    for name, blob in data.items():
        if not isinstance(blob, dict):
            continue
        status = str(blob.get("status") or "")
        out.append((str(name), status, blob))
    return out


def is_success_record(record: dict[str, Any]) -> bool:
    return any(status == "success" for _, status, _ in record_statuses(record))


def record_to_search_text(record: dict[str, Any]) -> str:
    """Flatten a zgrab2 record to text for optional hit-word / regex filtering."""
    return json.dumps(record, ensure_ascii=False)


def filter_zgrab2_records(
    records: Iterable[dict[str, Any]],
    *,
    success_only: bool = True,
    hit_words: list[str] | None = None,
    hit_regexes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Filter zgrab2 JSON records.

    By default keeps protocol successes. Optional hit-words/regexes match against the
    full JSON transcript so every data point ZGrab2 emits remains searchable.
    """
    patterns = None
    if hit_words or hit_regexes:
        patterns = compile_patterns(hit_words=hit_words, hit_regexes=hit_regexes)

    kept: list[dict[str, Any]] = []
    for rec in records:
        if success_only and not is_success_record(rec):
            continue
        if patterns is not None:
            if not match_banner(record_to_search_text(rec), patterns):
                continue
        kept.append(rec)
    return kept


def extract_ips(records: Iterable[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for rec in records:
        ip = rec.get("ip") or rec.get("domain")
        if not ip:
            continue
        ip_s = str(ip)
        if ip_s not in seen:
            seen.add(ip_s)
            out.append(ip_s)
    return out


def summarize_modules(records: Iterable[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Count success/error/other per module name across records."""
    stats: dict[str, dict[str, int]] = {}
    for rec in records:
        for name, status, _ in record_statuses(rec):
            bucket = stats.setdefault(name, {"success": 0, "error": 0, "other": 0})
            if status == "success":
                bucket["success"] += 1
            elif status in {"error", "io-timeout", "connection-timeout", "protocol-error"}:
                bucket["error"] += 1
            else:
                bucket["other"] += 1
    return stats
