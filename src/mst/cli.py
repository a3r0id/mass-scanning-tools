"""mst - mass scanning tools CLI."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Optional

import click
import typer
from rich.console import Console
from typer.core import TyperGroup

from mst import __version__
from mst.archive import make_run_dir
from mst.asn import asn_to_cidrs, normalize_asn, write_cidrs
from mst.doctor import run_doctor
from mst.io_formats import load_ips, write_json, write_jsonl, write_lines
from mst.probe import load_config
from mst.zgrab2_ops import (
    default_port,
    discover_modules,
    extract_ips,
    filter_zgrab2_records,
    iter_zgrab2_records,
    known_modules,
    run_zgrab2,
    summarize_modules,
    validate_module,
)
from mst.zmap_ops import run_zmap

console = Console()


@lru_cache(maxsize=1)
def _load_logo() -> str:
    try:
        return resources.files("mst").joinpath("assets", "logo.ascii").read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, OSError, TypeError, ModuleNotFoundError):
        fallback = Path(__file__).resolve().parent / "assets" / "logo.ascii"
        return fallback.read_text(encoding="utf-8")


def _print_logo() -> None:
    if os.getenv("HEADLESS", "").lower() in {"1", "true", "yes"}:
        return
    logo = _load_logo().rstrip()
    # markup/highlight off so Rich does not mangle backslashes in the art
    console.print(logo, markup=False, highlight=False, soft_wrap=False)
    console.print()


class BannerGroup(TyperGroup):
    """Prepend the ASCII logo to help output (bare `mst` / `--help`)."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        _print_logo()
        super().format_help(ctx, formatter)


app = typer.Typer(
    name="mst",
    help="Map services across entire ASNs, and gather insights from the data.",
    no_args_is_help=True,
    add_completion=False,
    cls=BannerGroup,
)


def _version_callback(value: bool) -> None:
    if value:
        _print_logo()
        console.print(f"mst {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Mass Scanning Tools."""
    _print_logo()


@app.command("doctor")
def doctor_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm install prompts."),
) -> None:
    """Check whois, zmap, zgrab2, and privileges; offer installs if missing."""
    code = run_doctor(console, assume_yes=yes)
    raise typer.Exit(code)


@app.command("asn")
def asn_cmd(
    asn: str = typer.Argument(..., help="ASN like AS36352 or 36352"),
    output: Path = typer.Option(Path("cidrs.txt"), "--output", "-o", help="CIDR list output"),
) -> None:
    """Resolve an ASN to IPv4 CIDR prefixes via RADB."""
    asn_n = normalize_asn(asn)
    console.print(f"[bold]Resolving {asn_n} via whois.radb.net...[/bold]")
    try:
        cidrs = asn_to_cidrs(asn_n)
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    write_cidrs(str(output), cidrs)
    console.print(f"[green]Wrote {len(cidrs)} CIDRs -> {output}[/green]")


@app.command("scan")
def scan_cmd(
    whitelist: Path = typer.Option(..., "--whitelist", "-w", help="CIDR whitelist file"),
    port: int = typer.Option(..., "--port", "-p", help="Target TCP port"),
    output: Path = typer.Option(Path("zmap.jsonl"), "--output", "-o", help="ZMap output file"),
    bandwidth: str = typer.Option("10M", "--bandwidth", "-b", help="ZMap bandwidth cap"),
    output_module: str = typer.Option("json", "--output-module", help="ZMap output module"),
    cooldown_time: Optional[int] = typer.Option(None, "--cooldown-time", help="ZMap cooldown seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface for ZMap"),
    gateway_mac: Optional[str] = typer.Option(
        None,
        "--gateway-mac",
        "-G",
        help="Gateway MAC (avoids ARP hang); implies Ethernet send path",
    ),
    vpn: Optional[bool] = typer.Option(
        None,
        "--vpn/--no-vpn",
        "-X",
        help="Send IP packets (recommended in Docker/WSL). Default: auto in containers.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm zmap install"),
) -> None:
    """Run ZMap against a CIDR whitelist (offers to install zmap if missing)."""
    try:
        path = run_zmap(
            whitelist=whitelist,
            port=port,
            output=output,
            bandwidth=bandwidth,
            output_module=output_module,
            cooldown_time=cooldown_time,
            interface=interface,
            gateway_mac_addr=gateway_mac,
            vpn=vpn,
            console=console,
            assume_yes=yes,
        )
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]ZMap output -> {path}[/green]")


def _parse_hit_words(raw: Optional[str], config_words: list[str] | None) -> list[str]:
    if raw:
        return [w.strip() for w in raw.split(",") if w.strip()]
    if config_words:
        return list(config_words)
    return []


def _parse_hit_regexes(
    cli_regexes: Optional[list[str]],
    config_regexes: list[str] | str | None,
) -> list[str]:
    if cli_regexes:
        return [r for r in cli_regexes if r]
    if not config_regexes:
        return []
    if isinstance(config_regexes, str):
        return [config_regexes] if config_regexes.strip() else []
    return [r for r in config_regexes if r]


@app.command("modules")
def modules_cmd(
    installed: bool = typer.Option(
        False,
        "--installed",
        help="Query the local zgrab2 binary for modules (falls back to built-in list)",
    ),
) -> None:
    """List ZGrab2 protocol modules and default ports."""
    mods = discover_modules() if installed else known_modules()
    for name in mods:
        port = default_port(name)
        port_s = str(port) if port is not None else "(requires -p)"
        console.print(f"{name:14} default-port={port_s}")
    console.print(f"[dim]{len(mods)} modules. Pass module-specific flags after --[/dim]")


@app.command(
    "probe",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def probe_cmd(
    ctx: typer.Context,
    input_file: Path = typer.Argument(..., help="ZMap JSON or plain IP list"),
    module: str = typer.Option(
        "banner",
        "--module",
        "-m",
        help="ZGrab2 module (see `mst modules`). Use with --zgrab-config for multiple.",
    ),
    port: Optional[int] = typer.Option(
        None,
        "--port",
        "-p",
        help="Port to grab (defaults to module well-known port; required for banner)",
    ),
    senders: int = typer.Option(50, "--senders", "-j", help="ZGrab2 sender goroutines"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Per-target timeout seconds"),
    output: Path = typer.Option(
        Path("zgrab2.jsonl"),
        "--output",
        "-o",
        help="Full ZGrab2 JSONL transcripts",
    ),
    ips_output: Optional[Path] = typer.Option(
        None, "--ips-output", help="Also write plain IP list of matching records"
    ),
    success_only: bool = typer.Option(
        True,
        "--success-only/--all-results",
        help="Keep only successful protocol handshakes (default) or every record",
    ),
    hit_words: Optional[str] = typer.Option(
        None,
        "--hit-words",
        help="Optional comma-separated substrings matched against full JSON transcripts",
    ),
    hit_regex: Optional[list[str]] = typer.Option(
        None,
        "--hit-regex",
        "-r",
        help="Optional regex matched against full JSON transcripts (repeatable)",
    ),
    zgrab_config: Optional[Path] = typer.Option(
        None,
        "--zgrab-config",
        help="ZGrab2 multiple-module .ini (implies module=multiple)",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", help="Optional legacy JSON config (port/timeout/hit filters)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm zgrab2 install"),
) -> None:
    """Run ZGrab2 application-layer grabs; preserve full protocol transcripts."""
    cfg: dict = {}
    if config:
        try:
            cfg = load_config(config)
        except (OSError, json.JSONDecodeError) as exc:
            console.print(f"[red]Failed to load config: {exc}[/red]")
            raise typer.Exit(1) from exc

    extra_args = list(ctx.args)
    words = _parse_hit_words(hit_words, cfg.get("hit_words"))
    regexes = _parse_hit_regexes(
        hit_regex,
        cfg.get("hit_regex") or cfg.get("hit_regexes"),
    )

    port_v = port if port is not None else cfg.get("port")
    timeout_v = int(cfg.get("timeout", timeout)) if config and "timeout" in cfg else timeout
    senders_v = (
        int(cfg.get("thread_count", senders))
        if config and "thread_count" in cfg
        else senders
    )

    module_v = (module or cfg.get("module") or "banner").lower()
    if zgrab_config is not None:
        module_v = "multiple"

    try:
        if module_v != "multiple":
            module_v = validate_module(module_v)
            if port_v is None:
                port_v = default_port(module_v)
            if port_v is None:
                console.print(
                    f"[red]Module {module_v!r} requires --port "
                    f"(no default well-known port).[/red]"
                )
                raise typer.Exit(1)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    try:
        ips = load_ips(input_file)
    except OSError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if not ips and zgrab_config is None:
        console.print("[yellow]No IPs to probe.[/yellow]")
        raise typer.Exit(0)

    label = (
        f"multiple:{zgrab_config}"
        if module_v == "multiple"
        else f"{module_v}:{port_v}"
    )
    console.print(
        f"[bold]ZGrab2 {label}[/bold] targets={len(ips)} senders={senders_v}"
    )
    if extra_args:
        console.print(f"[dim]passthrough:[/dim] {' '.join(extra_args)}")

    try:
        run_zgrab2(
            module=module_v,
            targets=ips if ips else input_file,
            output=output,
            port=int(port_v) if port_v is not None else None,
            senders=senders_v,
            timeout=timeout_v,
            multiple_config=zgrab_config,
            extra_args=extra_args or None,
            console=console,
            assume_yes=yes,
        )
    except (RuntimeError, FileNotFoundError, ValueError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    records = list(iter_zgrab2_records(output))
    filtered = filter_zgrab2_records(
        records,
        success_only=success_only,
        hit_words=words or None,
        hit_regexes=regexes or None,
    )

    if len(filtered) != len(records):
        full_path = output.with_name(output.stem + ".full" + output.suffix)
        if output.exists():
            output.replace(full_path)
        write_jsonl(output, filtered)
        console.print(f"[dim]Full transcripts:[/dim] {full_path}")

    if ips_output:
        write_lines(ips_output, extract_ips(filtered))

    stats = summarize_modules(filtered if filtered else records)
    console.print(
        f"[green]Done.[/green] {len(filtered)}/{len(records)} records -> {output}"
        + (f", {ips_output}" if ips_output else "")
    )
    for name, counts in sorted(stats.items()):
        console.print(
            f"  [cyan]{name}[/cyan] success={counts['success']} "
            f"error={counts['error']} other={counts['other']}"
        )


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run_cmd(
    ctx: typer.Context,
    asn: str = typer.Option(..., "--asn", help="ASN to map (AS36352 or 36352)"),
    port: int = typer.Option(..., "--port", "-p", help="Target TCP/UDP port for ZMap + ZGrab2"),
    module: str = typer.Option(
        "banner",
        "--module",
        "-m",
        help="ZGrab2 module (see `mst modules`)",
    ),
    hit_words: Optional[str] = typer.Option(
        None,
        "--hit-words",
        help="Optional comma-separated substrings matched against full JSON transcripts",
    ),
    hit_regex: Optional[list[str]] = typer.Option(
        None,
        "--hit-regex",
        "-r",
        help="Optional regex matched against full JSON transcripts (repeatable)",
    ),
    senders: int = typer.Option(50, "--senders", "-j", help="ZGrab2 sender goroutines"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="ZGrab2 per-target timeout seconds"),
    bandwidth: str = typer.Option("10M", "--bandwidth", "-b", help="ZMap bandwidth"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface for ZMap"),
    gateway_mac: Optional[str] = typer.Option(
        None,
        "--gateway-mac",
        "-G",
        help="Gateway MAC (avoids ARP hang); implies Ethernet send path",
    ),
    vpn: Optional[bool] = typer.Option(
        None,
        "--vpn/--no-vpn",
        "-X",
        help="Send IP packets (recommended in Docker/WSL). Default: auto in containers.",
    ),
    success_only: bool = typer.Option(
        True,
        "--success-only/--all-results",
        help="Keep only successful protocol handshakes in hits.jsonl",
    ),
    zgrab_config: Optional[Path] = typer.Option(
        None,
        "--zgrab-config",
        help="ZGrab2 multiple-module .ini",
    ),
    runs_dir: Path = typer.Option(Path("runs"), "--runs-dir", help="Archive parent directory"),
    skip_zmap: bool = typer.Option(
        False,
        "--skip-zmap",
        help="Skip ZMap and treat the CIDR file as an IP list (debug)",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm zmap/zgrab2 installs"),
) -> None:
    """Full pipeline: ASN -> CIDR -> ZMap -> ZGrab2 -> archive under runs/."""
    started = datetime.now(timezone.utc)
    extra_args = list(ctx.args)
    words = _parse_hit_words(hit_words, None)
    regexes = _parse_hit_regexes(hit_regex, None)

    try:
        asn_n = normalize_asn(asn)
        module_v = "multiple" if zgrab_config else validate_module(module)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    run_dir = make_run_dir(runs_dir, label=asn_n)
    console.print(f"[bold]Run archive:[/bold] {run_dir}")

    cidrs_path = run_dir / "cidrs.txt"
    zmap_path = run_dir / "zmap.json"
    zgrab_full = run_dir / "zgrab2.full.jsonl"
    hits_jsonl = run_dir / "hits.jsonl"
    hits_txt = run_dir / "hits.txt"
    summary_path = run_dir / "summary.json"

    console.print(f"[bold]1/3 ASN -> CIDR ({asn_n})[/bold]")
    try:
        cidrs = asn_to_cidrs(asn_n)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    write_cidrs(str(cidrs_path), cidrs)
    console.print(f"  {len(cidrs)} CIDRs -> {cidrs_path}")

    open_hosts: list[str] = []
    if skip_zmap:
        console.print("[yellow]2/3 Skipping ZMap (--skip-zmap)[/yellow]")
        zmap_path.write_text("", encoding="utf-8")
    else:
        console.print(f"[bold]2/3 ZMap port {port}[/bold]")
        try:
            run_zmap(
                whitelist=cidrs_path,
                port=port,
                output=zmap_path,
                bandwidth=bandwidth,
                interface=interface,
                gateway_mac_addr=gateway_mac,
                vpn=vpn,
                console=console,
                assume_yes=yes,
            )
        except (RuntimeError, OSError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        open_hosts = load_ips(zmap_path)
        console.print(f"  {len(open_hosts)} open hosts -> {zmap_path}")

    console.print(f"[bold]3/3 ZGrab2 module={module_v}[/bold]")
    filtered: list[dict] = []
    records: list[dict] = []
    if skip_zmap and not open_hosts:
        console.print("[yellow]No open hosts to grab (skipped zmap).[/yellow]")
    elif not open_hosts:
        console.print("[yellow]No open hosts from ZMap; skipping zgrab2.[/yellow]")
    else:
        try:
            run_zgrab2(
                module=module_v,
                targets=open_hosts,
                output=zgrab_full,
                port=port,
                senders=senders,
                timeout=timeout,
                multiple_config=zgrab_config,
                extra_args=extra_args or None,
                console=console,
                assume_yes=yes,
            )
        except (RuntimeError, FileNotFoundError, ValueError, OSError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        records = list(iter_zgrab2_records(zgrab_full))
        filtered = filter_zgrab2_records(
            records,
            success_only=success_only,
            hit_words=words or None,
            hit_regexes=regexes or None,
        )
        write_jsonl(hits_jsonl, filtered)
        write_lines(hits_txt, extract_ips(filtered))
        console.print(f"  {len(filtered)}/{len(records)} records -> {hits_jsonl}")

    ended = datetime.now(timezone.utc)
    summary = {
        "asn": asn_n,
        "port": port,
        "module": module_v,
        "hit_words": words,
        "hit_regexes": regexes,
        "bandwidth": bandwidth,
        "senders": senders,
        "timeout": timeout,
        "success_only": success_only,
        "cidr_count": len(cidrs),
        "open_hosts": len(open_hosts),
        "zgrab2_records": len(records),
        "hits": len(filtered),
        "module_stats": summarize_modules(filtered),
        "started": started.isoformat(),
        "ended": ended.isoformat(),
        "duration_seconds": (ended - started).total_seconds(),
        "run_dir": str(run_dir),
        "zgrab2_passthrough": extra_args,
    }
    write_json(summary_path, summary)
    console.print(
        f"[green]Complete.[/green] {len(filtered)} hits in "
        f"{summary['duration_seconds']:.1f}s -> {run_dir}"
    )


if __name__ == "__main__":
    app()
