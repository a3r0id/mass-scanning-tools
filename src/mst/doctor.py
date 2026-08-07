"""Dependency checks and guided fixes (`mst doctor`)."""

from __future__ import annotations

import os
import platform
import shutil
import sys

from rich.console import Console
from rich.table import Table

from mst import __version__
from mst.zgrab2_ops import find_go, find_zgrab2, offer_install_zgrab2
from mst.zmap_ops import find_zmap, in_container, offer_install_zmap


def run_doctor(console: Console | None = None, *, assume_yes: bool = False) -> int:
    """Print environment health. Returns 0 if ready for full pipeline, else 1."""
    console = console or Console()
    table = Table(title=f"mst doctor (v{__version__})")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail")

    ok = True

    # Python
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        table.add_row("Python", "[green]ok[/green]", py)
    else:
        ok = False
        table.add_row("Python", "[red]fail[/red]", f"{py} (need >= 3.10)")

    # Platform
    table.add_row("Platform", "[cyan]info[/cyan]", platform.platform())

    # whois
    whois = shutil.which("whois")
    if whois:
        table.add_row("whois", "[green]ok[/green]", whois)
    else:
        table.add_row(
            "whois",
            "[yellow]missing[/yellow]",
            "optional - ASN lookup will use a socket fallback to whois.radb.net",
        )

    # go (needed to build zgrab2)
    go = find_go()
    if go:
        table.add_row("go", "[green]ok[/green]", go)
    else:
        table.add_row(
            "go",
            "[yellow]missing[/yellow]",
            "needed to build zgrab2 from source (Go 1.23+)",
        )

    # zmap
    zmap = find_zmap()
    if zmap:
        table.add_row("zmap", "[green]ok[/green]", zmap)
    else:
        ok = False
        table.add_row("zmap", "[red]missing[/red]", "required for `mst scan` / `mst run`")

    # zgrab2
    zgrab2 = find_zgrab2()
    if zgrab2:
        table.add_row("zgrab2", "[green]ok[/green]", zgrab2)
    else:
        ok = False
        table.add_row(
            "zgrab2",
            "[red]missing[/red]",
            "required for `mst probe` / `mst run` (https://github.com/zmap/zgrab2)",
        )

    # privileges
    if os.name != "nt" and hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            table.add_row("privileges", "[green]root[/green]", "zmap can use raw sockets")
        else:
            table.add_row(
                "privileges",
                "[yellow]user[/yellow]",
                "zmap may need sudo or CAP_NET_RAW",
            )
    else:
        table.add_row(
            "privileges",
            "[yellow]n/a[/yellow]",
            "Windows: use WSL2 for zmap/zgrab2",
        )

    # networking
    if in_container():
        table.add_row(
            "networking",
            "[yellow]container[/yellow]",
            "mst scan auto-enables zmap --vpn (gateway ARP often hangs on docker bridges)",
        )
    else:
        table.add_row("networking", "[green]ok[/green]", "host/network namespace looks normal")

    console.print(table)

    if not find_zmap():
        console.print()
        offer_install_zmap(console, assume_yes=assume_yes)
        if find_zmap():
            console.print(f"[green]zmap ready:[/green] {find_zmap()}")

    if not find_zgrab2():
        console.print()
        offer_install_zgrab2(console, assume_yes=assume_yes)
        if find_zgrab2():
            console.print(f"[green]zgrab2 ready:[/green] {find_zgrab2()}")

    ok = bool(find_zmap() and find_zgrab2() and sys.version_info >= (3, 10))
    return 0 if ok else 1
