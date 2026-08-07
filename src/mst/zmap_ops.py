"""ZMap detection, guided install, and invocation."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm


def in_container() -> bool:
    """Best-effort detection for Docker/Podman/containerd environments."""
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(token in cgroup for token in ("docker", "containerd", "kubepods", "podman"))


def default_interface() -> str | None:
    """Return the interface used for the default IPv4 route, if any."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    match = re.search(r"\bdev\s+(\S+)", out)
    return match.group(1) if match else None


def gateway_mac(interface: str | None = None) -> str | None:
    """Return the L2 address of the default gateway when already in the neighbor table."""
    iface = interface or default_interface()
    if not iface:
        return None
    try:
        route = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    gw_match = re.search(r"default via ([0-9.]+)", route)
    if not gw_match:
        return None
    gateway = gw_match.group(1)
    try:
        neigh = subprocess.check_output(
            ["ip", "neigh", "show", gateway, "dev", iface],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    mac_match = re.search(r"lladdr\s+([0-9a-fA-F:]{11,17})", neigh)
    return mac_match.group(1) if mac_match else None


def should_use_vpn_mode(*, vpn: bool | None = None, gateway_mac_addr: str | None = None) -> bool:
    """
    ZMap Ethernet send path ARP-resolves the gateway MAC and often hangs forever
    inside Docker/WSL bridge networking. Prefer IP-layer (--vpn) there unless the
    caller already supplied a gateway MAC.
    """
    if vpn is not None:
        return vpn
    if gateway_mac_addr:
        return False
    return in_container()


@dataclass
class InstallPlan:
    platform_name: str
    commands: list[list[str]]
    notes: str = ""


def find_zmap() -> str | None:
    return shutil.which("zmap")


def detect_install_plan() -> InstallPlan:
    system = platform.system().lower()
    if system == "windows":
        return InstallPlan(
            platform_name="Windows",
            commands=[],
            notes=(
                "ZMap is not supported natively on Windows. "
                "Install WSL2 (Ubuntu), then run `mst doctor` inside WSL and install zmap there."
            ),
        )

    if system == "darwin":
        if shutil.which("brew"):
            return InstallPlan(
                platform_name="macOS (Homebrew)",
                commands=[["brew", "install", "zmap"]],
            )
        return InstallPlan(
            platform_name="macOS",
            commands=[],
            notes="Install Homebrew (https://brew.sh), then re-run `mst doctor`.",
        )

    # Linux
    if shutil.which("apt-get"):
        return InstallPlan(
            platform_name="Debian/Ubuntu",
            commands=[
                ["sudo", "apt-get", "update"],
                ["sudo", "apt-get", "install", "-y", "zmap"],
            ],
        )
    if shutil.which("dnf"):
        return InstallPlan(
            platform_name="Fedora/RHEL",
            commands=[["sudo", "dnf", "install", "-y", "zmap"]],
        )
    if shutil.which("yum"):
        return InstallPlan(
            platform_name="RHEL/CentOS",
            commands=[["sudo", "yum", "install", "-y", "zmap"]],
        )
    if shutil.which("pacman"):
        return InstallPlan(
            platform_name="Arch",
            commands=[["sudo", "pacman", "-S", "--noconfirm", "zmap"]],
        )
    if shutil.which("zypper"):
        return InstallPlan(
            platform_name="openSUSE",
            commands=[["sudo", "zypper", "install", "-y", "zmap"]],
        )

    return InstallPlan(
        platform_name=f"Linux ({platform.platform()})",
        commands=[],
        notes="No supported package manager detected. Build zmap from https://github.com/zmap/zmap",
    )


def offer_install_zmap(console: Console | None = None, *, assume_yes: bool = False) -> bool:
    """Prompt the user and attempt to install zmap. Returns True if zmap is available afterward."""
    console = console or Console()
    if find_zmap():
        console.print(f"[green]zmap found:[/green] {find_zmap()}")
        return True

    plan = detect_install_plan()
    console.print(f"[yellow]zmap not found on PATH.[/yellow] Detected: {plan.platform_name}")
    if plan.notes:
        console.print(f"[dim]{plan.notes}[/dim]")
    if not plan.commands:
        return False

    console.print("Install commands:")
    for cmd in plan.commands:
        console.print(f"  [cyan]{' '.join(cmd)}[/cyan]")

    if not assume_yes:
        if not Confirm.ask("Run these install commands now?", default=True):
            console.print("[yellow]Skipped zmap install.[/yellow]")
            return False

    for cmd in plan.commands:
        console.print(f"[bold]$ {' '.join(cmd)}[/bold]")
        try:
            result = subprocess.run(cmd, check=False)
        except OSError as exc:
            console.print(f"[red]Failed to run {' '.join(cmd)}: {exc}[/red]")
            return False
        if result.returncode != 0:
            console.print(f"[red]Command failed with exit {result.returncode}[/red]")
            return False

    path = find_zmap()
    if path:
        console.print(f"[green]zmap installed:[/green] {path}")
        return True
    console.print(
        "[yellow]Install finished but zmap still not on PATH. "
        "Open a new shell or check your package manager output.[/yellow]"
    )
    return False


def ensure_zmap(console: Console | None = None, *, assume_yes: bool = False) -> str:
    """Return path to zmap, offering install if missing. Raises RuntimeError if unavailable."""
    console = console or Console()
    path = find_zmap()
    if path:
        return path
    if offer_install_zmap(console, assume_yes=assume_yes):
        path = find_zmap()
        if path:
            return path
    raise RuntimeError(
        "zmap is required but not available. Install it manually, then re-run."
    )


def run_zmap(
    whitelist: Path | str,
    port: int,
    output: Path | str,
    *,
    bandwidth: str = "10M",
    output_module: str = "json",
    cooldown_time: int | None = None,
    interface: str | None = None,
    gateway_mac_addr: str | None = None,
    vpn: bool | None = None,
    extra_args: list[str] | None = None,
    console: Console | None = None,
    assume_yes: bool = False,
) -> Path:
    console = console or Console()
    zmap = ensure_zmap(console, assume_yes=assume_yes)
    whitelist = Path(whitelist)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    if not whitelist.is_file():
        raise FileNotFoundError(f"Whitelist not found: {whitelist}")

    iface = interface or default_interface()
    mac = gateway_mac_addr
    use_vpn = should_use_vpn_mode(vpn=vpn, gateway_mac_addr=mac)
    if not use_vpn and not mac:
        mac = gateway_mac(iface)

    cmd = [
        "sudo",
        zmap,
        f"--whitelist-file={whitelist}",
        f"--bandwidth={bandwidth}",
        f"--target-port={port}",
        f"--output-module={output_module}",
        f"--output-file={output}",
    ]
    if iface:
        cmd.append(f"--interface={iface}")
    if use_vpn:
        cmd.append("--vpn")
        console.print(
            "[yellow]Using --vpn (IP packets).[/yellow] "
            "Container/bridge networking often hangs while ZMap ARP-resolves the gateway MAC."
        )
    elif mac:
        cmd.append(f"--gateway-mac={mac}")
    if cooldown_time is not None:
        cmd.append(f"--cooldown-time={cooldown_time}")
    if extra_args:
        cmd.extend(extra_args)

    console.print(f"[bold]$ {' '.join(cmd)}[/bold]")
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print(
            "[yellow]Note: zmap often requires root or CAP_NET_RAW. "
            "If it fails, retry with sudo.[/yellow]"
        )

    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"zmap exited with code {result.returncode}")
    if not output.exists():
        # zmap may create empty output; touch for pipeline consistency
        output.touch()
    return output
