# mass-scanning-tools

<img width="872" height="1061" alt="image" src="https://github.com/user-attachments/assets/f2d85a6e-e061-4a55-9121-15fc56d9a0b9" />


Map services across entire IP ranges, then quantify, inspect, and archive the results.

**UPDATE**: Picking this project back up, after many years. This is an old project that I figured could use some TLC, enjoy!

**Pipeline:** `ASN -> CIDR -> ZMap -> ZGrab2 -> archive`

> **Authorization required.** Only scan networks you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Install

Requires **Python 3.10+**.

```bash
pip install -e .
```

This installs the `mst` command.

External tools:

| Tool | Role | Install |
|------|------|---------|
| [ZMap](https://zmap.io/) | L4 discovery (open ports) | `mst doctor` / distro packages |
| [ZGrab2](https://github.com/zmap/zgrab2) | L7 handshakes / banners | `mst doctor` (builds from source; needs Go 1.23+) |

On Windows, use **WSL2**, then run `mst doctor` inside WSL.

ASN lookup uses the `whois` binary when available, otherwise a direct socket query to `whois.radb.net`.

## Quickstart

```bash
mst doctor
mst run --asn AS36352 --port 1337 --module banner
mst run --asn AS36352 --port 443 --module tls
mst run --asn AS36352 --port 80 --module http -- --endpoint=/ --max-redirects=1
```

## Commands

```text
mst doctor                              # check whois/zmap/zgrab2; offer installs
mst asn AS36352 -o cidrs.txt            # ASN -> CIDR list
mst scan -w cidrs.txt -p 1337 -o open.json
mst modules                             # list ZGrab2 protocol modules + default ports
mst probe open.json -m banner -p 1337 -o zgrab2.jsonl
mst probe open.json -m http -p 80 -- --endpoint=/
mst probe open.json --zgrab-config multi.ini -o zgrab2.jsonl
mst run --asn AS36352 --port 22 --module ssh
```

Anything after `--` on `mst probe` / `mst run` is passed straight through to ZGrab2 (module-specific flags).

### ZGrab2 modules

`mst` supports every protocol ZGrab2 ships, including:

AMQP, AMQP091, BACnet, Banner, CheckPoint, Codesys2, DNP3, DRDA, EtherNet/IP, Fox, FTP, HTTP, IMAP, IPP, JARM, ManageSieve, Memcached, Modbus, MongoDB, MQTT, MSSQL, MySQL, NTP, Omron FINS, Oracle, POP3, PostgreSQL, PPTP, RDP, Redis, Siemens, SMB, SMTP, SOCKS5, SSH, Telnet, TLS.

`mst modules` lists the built-in catalog; `mst modules --installed` queries your local `zgrab2` binary so newly added upstream modules are picked up automatically.

Optional filters:

- `--success-only` (default) keeps protocol successes; `--all-results` keeps every record
- `--hit-words` / `--hit-regex` match against the **full JSON transcript** (not a reduced banner string)

### Multiple modules

Use a ZGrab2 `.ini` with `mst probe --zgrab-config multi.ini` / `mst run --zgrab-config multi.ini`. Example:

```ini
[Application Options]
[http]
name="http80"
port=80
endpoint="/"
[ssh]
name="ssh22"
port=22
```

### Archive layout (`mst run`)

```text
runs/20260101T120000Z_AS36352/
  cidrs.txt
  zmap.json
  zgrab2.full.jsonl   # complete ZGrab2 transcripts
  hits.jsonl          # filtered successes / hit matches
  hits.txt
  summary.json
```

## Development

```bash
pip install -e .
mst --help
```

## Legacy

The old standalone scripts (`asn2cidr`, `raw_cnc_discovery`, `telnet_cnc_discovery`, `zmap_stuff`) and the built-in raw/telnet socket prober are replaced by `mst` + ZMap + ZGrab2.
