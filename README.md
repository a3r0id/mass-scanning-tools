# mass-scanning-tools

**Mass-Scanning** as in: Locating specific services like botnet C2's etc. over an entire ASN range.

I will add some better documentation when I have the time.

__[Programatically Chaining I/O]:__

[ASN] -> asn2cidr.py -> Zmap (passing the port/probe module you are seeking) -> [raw/telnet/http discovery tool] -> Manual Examination

