"""CLI: python -m macsec_lab generate|analyze|lab-inject."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cmd_generate(args: argparse.Namespace) -> int:
    from .generate import generate

    written = generate(Path(args.out))
    print(f"wrote {len(written)} pcaps to {args.out}")
    for name, path in written.items():
        print(f"  {name:42s} {path.stat().st_size:6d} B")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from .analyze import write_reports

    dests = write_reports(Path(args.captures), Path(args.out), Path(args.docs) if args.docs else None)
    print(f"wrote {len(dests)} reports to {args.out}")
    for p in dests:
        print(f"  {p.name}")
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    """Send generated frames on an AF_PACKET interface (needs CAP_NET_RAW)."""
    import socket
    import time

    from .generate import generate
    from .pcap import read_pcap

    tmp = Path(args.captures)
    generate(tmp)
    pcap = tmp / args.pcap
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for pkt in read_pcap(pcap):
        sock.send(pkt.data)
        time.sleep(args.delay)
        print(f"sent {len(pkt.data)} octets on {args.iface}")
    sock.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="macsec_lab", description="MACsec / MKA learning lab")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write reference PCAPs")
    g.add_argument("--out", default=str(ROOT / "captures"))
    g.set_defaults(func=cmd_generate)

    a = sub.add_parser("analyze", help="parse PCAPs into Markdown")
    a.add_argument("--captures", default=str(ROOT / "captures"))
    a.add_argument("--out", default=str(ROOT / "captures" / "decoded"))
    a.add_argument("--docs", default=str(ROOT / "docs"))
    a.set_defaults(func=cmd_analyze)

    i = sub.add_parser("inject", help="replay a pcap onto a local interface")
    i.add_argument("--iface", required=True)
    i.add_argument("--captures", default=str(ROOT / "captures"))
    i.add_argument("--pcap", default="session-full.pcap")
    i.add_argument("--delay", type=float, default=0.05)
    i.set_defaults(func=cmd_inject)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
