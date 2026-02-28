from __future__ import annotations

import argparse
import ipaddress
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pcapfile import savefile


@dataclass(frozen=True)
class Run:
    direction: str  # 'in' (to mix) or 'out' (from mix)
    senders: frozenset[str]
    receivers: frozenset[str]


def ip_to_int(ip: str) -> int:
    # Big-endian 32-bit integer.
    return int(ipaddress.IPv4Address(ip))


def iter_packets(pcap_path: Path) -> Iterable[tuple[str, str]]:
    """Yield (ip_src, ip_dst) strings for each packet."""

    with pcap_path.open("rb") as fh:
        cap = savefile.load_savefile(fh, layers=2, verbose=False)

    for pkt in cap.packets:
        ip_src = pkt.packet.payload.src.decode("UTF8")
        ip_dst = pkt.packet.payload.dst.decode("UTF8")
        yield ip_src, ip_dst


def build_runs(pcap_path: Path, mix_ip: str) -> list[Run]:
    runs: list[Run] = []

    current_dir: str | None = None
    current_senders: set[str] = set()
    current_receivers: set[str] = set()

    def flush() -> None:
        nonlocal current_dir, current_senders, current_receivers
        if current_dir is None:
            return
        runs.append(
            Run(
                direction=current_dir,
                senders=frozenset(current_senders),
                receivers=frozenset(current_receivers),
            )
        )
        current_dir = None
        current_senders = set()
        current_receivers = set()

    for ip_src, ip_dst in iter_packets(pcap_path):
        if ip_dst == mix_ip:
            direction = "in"
            sender = ip_src
            receiver = ip_dst
        elif ip_src == mix_ip:
            direction = "out"
            sender = ip_src
            receiver = ip_dst
        else:
            # Ignore unrelated traffic (if present).
            continue

        if current_dir is None:
            current_dir = direction
        elif direction != current_dir:
            flush()
            current_dir = direction

        # Track who sent in this run and who received in this run.
        if direction == "in":
            current_senders.add(sender)
        else:
            current_receivers.add(receiver)

    flush()

    # Some pcaps may start/end mid-cycle; we want (in, out) pairs.
    return runs


def disclosure_attack(
    runs: list[Run],
    nazir_ip: str,
    partners_count: int,
    *,
    verbose: bool = False,
) -> list[str]:
    """Return disclosed partner IPs as strings."""

    learning_sets: list[set[str]] = []
    used: set[str] = set()

    i = 0
    # Phase 1: learn m disjoint output sets.
    while i + 1 < len(runs) and len(learning_sets) < partners_count:
        r_in = runs[i]
        r_out = runs[i + 1]
        i += 1

        if r_in.direction != "in" or r_out.direction != "out":
            continue

        if nazir_ip not in r_in.senders:
            continue

        candidate = set(r_out.receivers)
        if candidate.isdisjoint(used):
            learning_sets.append(candidate)
            used |= candidate
            if verbose:
                print(
                    f"[learn] saved set {len(learning_sets)}/{partners_count} size={len(candidate)}",
                    file=sys.stderr,
                )

    if len(learning_sets) != partners_count:
        raise RuntimeError(
            f"Could not find {partners_count} disjoint sets; found {len(learning_sets)}. "
            "Check inputs or pcap completeness."
        )

    # Phase 2: exclude until each set becomes singleton.
    def all_singletons() -> bool:
        return all(len(s) == 1 for s in learning_sets)

    while i + 1 < len(runs) and not all_singletons():
        r_in = runs[i]
        r_out = runs[i + 1]
        i += 1

        if r_in.direction != "in" or r_out.direction != "out":
            continue

        out_set = set(r_out.receivers)

        if nazir_ip not in r_in.senders:
            # We only learn from rounds where Nazir is observed sending.
            # In rounds where Nazir is absent, other users may still send to
            # Nazir's partners, so we MUST NOT eliminate candidates here.
            continue

        # Nazir sent: the following outgoing batch contains exactly one of his
        # partners. We only update when the batch intersects exactly one of the
        # candidate sets; otherwise the observation is ambiguous (overlaps can
        # happen on non-partner recipients).
        intersects: list[tuple[int, set[str]]] = []
        for idx, s in enumerate(learning_sets):
            inter = s & out_set
            if inter:
                intersects.append((idx, inter))

        if len(intersects) != 1:
            continue

        idx, inter = intersects[0]
        if inter != learning_sets[idx]:
            learning_sets[idx] = inter
            if verbose:
                print(f"[exclude-present] set {idx+1} shrank to size={len(inter)}", file=sys.stderr)

    if not all_singletons():
        sizes = [len(s) for s in learning_sets]
        raise RuntimeError(f"Excluding phase ended but not all singletons. Sizes={sizes}")

    partners = [next(iter(s)) for s in learning_sets]
    return partners


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Disclosure attack on mix network pcap: output sum of partner IP integers"
    )
    parser.add_argument("--nazir", required=True, help="Abu Nazir IP address")
    parser.add_argument("--mix", required=True, help="Mix IP address")
    parser.add_argument("--partners", type=int, required=True, help="Number of partners")
    parser.add_argument("--pcap", type=Path, required=True, help="Path to .pcap file")
    parser.add_argument("--verbose", action="store_true", help="Print progress information")
    parser.add_argument(
        "--show-partners",
        action="store_true",
        help="Print disclosed partner IPs to stderr (stdout remains the required sum)",
    )
    args = parser.parse_args()

    # Validate IPs early.
    ipaddress.IPv4Address(args.nazir)
    ipaddress.IPv4Address(args.mix)

    runs = build_runs(args.pcap, args.mix)
    if args.verbose:
        print(f"runs={len(runs)}", file=sys.stderr)

    partners = disclosure_attack(runs, args.nazir, args.partners, verbose=args.verbose)
    if args.show_partners:
        for ip in partners:
            print(ip, file=sys.stderr)
    total = sum(ip_to_int(ip) for ip in partners)

    # Required output: integer sum only.
    print(total)


if __name__ == "__main__":
    main()
