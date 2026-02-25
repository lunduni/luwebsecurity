from __future__ import annotations

import sys
from pathlib import Path

# Ensure bundled pcapfile and solver are importable.
sys.path.insert(0, str(Path(__file__).resolve().parent / "disclosure_attack"))

from solve import build_runs, disclosure_attack, ip_to_int  # noqa: E402


def main() -> None:
    nazir = "160.66.13.37"
    mix = "204.177.242.216"
    partners_count = 15
    pcap = Path("mixnetworks/pcap.pcap")

    runs = build_runs(pcap, mix)
    partners = disclosure_attack(runs, nazir, partners_count, verbose=False)
    total = sum(ip_to_int(ip) for ip in partners)

    print("partners:")
    for ip in partners:
        print(" ", ip)
    print("sum:", total)

    partner_set = set(partners)
    violations: list[tuple[int, int, list[str], int]] = []
    nazir_pairs = 0

    for i in range(len(runs) - 1):
        rin = runs[i]
        rout = runs[i + 1]
        if rin.direction != "in" or rout.direction != "out":
            continue
        if nazir not in rin.senders:
            continue

        nazir_pairs += 1
        present = sorted(partner_set.intersection(rout.receivers))
        if len(present) != 1:
            violations.append((i, len(present), present[:5], len(rout.receivers)))

    print("nazir-present pairs:", nazir_pairs)
    print("violations:", len(violations))
    if violations:
        print("first violations:")
        for v in violations[:10]:
            print(" ", v)


if __name__ == "__main__":
    main()
