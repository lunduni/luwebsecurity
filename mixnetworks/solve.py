from __future__ import annotations

import runpy
import sys
from pathlib import Path


def _read_required_text(path: Path, *, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as ex:
        raise SystemExit(f"Missing required {label} file: {path}") from ex
    if not value:
        raise SystemExit(f"{label} file is empty: {path}")
    return value


def main() -> None:
    # Wrapper entrypoint required by the assignment structure.
    # Delegates to the actual implementation in disclosure_attack/solve.py.
    root = Path(__file__).resolve().parent
    impl = root / "disclosure_attack" / "solve.py"

    # If no args are provided, default to the input files in mixnetworks/.
    # Files expected:
    # - mixnetworks/nazir.txt (single IP)
    # - mixnetworks/mix.txt (single IP)
    # - mixnetworks/partners.txt (single integer)
    # - mixnetworks/pcap.pcap (pcap capture)
    if len(sys.argv) == 1:
        nazir = _read_required_text(root / "nazir.txt", label="Nazir IP")
        mix = _read_required_text(root / "mix.txt", label="Mix IP")
        partners = _read_required_text(root / "partners.txt", label="Partners count")
        pcap = root / "pcap.pcap"
        if not pcap.exists():
            raise SystemExit(f"Missing required pcap file: {pcap}")

        sys.argv.extend([
            "--nazir",
            nazir,
            "--mix",
            mix,
            "--partners",
            partners,
            "--pcap",
            str(pcap),
        ])

    # Ensure bundled dependencies (pcapfile/) are importable.
    sys.path.insert(0, str(impl.parent))
    runpy.run_path(str(impl), run_name="__main__")


if __name__ == "__main__":
    main()
