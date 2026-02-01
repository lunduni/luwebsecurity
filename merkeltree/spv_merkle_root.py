"""

A program that computes a Merkle root from a leaf + Merkle path as used in SPV verification.
Written by:
- Prince Samuel Kyeremanteng
- Hadar Eklund

Input file format:
- First non-empty line: leaf hash as hex (e.g., 40 hex chars for SHA-1)
- Each subsequent non-empty line: <L|R><hex>
  where the prefix indicates whether the sibling is on the Left or Right.

Hash function: SHA-1
Parent computation:
- If sibling is Left:  parent = SHA1(sibling || current)
- If sibling is Right: parent = SHA1(current || sibling)

Outputs the resulting Merkle root as lowercase hex.
"""
# We leveraged on these python standard libraries:

# this allows postponed evaluation of annotations
from __future__ import annotations
# for command-line argument parsing and system operations
import argparse
import sys
# for file path manipulations
from pathlib import Path

# so I can run this file directly from within the merkeltree package
if __package__ is None or __package__ == "":
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from merkeltree.common import InputFormatError, _iter_nonempty_lines, _parse_hex_bytes, _sha1


def compute_merkle_root_from_file_content(file_content: str) -> bytes:
    """A function to compute and return the Merkle root as raw bytes."""
    it = iter(_iter_nonempty_lines(file_content))
    try:
        leaf_line_no, leaf_hex = next(it)
    except StopIteration as e:
        raise InputFormatError("Input file is empty (expected at least a leaf hex on the first line).") from e

    current = _parse_hex_bytes(leaf_hex, context=f"leaf on line {leaf_line_no}")

    for line_no, line in it:
        if len(line) < 2:
            # The line must at least have a side character and some hex
            raise InputFormatError(
                f"Invalid Merkle path entry on line {line_no}: expected 'L<hex>' or 'R<hex>'."
            )
        side = line[0]
        if side not in ("L", "R"):
            raise InputFormatError(
                f"Invalid Merkle path entry on line {line_no}: must start with 'L' or 'R', got '{side}'."
            )
        sibling = _parse_hex_bytes(line[1:], context=f"sibling on line {line_no}")

        if side == "L":
            data = sibling + current
        else:  # side == "R". This is safe because of the earlier check on line 85.
            data = current + sibling

        # current = hashlib.sha1(data).digest()
        current = _sha1(data)

    return current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute Merkle root from a leaf hash and Merkle path  using (SHA-1)."
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to the input file containing leaf hex and Merkle path lines.",
    )
    args = parser.parse_args(argv)

    content = args.input_file.read_text(encoding="utf-8")
    root = compute_merkle_root_from_file_content(content)
    print(root.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
