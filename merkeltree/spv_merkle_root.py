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

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterable, Tuple


class InputFormatError(ValueError):
    pass


def _parse_hex_bytes(hex_str: str, *, context: str) -> bytes:
    '''
    Parses a hex string into bytes, with error context.
        :param hex_str: The hex string to parse.
        :param context: Contextual information for error messages.
        :return: The parsed bytes.
        :rtype: bytes
    '''
    s = hex_str.strip()
    if s.startswith("0x") or s.startswith("0X"):
        # remove the 0x prefix that sometimes appears in hex strings
        s = s[2:]
    if len(s) == 0:
        raise InputFormatError(f"Missing hex string for {context}.")
    if len(s) % 2 != 0:
        # because every valid hex string's length must be even
        raise InputFormatError(f"Hex string length must be even for {context}: got {len(s)}.")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise InputFormatError(f"Invalid hex for {context}: {e}") from e


def _iter_nonempty_lines(text: str) -> Iterable[Tuple[int, str]]:
    '''
    A generator function that yields the hashes as non-empty lines from the input text along with their line numbers (indexes).
        :param text: The input text to process.
    '''
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        print(f"Iterating line {idx}: {line}")
        yield idx, line


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

        current = hashlib.sha1(data).digest()

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
