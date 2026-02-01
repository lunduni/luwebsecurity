"""
Thi program is a full-node helper that builds a SHA-1 Merkle tree from given leaves and returns Merkle path information.
Written by:
- Prince Samuel Kyeremanteng
- Hadar Eklund

Input file format (one item per line):
1) integer i  (leaf index)
2) integer j  (depth for the requested Merkle-path node; root depth=0)
3+) leaves as hex strings (interpreted as byte arrays)

Tree rules:
- Parent node = SHA1(left_child || right_child)
- If a level has an odd number of nodes, duplicate the last node to make it even. (I saw this rule in a youtube video.)

Outputs (stdout):
- The concatenation of:
  (a) the Merkle path node at depth j, prefixed with 'L'/'R'
  (b) the Merkle root hex

Optionally prints the full Merkle path (leaf sibling first) to stderr.
"""

# We leveraged on these python standard libraries:
# this allows postponed evaluation of annotations
from __future__ import annotations
# for command-line argument parsing and system operations
import argparse
import sys
# for data structure definitions and type hinting
from dataclasses import dataclass
from typing import List, Tuple
# for file path manipulations
from pathlib import Path

# so it can run as a script while still supporting package-style imports
if __package__ is None or __package__ == "":
    # add the repo root to sys.path if it's not already there
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from merkeltree.common import InputFormatError, _iter_nonempty_lines, _parse_hex_bytes, _sha1


def _parse_int(s: str, *, context: str) -> int:
    '''
    Parses an integer from a string, with error context.
        :param s: The string to parse.
        :param context: Contextual information for error messages.
        :return: The parsed integer.
        :rtype: int
    '''
    try:
        return int(s.strip())
    except ValueError as e:
        raise InputFormatError(f"Invalid integer for {context}: {s!r}") from e


def build_merkle_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """Return levels as a list from leaves up to root.

    levels[0] = leaves
    levels[-1] = [root]

    Note: Padding is applied during construction to ensure each level has even length.
    """
    if not leaves:
        raise InputFormatError("At least one leaf is required.")

    levels: List[List[bytes]] = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        # Build the parent level from the current level.
        if len(current) % 2 == 1:
            # Pad by duplicating the last node if the number of nodes is odd.
            current = current + [current[-1]]
        parent: List[bytes] = []
        for k in range(0, len(current), 2):
            parent.append(_sha1(current[k] + current[k + 1]))
        levels.append(parent)
        current = parent

    return levels


@dataclass(frozen=True)
class PathNode:
    '''
    A Merkle path node consisting of its depth, side (L/R), and sibling hash.
    '''
    depth: int  # root is 0, leaves are max depth
    side: str   # 'L' or 'R' indicating where sibling sits
    sibling: bytes


def compute_merkle_path(leaves: List[bytes], leaf_index: int) -> Tuple[List[PathNode], bytes]:
    """Compute the Merkle path for leaves[leaf_index] and return (path_nodes, root).

    The returned path_nodes are ordered from highest depth to lowest depth:
    leaf sibling first, then upwards toward the root.
    """
    levels = build_merkle_levels(leaves)
    max_depth = len(levels) - 1  # root level is last => depth 0, leaves => depth max_depth

    if leaf_index < 0 or leaf_index >= len(leaves):
        # check if leaf_index is valid
        raise InputFormatError(f"Leaf index i out of range: i={leaf_index}, leaves={len(leaves)}")

    idx = leaf_index
    path: List[PathNode] = []

    # Walk from leaf level (depth=max_depth) up to depth=1.
    for level_no in range(0, max_depth):
        nodes = levels[level_no]
        # Ensure padding matches build rules.
        if len(nodes) % 2 == 1:
            nodes = nodes + [nodes[-1]]

        # bcus a sibling of a node is either directly left or right of it
        if idx % 2 == 0:
            sibling_idx = idx + 1
            side = "R"  # sibling is right of current
        else:
            sibling_idx = idx - 1
            side = "L"  # sibling is left of current

        sibling = nodes[sibling_idx]

        depth_here = max_depth - level_no
        path.append(PathNode(depth=depth_here, side=side, sibling=sibling))

        # Move up to the parent index for the next level.
        idx //= 2

    root = levels[-1][0]
    return path, root


def parse_input_file(content: str) -> Tuple[int, int, List[bytes]]:
    '''
    Parses the input file content and returns (i, j, leaves).
        :param content: The input file content as a string.
        :return: A tuple of (i, j, leaves).
        :rtype: Tuple[int, int, List[bytes]]
    '''
    it = iter(_iter_nonempty_lines(content))
    try:
        i_line, i_str = next(it)
        j_line, j_str = next(it)
    except StopIteration as e:
        raise InputFormatError("Input must contain at least i, j, and one leaf.") from e

    i = _parse_int(i_str, context=f"i (line {i_line})")
    j = _parse_int(j_str, context=f"j (line {j_line})")

    leaves: List[bytes] = []
    for line_no, leaf_hex in it:
        leaves.append(_parse_hex_bytes(leaf_hex, context=f"leaf on line {line_no}"))

    if not leaves:
        raise InputFormatError("Input must contain at least one leaf after i and j.")

    return i, j, leaves


def main(argv: list[str] | None = None) -> int:
    #Main entry point for the full-node Merkle tree helper.
    parser = argparse.ArgumentParser(
        description="Build a SHA-1 Merkle tree and output the node-at-depth-j + root concatenation."
    )
    parser.add_argument("input_file", type=Path, help="Path to input file (i, j, then leaves).")
    parser.add_argument(
        "--print-path",
        action="store_true",
        help="Print the full Merkle path (leaf sibling first) to stderr.",
    )
    args = parser.parse_args(argv)

    content = args.input_file.read_text(encoding="utf-8")
    i, j, leaves = parse_input_file(content)

    path, root = compute_merkle_path(leaves, i)

    max_depth = len(build_merkle_levels(leaves)) - 1
    if j < 1 or j > max_depth:
        raise InputFormatError(
            f"Depth j out of range: j={j}. Valid range is 1..{max_depth} (root is depth 0)."
        )

    if args.print_path:
        for pn in path:
            print(f"{pn.side}{pn.sibling.hex()}", file=sys.stderr)

    try:
        node_at_j = next(pn for pn in path if pn.depth == j)
    except StopIteration as e:
        raise InputFormatError(f"No Merkle path node found at depth j={j}.") from e

    # Required output: concatenation of (node-at-j with L/R prefix) and (root hex)
    print(f"{node_at_j.side}{node_at_j.sibling.hex()}{root.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
