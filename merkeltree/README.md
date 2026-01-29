# Merkle Tree (SPV)

This folder contains a lightweight SPV-style verifier that computes a Merkle root from:
- a leaf node (already given as a hex hash), and
- a Merkle path (one sibling per line, prefixed with `L`/`R`).

Hash function: **SHA-1**

## Input format

- First non-empty line: leaf hex
- Each subsequent non-empty line: `L<hex>` or `R<hex>`
  - `L` means the sibling is the **left** child (so we hash `sibling || current`)
  - `R` means the sibling is the **right** child (so we hash `current || sibling`)

## Run

From the repo root:

```powershell
python .\merkeltree\spv_merkle_root.py .\merkeltree\example_input.txt
```

Expected output for the provided example:

```
6f51120bc17e224de27d3d27b32f05d0a5ffb376
```

## Part 2 (Full node)

The full-node helper builds a Merkle tree from the given leaves, generates the Merkle path for leaf index `i`,
and prints the required assessment string: the node at depth `j` (prefixed with `L`/`R`) concatenated with the
Merkle root.

Run:

```powershell
python .\merkeltree\fullnode_merkle.py .\merkeltree\example_fullnode_input.txt
```

Expected output for the provided example:

```
R8d3f164890509c6510cc9bc975cb978f0b872fbb1781a6ea9a22f67e8a09cb54bbdc6d99d0efc081
```

If you want to see the entire Merkle path (leaf sibling first), add `--print-path`
