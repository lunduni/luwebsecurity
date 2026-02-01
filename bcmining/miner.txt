"""
This program is a Block Chain Mining assignment helper.
Written by:
    Prince Samuel Kyeremanteng
    Hadar Eklund

It fetches a starter blockchain from the course server, mines additional blocks so
that each block hash begins with a 4-hex-digit seed, then submits the extended
chain back to the server.

Block hash definition (must match assignment):
sha256(f"{index}-{timestamp}-{data}-{prevhash}-{nonce}")

Usage examples (PowerShell):
    python bcmining\\miner.py --seed 0a72
    python bcmining\\miner.py --seed 0a72 --no-submit
    python bcmining\\miner.py --seed random

"""

# We leveraged on these python standard libraries:
# this allows postponed evaluation of annotations
from __future__ import annotations

# for parsing arguments in the command line
import argparse
# for hash related functions
import hashlib
# for json encoding/decoding
import json
# for random nonce (number) generation
import random
# for regular expressions
import re
# for system related functions
import sys
# for time related functions
import time
# for URL requests handling
import urllib.error
import urllib.parse
import urllib.request
# for typing annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


# consts
DEFAULT_SERVER = "http://igor.eit.lth.se:6003"
TIMESTAMP_FORMAT = "%Y-%m-%d, %H:%M:%S"


def now_timestamp() -> str:
    '''
    Returns the current local time formatted as a timestamp string.
    '''
    return time.strftime(TIMESTAMP_FORMAT, time.localtime())


def compute_hash(index: int, timestamp: str, data: str, prevhash: str, nonce: int) -> str:
    '''
    Computes the SHA-256 hash of the block components.
    payload = f"{index}-{timestamp}-{data}-{prevhash}-{nonce}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
    '''
    payload = f"{index}-{timestamp}-{data}-{prevhash}-{nonce}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def is_valid_seed(seed: str) -> bool:
    '''ensures that the seed is exactly 4 hex digits'''
    if len(seed) != 4:
        return False
    try:
        int(seed, 16)
        return True
    except ValueError:
        return False


def fetch_chain(server: str, seed: str) -> List[Dict[str, Any]]:
    url = f"{server.rstrip('/')}/generate?" + urllib.parse.urlencode({"seed": seed})
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch chain from server: {e}") from e

    # raw server response.
    raw = raw.strip()

    def _try_parse_json(text: str) -> Any:
        parsed_any = json.loads(text)
        if isinstance(parsed_any, str):
            # just to be double sure!
            parsed_any = json.loads(parsed_any)
        return parsed_any

    try:
        parsed = _try_parse_json(raw)
    except json.JSONDecodeError:
        # my lazy way of extracting the JSON array from the response. lol
        start = raw.find("[{")
        end = raw.rfind("}]")
        candidate = None
        if start != -1 and end != -1 and end > start:
            candidate = raw[start : end + 2]
        else:
            # use re to look for an array that starts with objects.
            m = re.search(r"\[\s*\{.*\}\s*\]", raw, flags=re.DOTALL)
            if m:
                candidate = m.group(0)

        if not candidate:
            raise RuntimeError(
                "Server response was not JSON and no JSON array could be extracted. "
                f"First 200 chars: {raw[:200]!r}"
            )

        try:
            parsed = _try_parse_json(candidate)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                "Extracted a JSON-looking array from the server response but it did not parse. "
                f"First 200 chars of extracted text: {candidate[:200]!r}"
            ) from e

    if not isinstance(parsed, list):
        raise RuntimeError(f"Expected a JSON list blockchain; got {type(parsed).__name__}.")

    return parsed


def validate_chain(chain: List[Dict[str, Any]], seed: str) -> Tuple[bool, str]:
    # Validates the entire chain.
    if not chain:
        return False, "Chain is empty"

    for i, blk in enumerate(chain):
        required = {"block_id", "time_stamp", "metadata", "prev_hash", "nonce", "curr_hash"}
        missing = required - set(blk.keys())
        if missing:
            return False, f"Block {i} missing keys: {sorted(missing)}"

        try:
            block_id = int(blk["block_id"])
            timestamp = str(blk["time_stamp"])
            metadata = str(blk["metadata"])
            prev_hash = str(blk["prev_hash"])
            nonce = int(blk["nonce"])
            curr_hash = str(blk["curr_hash"])
        except Exception as e:
            return False, f"Block {i} has invalid field types: {e}"

        expected = compute_hash(block_id, timestamp, metadata, prev_hash, nonce)
        if expected != curr_hash:
            return False, f"Block {i} curr_hash mismatch"

        # Link integrity for i>0.
        if i > 0:
            prev = chain[i - 1]
            if str(prev["curr_hash"]) != prev_hash:
                return False, f"Block {i} prev_hash does not match previous curr_hash"

        # genesis blocks are sometimes allowed to not satisfy the seed rule.
        # (I had this discussion with Paul in class the other day).
        if i >= 1 and not curr_hash.startswith(seed):
            return False, f"Block {i} hash does not start with seed {seed}"

        if block_id != i:
            return False, f"Block {i} has block_id={block_id}, expected {i}"

    return True, "ok"


@dataclass(frozen=True)
class MineResult:
    block: Dict[str, Any]
    attempts: int
    seconds: float


def mine_block(index: int, prevhash: str, seed: str, metadata: str, start_nonce: int | None = None) -> MineResult:
    '''
    The main mining loop.
    Tries different nonce values until a hash starting with the seed is found.
    '''
    timestamp = now_timestamp()

    nonce = start_nonce if start_nonce is not None else random.randrange(0, 1 << 31)
    attempts = 0
    start = time.time()

    while True:
        attempts += 1
        curr_hash = compute_hash(index, timestamp, metadata, prevhash, nonce)
        if curr_hash.startswith(seed):
            end = time.time()
            return MineResult(
                block={
                    "block_id": index,
                    "time_stamp": timestamp,
                    "metadata": metadata,
                    "prev_hash": prevhash,
                    "nonce": nonce,
                    "curr_hash": curr_hash,
                },
                attempts=attempts,
                seconds=(end - start),
            )
        nonce += 1


def extend_chain(chain: List[Dict[str, Any]], seed: str, additional_blocks: int) -> List[Dict[str, Any]]:
    # Make a deep copy of the existing chain to extend.
    extended = [dict(b) for b in chain]

    for _ in range(additional_blocks):
        next_index = len(extended)
        prev_hash = str(extended[-1]["curr_hash"])
        metadata = f"block{next_index}"
        result = mine_block(next_index, prev_hash, seed, metadata)
        extended.append(result.block)
        print(
            f"Mined block {next_index}: nonce={result.block['nonce']} attempts={result.attempts} time={result.seconds:.3f}s hash={result.block['curr_hash']}"
        )

    ok, msg = validate_chain(extended, seed)
    if not ok:
        raise RuntimeError(f"Extended chain failed validation: {msg}")

    return extended


def submit_chain(server: str, seed: str, chain: List[Dict[str, Any]]) -> str:
    # Submit the extended chain to the server.
    chain_json = json.dumps(chain, separators=(",", ":"))

    # Server expects GET with query params.
    url = f"{server.rstrip('/')}/submit?" + urllib.parse.urlencode({"seed": seed, "chain": chain_json})
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            raw = resp.read().decode("utf-8").strip()
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to submit chain: {e}") from e

    # Response may be raw hash/0 or an HTML wrapper. Extract the most useful token.
    m = re.search(r"\b[0-9a-f]{64}\b", raw, flags=re.IGNORECASE)
    if m:
        return m.group(0)
    m0 = re.search(r"\b0\b", raw)
    if m0 and raw.strip() == "0":
        return "0"
    return raw


def parse_args(argv: List[str]) -> argparse.Namespace:
    # Parses command line arguments.
    p = argparse.ArgumentParser(description="Blockchain mining assignment helper")
    p.add_argument("--seed", required=True, help="4 hex digits (0000-ffff) or 'random'")
    p.add_argument("--server", default=DEFAULT_SERVER, help=f"Server base URL (default: {DEFAULT_SERVER})")
    p.add_argument("--additional-blocks", type=int, default=3, help="How many blocks to mine (default: 3)")
    p.add_argument("--no-submit", action="store_true", help="Mine but do not submit")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    # This is where the main execution starts.
    args = parse_args(argv)

    seed = args.seed.lower()
    if seed == "random":
        seed = f"{random.randrange(0, 0x10000):04x}"
        print(f"Chosen random seed: {seed}")

    if not is_valid_seed(seed):
        print("Seed must be exactly 4 hex digits (0000-ffff) or 'random'.", file=sys.stderr)
        return 2

    chain = fetch_chain(args.server, seed)
    print(f"Fetched chain length={len(chain)}")

    ok, msg = validate_chain(chain, seed)
    if not ok:
        # The server-provided chain might not satisfy our stricter checks on genesis.
        # If it fails ONLY on the difficulty rule for block 0, still proceed.
        if msg.startswith("Block 0") and "seed" in msg:
            print(f"Warning: genesis block does not match seed rule ({msg}); proceeding.")
        else:
            print(f"Fetched chain failed validation: {msg}", file=sys.stderr)
            return 1

    extended = extend_chain(chain, seed, args.additional_blocks)
    print(f"Extended chain length={len(extended)}")

    if args.no_submit:
        print("--no-submit set; skipping submission.")
        return 0

    reply = submit_chain(args.server, seed, extended)
    print(f"Server reply: {reply}")
    return 0


if __name__ == "__main__":
    # Entry point.
    # we pass sys.argv[1:] to skip the script name.
    raise SystemExit(main(sys.argv[1:]))
