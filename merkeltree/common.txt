'''
Common utilities and exceptions for Merkle tree operations.
'''
import hashlib
from typing import Iterable, Tuple


class InputFormatError(ValueError):
    '''
    Custom Exception raised for errors in the input file format.
    '''
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
        yield idx, line


def _sha1(data: bytes) -> bytes:
    '''
    Returns the SHA-1 hash of the given data.
        :param data: The input data to hash.
        :return: The SHA-1 hash of the data.
        :rtype: bytes
    '''
    return hashlib.sha1(data).digest()