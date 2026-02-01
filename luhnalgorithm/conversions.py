# conversion helpers. These are simple functions to convert between
# integers, hexadecimal strings, and byte arrays.
# Please note that this file is part of the luhn algorithm assignment.

import hashlib

def int_to_hash(num):
    """
    Converts an integer to a hexadecimal string representation, 
    removing the '0x' prefix.
    """
    return hex(num)[2:]

def hex_to_int(hex_str):
    """
    Converts a hexadecimal string back to an integer.
    """
    return int(hex_str, 16)

def int_to_bytes(num):
    """
    Converts an integer to a bytes object of length 4 using big-endian byte order.
    """
    return num.to_bytes(4, byteorder="big")

def bytes_to_int(byte_data):
    """
    Converts a bytes object to an integer using big-endian byte order.
    """
    return int.from_bytes(byte_data, byteorder="big")

def hex_to_bytes(hex_str):
    """
    Converts a hexadecimal string to a bytes object.
    """
    return bytes.fromhex(hex_str)

def bytes_to_hex(byte_data):
    """
    Converts a bytes object to a hexadecimal string.
    """
    return byte_data.hex()

def hash_bytes(byte_data):
    """
    Computes the SHA-256 hash of the input byte data and returns 
    the hexadecimal digest.
    """
    return hashlib.sha256(byte_data).hexdigest()
    