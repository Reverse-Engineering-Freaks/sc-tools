"""Dump binary with HEX"""

import math


def __dump_binary_line(address: int, chunk: bytes, chunk_size: int):
    BYTES_PER_SEP = " "

    line = "0x"
    line += format(address, "08X")
    line += "    "
    line += chunk.hex(BYTES_PER_SEP).upper()
    padding = chunk_size - len(chunk)
    line += "   " * padding
    line += "    "
    for byte in chunk:
        if byte < 0x20 or 0x7E < byte:
            # Control character
            line += "."
            continue
        line += chr(byte)
    line += "\n"
    return line


def dump_binary(data: bytes, chunk_size=16) -> str:
    """Dump binary with HEX

    Args:
        data (bytes): Data
        chunk_size (int, optional): Chunk size. Defaults to 16.

    Returns:
        str: Binary dumped string
    """

    output = ""

    data_length = len(data)
    chunk_count = math.floor(data_length / chunk_size)
    fraction_length = data_length % chunk_size

    for i in range(chunk_count):
        address = chunk_size * i
        chunk: bytes = data[address : address + chunk_size]
        output += __dump_binary_line(address, chunk, chunk_size)

    if fraction_length == 0:
        return output[:-1]

    address = chunk_size * chunk_count
    fraction: bytes = data[address : address + fraction_length]
    output += __dump_binary_line(address, fraction, chunk_size)

    return output[:-1]
