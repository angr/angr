from __future__ import annotations


def decode_utf16_string(data: bytes) -> str:
    """
    Decode a UTF-16 encoded string from a bytes object in a resilient manner.

    :param data: The bytes object containing the UTF-16 encoded string.
    :param errors: The error handling scheme. Default is 'strict'.
                   Other options include 'ignore', 'replace', etc.
    :return: The decoded string.
    """
    if len(data) % 2 == 1:
        data = data[:-1]  # Trim off the last byte if the length is odd

    # If no BOM, try to decode as little-endian first
    try:
        return data.decode("utf-16-le")
    except UnicodeDecodeError:
        return "<utf16-decode-error>"
