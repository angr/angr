from __future__ import annotations
from .flirt_function import FlirtFunction


class FlirtModule:
    """
    Describes a module in a FLIRT signature.
    """

    __slots__ = ("crc", "crc_len", "length", "pub_funcs", "ref_funcs", "tail_bytes")

    def __init__(
        self,
        length: int,
        crc_len: int,
        crc: int,
        pub_funcs: list[FlirtFunction],
        ref_funcs: list[FlirtFunction],
        tail_bytes: list[tuple[int, int]],
    ):
        self.length = length
        self.crc_len = crc_len
        self.crc = crc  # CRC16
        self.pub_funcs = pub_funcs
        self.ref_funcs = ref_funcs
        self.tail_bytes = tail_bytes

    def __repr__(self) -> str:
        return (
            f"<FlirtModule: length={self.length}, crc_len={self.crc_len}, crc={self.crc}, "
            f"pub_funcs={self.pub_funcs}, ref_funcs={self.ref_funcs}, tail_bytes={self.tail_bytes}>"
        )
