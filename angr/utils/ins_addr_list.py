from __future__ import annotations

from collections.abc import Generator, Iterator


class InsAddrList:
    """
    A memory-efficient replacement for list[int] that stores instruction addresses as a base address plus a bytestring
    of instruction sizes (one byte per instruction).

    Address reconstruction: addr[i] = base_addr + sum(ins_sizes[0:i])

    For compatibility, this class exposes a list-like interface (iteration, indexing,
    length, membership testing, concatenation, etc.).
    """

    __slots__ = ("_addrs", "_base_addr", "_ins_sizes")

    def __init__(self, base_addr: int = 0, ins_sizes: bytes | bytearray | list[int] = b""):
        self._base_addr: int = base_addr
        # Set when the addresses are not a monotonically increasing run of byte-sized steps -- the
        # VM-deobfuscation passes stitch instructions from unrelated addresses into one IRSB. In
        # that case the compact representation cannot hold them and we keep the list verbatim.
        self._addrs: tuple[int, ...] | None = None
        if isinstance(ins_sizes, (list, bytearray)):
            self._ins_sizes: bytes = bytes(ins_sizes)
        else:
            self._ins_sizes: bytes = ins_sizes

    @classmethod
    def from_addr_list(cls, addrs) -> InsAddrList:
        """Construct an InsAddrList from a list/sequence of absolute instruction addresses."""
        if not addrs:
            return cls()
        base = addrs[0]
        n = len(addrs)
        if n == 1:
            return cls(base, b"\x00")
        sizes = bytearray(n)
        for i in range(n - 1):
            delta = addrs[i + 1] - addrs[i]
            if not 0 <= delta <= 255:
                return cls.from_explicit_addr_list(addrs)
            sizes[i] = delta
        # Last instruction size is unknown from addresses alone; store 0
        sizes[n - 1] = 0
        return cls(base, bytes(sizes))

    @classmethod
    def from_explicit_addr_list(cls, addrs) -> InsAddrList:
        """Keep the addresses verbatim; used when they do not form a compact increasing run."""
        obj = cls(addrs[0], bytes(len(addrs)))
        obj._addrs = tuple(addrs)
        return obj

    @property
    def base_addr(self) -> int:
        return self._base_addr

    @property
    def ins_sizes(self) -> bytes:
        return self._ins_sizes

    def __len__(self) -> int:
        return len(self._ins_sizes)

    def __bool__(self) -> bool:
        return len(self._ins_sizes) > 0

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            return [self[i] for i in range(*idx.indices(len(self._ins_sizes)))]
        if idx < 0:
            idx += len(self._ins_sizes)
        if idx < 0 or idx >= len(self._ins_sizes):
            raise IndexError(idx)
        if self._addrs is not None:
            return self._addrs[idx]
        return self._base_addr + sum(self._ins_sizes[:idx])

    def __iter__(self) -> Generator[int]:
        if self._addrs is not None:
            yield from self._addrs
            return
        addr = self._base_addr
        for size in self._ins_sizes:
            yield addr
            addr += size

    def __reversed__(self) -> Iterator[int]:
        return reversed(list(self))

    def __contains__(self, addr) -> bool:
        if not self._ins_sizes:
            return False
        if self._addrs is not None:
            return addr in self._addrs
        if addr < self._base_addr:
            return False
        cur = self._base_addr
        for size in self._ins_sizes:
            if cur == addr:
                return True
            cur += size
        return False

    def __eq__(self, other):
        if isinstance(other, InsAddrList):
            if self._addrs is not None or other._addrs is not None:
                return list(self) == list(other)
            return self._base_addr == other._base_addr and self._ins_sizes == other._ins_sizes
        if isinstance(other, list):
            if len(other) != len(self._ins_sizes):
                return False
            return all(a == b for a, b in zip(self, other))
        return NotImplemented

    def __add__(self, other) -> list[int]:
        if isinstance(other, (InsAddrList, list)):
            return list(self) + list(other)
        return NotImplemented

    def __radd__(self, other) -> list[int]:
        if isinstance(other, list):
            return other + list(self)
        return NotImplemented

    def __iadd__(self, other) -> list[int]:
        if isinstance(other, (InsAddrList, list)):
            return list(self) + list(other)
        return NotImplemented

    def __repr__(self) -> str:
        return repr(list(self))

    def __hash__(self):
        raise TypeError("unhashable type: 'InsAddrList'")

    def extend(self, other: InsAddrList) -> None:
        addrs = list(self) + list(other)
        if any(not 0 <= addrs[i + 1] - addrs[i] <= 255 for i in range(len(addrs) - 1)):
            self._addrs = tuple(addrs)
            self._ins_sizes = bytes(len(addrs))
            return
        self._addrs = None
        self._ins_sizes = bytes([addrs[i + 1] - addrs[i] for i in range(len(addrs) - 1)] + [0])

    def index(self, value, start=0, stop=None):
        if self._addrs is not None:
            return self._addrs.index(value, start, len(self._addrs) if stop is None else stop)
        if stop is None:
            stop = len(self._ins_sizes)
        addr = self._base_addr + sum(self._ins_sizes[:start])
        for i in range(start, min(stop, len(self._ins_sizes))):
            if addr == value:
                return i
            addr += self._ins_sizes[i]
        raise ValueError(f"{value} is not in InsAddrList")

    def count(self, value) -> int:
        return sum(1 for a in self if a == value)

    def copy(self) -> InsAddrList:
        if self._addrs is not None:
            return InsAddrList.from_explicit_addr_list(self._addrs)
        return InsAddrList(self._base_addr, self._ins_sizes)

    def __reduce__(self):
        if self._addrs is not None:
            return (InsAddrList.from_explicit_addr_list, (list(self._addrs),))
        # Pickle as (base_addr, list_of_sizes) for readability and compatibility
        return (InsAddrList, (self._base_addr, list(self._ins_sizes)))
