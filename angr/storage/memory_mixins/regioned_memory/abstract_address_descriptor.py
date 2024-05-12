from collections.abc import Generator

from claripy.vsa import StridedInterval


class AbstractAddressDescriptor:
    """
    AbstractAddressDescriptor describes a list of region+offset tuples. It provides a convenient way for accessing the
    cardinality (the total number of addresses) without enumerating or creating all addresses in static mode.
    """

    __slots__ = ("_regioned_addrs",)

    def __init__(self):
        self._regioned_addrs: list[tuple[str, StridedInterval]] = []

    def __len__(self) -> int:
        # this may raise an OverflowError if self.cardinality is greater than sys.maxint
        return self.cardinality

    def __iter__(self) -> Generator[tuple[str, StridedInterval], None, None]:
        yield from self._regioned_addrs

    @property
    def cardinality(self):
        n = 0
        for _, si in self._regioned_addrs:
            n += si.cardinality
        return n

    def add_regioned_address(self, region: str, addr: StridedInterval):
        self._regioned_addrs.append((region, addr))

    def clear(self):
        self._regioned_addrs.clear()
