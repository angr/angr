# pylint:disable=no-member
from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping

from angr.protos import cfg_pb2
from angr.rustylib.memory_data import MemoryDataStore
from angr.serializable import Serializable


class MemoryDataSort:
    Unspecified = None
    Unknown = "unknown"
    Integer = "integer"
    PointerArray = "pointer-array"
    String = "string"
    UnicodeString = "unicode"
    SegmentBoundary = "segment-boundary"
    CodeReference = "code reference"
    GOTPLTEntry = "GOT PLT Entry"
    ELFHeader = "elf-header"
    FloatingPoint = "fp"  # the size is determined by the MemoryData itself
    Alignment = "alignment"
    PEImportDirectory = "pe-import-directory"
    PEExportDirectory = "pe-export-directory"
    PEDelayImportDirectory = "pe-delay-import-directory"
    EHFuncInfo = "eh-funcinfo"
    EHUnwindMapEntry = "eh-unwindmapentry"
    EH4ScopeTable = "eh4-scopetable"
    EHTryBlockMap = "eh-tryblockmap"
    EHHandlerType = "eh-handlertype"


_SORT_TO_IDX = {
    MemoryDataSort.Unspecified: cfg_pb2.MemoryData.Unspecified,
    MemoryDataSort.Unknown: cfg_pb2.MemoryData.UnknownDataType,
    MemoryDataSort.Integer: cfg_pb2.MemoryData.Integer,
    MemoryDataSort.PointerArray: cfg_pb2.MemoryData.PointerArray,
    MemoryDataSort.String: cfg_pb2.MemoryData.String,
    MemoryDataSort.UnicodeString: cfg_pb2.MemoryData.UnicodeString,
    MemoryDataSort.SegmentBoundary: cfg_pb2.MemoryData.SegmentBoundary,
    MemoryDataSort.CodeReference: cfg_pb2.MemoryData.CodeReference,
    MemoryDataSort.GOTPLTEntry: cfg_pb2.MemoryData.GOTPLTEntry,
    MemoryDataSort.ELFHeader: cfg_pb2.MemoryData.ELFHeader,
    MemoryDataSort.FloatingPoint: cfg_pb2.MemoryData.FloatingPoint,
    MemoryDataSort.Alignment: cfg_pb2.MemoryData.Alignment,
    MemoryDataSort.PEImportDirectory: cfg_pb2.MemoryData.PEImportDirectory,
    MemoryDataSort.PEExportDirectory: cfg_pb2.MemoryData.PEExportDirectory,
    MemoryDataSort.PEDelayImportDirectory: cfg_pb2.MemoryData.PEDelayImportDirectory,
    MemoryDataSort.EHFuncInfo: cfg_pb2.MemoryData.EHFuncInfo,
    MemoryDataSort.EHUnwindMapEntry: cfg_pb2.MemoryData.EHUnwindMapEntry,
    MemoryDataSort.EH4ScopeTable: cfg_pb2.MemoryData.EH4ScopeTable,
    MemoryDataSort.EHTryBlockMap: cfg_pb2.MemoryData.EHTryBlockMap,
    MemoryDataSort.EHHandlerType: cfg_pb2.MemoryData.EHHandlerType,
}

_IDX_TO_SORT = {v: k for k, v in _SORT_TO_IDX.items()}

MEMORY_DATA_SORTS = set(_SORT_TO_IDX)


class MemoryData(Serializable):
    """
    MemoryData describes the syntactic content of a single address of memory.

    `reference_size` reflects the size of `content`. It can be different from `size`, which is the actual size of the
    memory data item in memory. The intended way to get the actual content in memory is `self.content[:self.size]`.

    A MemoryData is either detached (its fields live on the object) or a view over the record at `_key` in a
    `MemoryDataStore` (``_store``), which is how a `CFGModel` holds its memory data. `MemoryDataDict` attaches an
    object when it is stored and detaches it (copying the fields back) before its record is removed or overwritten.
    """

    __slots__ = (
        "_content",
        "_key",
        "_max_size",
        "_pointer_addr",
        "_reference_size",
        "_size",
        "_sort",
        "_store",
        "addr",
    )

    def __init__(
        self,
        address: int,
        size: int | None,
        sort: str | None,  # temporary type
        pointer_addr: int | None = None,
        max_size: int | None = None,
        reference_size: int | None = None,
    ):
        self.addr: int = address
        self._store: MemoryDataStore | None = None
        self._key: int = address
        self._size: int | None = size
        self._reference_size: int | None = reference_size
        self._sort: str | None = sort
        self._max_size: int | None = max_size
        self._pointer_addr: int | None = pointer_addr
        self._content: bytes | None = None

    @classmethod
    def _view(cls, store: MemoryDataStore, addr: int) -> MemoryData:
        md = cls.__new__(cls)
        md.addr = addr
        md._store = store
        md._key = addr
        return md

    def _fields(self) -> tuple:
        """(size, reference_size, sort, max_size, pointer_addr, content)"""
        store = self._store
        if store is not None:
            return store.fields(self._key)
        return self._size, self._reference_size, self._sort, self._max_size, self._pointer_addr, self._content

    def _attach(self, store: MemoryDataStore, key: int) -> None:
        store.set(key, *self._fields())
        self._store = store
        self._key = key

    def _detach(self) -> None:
        store = self._store
        if store is None:
            return
        if self._key in store:
            (
                self._size,
                self._reference_size,
                self._sort,
                self._max_size,
                self._pointer_addr,
                self._content,
            ) = store.fields(self._key)
        self._store = None

    @property
    def size(self) -> int | None:
        store = self._store
        return self._size if store is None else store.size(self._key)

    @size.setter
    def size(self, value: int | None) -> None:
        store = self._store
        if store is None:
            self._size = value
        else:
            store.set_size(self._key, value)

    @property
    def reference_size(self) -> int | None:
        store = self._store
        return self._reference_size if store is None else store.reference_size(self._key)

    @reference_size.setter
    def reference_size(self, value: int | None) -> None:
        store = self._store
        if store is None:
            self._reference_size = value
        else:
            store.set_reference_size(self._key, value)

    @property
    def sort(self) -> str | None:
        store = self._store
        return self._sort if store is None else store.sort(self._key)

    @sort.setter
    def sort(self, value: str | None) -> None:
        store = self._store
        if store is None:
            self._sort = value
        else:
            store.set_sort(self._key, value)

    @property
    def max_size(self) -> int | None:
        store = self._store
        return self._max_size if store is None else store.max_size(self._key)

    @max_size.setter
    def max_size(self, value: int | None) -> None:
        store = self._store
        if store is None:
            self._max_size = value
        else:
            store.set_max_size(self._key, value)

    @property
    def pointer_addr(self) -> int | None:
        store = self._store
        return self._pointer_addr if store is None else store.pointer_addr(self._key)

    @pointer_addr.setter
    def pointer_addr(self, value: int | None) -> None:
        store = self._store
        if store is None:
            self._pointer_addr = value
        else:
            store.set_pointer_addr(self._key, value)

    @property
    def content(self) -> bytes | None:
        store = self._store
        return self._content if store is None else store.content(self._key)

    @content.setter
    def content(self, value: bytes | None) -> None:
        store = self._store
        if store is None:
            self._content = value
        else:
            store.set_content(self._key, None if value is None else bytes(value))

    def __getstate__(self):
        if self._store is not None:
            return {"addr": self.addr, "_store": self._store, "_key": self._key}
        return {
            "addr": self.addr,
            "size": self._size,
            "reference_size": self._reference_size,
            "sort": self._sort,
            "max_size": self._max_size,
            "pointer_addr": self._pointer_addr,
            "content": self._content,
        }

    def __setstate__(self, state):
        # older pickles carry a (None, slots) pair
        if isinstance(state, tuple):
            state = state[1]
        self.addr = state["addr"]
        self._key = state.get("_key", self.addr)
        self._store = state.get("_store")
        self._size = state.get("size")
        self._reference_size = state.get("reference_size")
        self._sort = state.get("sort")
        self._max_size = state.get("max_size")
        self._pointer_addr = state.get("pointer_addr")
        self._content = state.get("content")

    def __copy__(self) -> MemoryData:
        size, reference_size, sort, max_size, pointer_addr, content = self._fields()
        md = MemoryData(
            self.addr, size, sort, pointer_addr=pointer_addr, max_size=max_size, reference_size=reference_size
        )
        md._content = content
        return md

    def __deepcopy__(self, memo) -> MemoryData:
        if self._store is None:
            return self.__copy__()
        # a view of the copied store, shared by everything copied along
        md = MemoryData._view(copy.deepcopy(self._store, memo), self._key)
        md.addr = self.addr
        return md

    def __eq__(self, other: MemoryData):
        return self.addr == other.addr and self._fields() == other._fields()

    __hash__ = None  # type: ignore[assignment]

    @property
    def address(self):
        return self.addr

    def __repr__(self):
        size = self.size
        return f"\\{self.address:#x}, {size if size is not None else 'size unknown'} bytes, {self.sort}/"

    def copy(self):
        """
        Make a copy of the MemoryData.

        :return: A copy of the MemoryData instance.
        :rtype: MemoryData
        """
        size, _, sort, max_size, pointer_addr, content = self._fields()
        s = MemoryData(self.address, size, sort, pointer_addr=pointer_addr, max_size=max_size)
        s.content = content

        return s

    def fill_content(self, loader):
        """
        Load data to fill self.content.

        :param loader:  The project loader.
        :return:        None
        """

        sort = self.sort
        if sort == MemoryDataSort.String:
            content = loader.memory.load(
                self.addr, self.reference_size if self.reference_size is not None else self.size
            )
            if content.endswith(b"\x00"):
                content = content.strip(b"\x00")
            self.content = content
        elif sort == MemoryDataSort.UnicodeString:
            content = loader.memory.load(
                self.addr, self.reference_size if self.reference_size is not None else self.size
            )
            if content.endswith(b"\x00\x00"):
                content = content[:-2]
            self.content = content
        else:
            # FIXME: Other types are not supported yet
            return

    #
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.MemoryData()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        cmsg.ea = self.addr
        if self.size is not None:
            cmsg.size = self.size
        if self.reference_size is not None:
            cmsg.reference_size = self.reference_size
        cmsg.type = _SORT_TO_IDX[self.sort]
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        return cls(
            cmsg.ea,
            cmsg.size if cmsg.HasField("size") else None,
            _IDX_TO_SORT[cmsg.type],
            reference_size=cmsg.reference_size if cmsg.HasField("reference_size") else None,
        )


_U64 = 1 << 64


def _is_addr(addr) -> bool:
    """Whether `addr` can be a key of the store (other keys are never in it)."""
    return type(addr) is int and 0 <= addr < _U64  # pylint:disable=unidiomatic-typecheck


class MemoryDataDict:
    """
    `CFGModel.memory_data`: the address-sorted MemoryData records of a model in a Rust `MemoryDataStore`, with the
    mapping API of the `SortedDict` it replaces. Values are `MemoryData` views; a view object stays the same for as
    long as its record exists.
    """

    __slots__ = ("_store", "_views")

    def __init__(self, items: Mapping[int, MemoryData] | None = None):
        self._store = MemoryDataStore()
        self._views: dict[int, MemoryData] = {}
        if items is not None:
            for addr, md in items.items():
                self[addr] = md

    @property
    def store(self) -> MemoryDataStore:
        return self._store

    def _view(self, addr: int) -> MemoryData:
        view = self._views.get(addr)
        if view is None:
            view = MemoryData._view(self._store, addr)
            self._views[addr] = view
        return view

    def __getitem__(self, addr: int) -> MemoryData:
        view = self._views.get(addr)
        if view is not None:
            return view
        if not _is_addr(addr) or addr not in self._store:
            raise KeyError(addr)
        view = MemoryData._view(self._store, addr)
        self._views[addr] = view
        return view

    def __setitem__(self, addr: int, md: MemoryData) -> None:
        if not isinstance(md, MemoryData):
            raise TypeError("MemoryDataDict values must be MemoryData instances")
        store = self._store
        old = self._views.pop(addr, None)
        if old is md and md._store is store:
            self._views[addr] = md
            return
        if old is not None:
            old._detach()
        if md._store is None:
            md._attach(store, addr)
        else:
            # attached to another record; the record is copied, the object stays with its own store
            store.set(addr, *md._fields())
            md = MemoryData._view(store, addr)
        self._views[addr] = md

    def __delitem__(self, addr: int) -> None:
        if not _is_addr(addr) or addr not in self._store:
            raise KeyError(addr)
        view = self._views.pop(addr, None)
        if view is not None:
            view._detach()
        self._store.remove(addr)

    def __contains__(self, addr) -> bool:
        return _is_addr(addr) and addr in self._store

    def __len__(self) -> int:
        return len(self._store)

    def __bool__(self) -> bool:
        return len(self._store) > 0

    def __iter__(self) -> Iterator[int]:
        return iter(self._store.addrs())

    def __eq__(self, other) -> bool:
        if not isinstance(other, (MemoryDataDict, Mapping)):
            return NotImplemented
        return len(self) == len(other) and all(a in other and other[a] == md for a, md in self.items())

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"<MemoryDataDict with {len(self)} entries>"

    def keys(self) -> list[int]:
        return self._store.addrs()

    def values(self) -> list[MemoryData]:
        view = self._view
        return [view(a) for a in self._store.addrs()]

    def items(self) -> list[tuple[int, MemoryData]]:
        view = self._view
        return [(a, view(a)) for a in self._store.addrs()]

    def get(self, addr: int, default=None):
        if not _is_addr(addr) or addr not in self._store:
            return default
        return self._view(addr)

    def pop(self, addr: int, *default):
        if addr not in self:
            if default:
                return default[0]
            raise KeyError(addr)
        md = self[addr]
        del self[addr]
        return md

    def setdefault(self, addr: int, default: MemoryData) -> MemoryData:
        if addr not in self:
            self[addr] = default
        return self[addr]

    def update(self, other: Mapping[int, MemoryData]) -> None:
        for addr, md in other.items():
            self[addr] = md

    def clear(self) -> None:
        for view in self._views.values():
            view._detach()
        self._views.clear()
        self._store.clear()

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False) -> Iterator[int]:
        """`SortedDict.irange`: the addresses in [minimum, maximum]."""
        if (minimum is not None and minimum >= _U64) or (maximum is not None and maximum < 0):
            return iter(())
        if minimum is not None and minimum < 0:
            minimum, inclusive = None, (True, inclusive[1])
        if maximum is not None and maximum >= _U64:
            maximum, inclusive = None, (inclusive[0], True)
        return iter(self._store.irange(minimum, maximum, inclusive, reverse))

    def bisect_left(self, addr: int) -> int:
        return len(list(self.irange(None, addr, (True, False))))

    def bisect_right(self, addr: int) -> int:
        return len(list(self.irange(None, addr, (True, True))))

    def peekitem(self, index: int = -1) -> tuple[int, MemoryData]:
        addr = self._store.addrs()[index]
        return addr, self._view(addr)

    def copy(self) -> MemoryDataDict:
        """A copy with its own records; views are not shared."""
        d = MemoryDataDict()
        d._store = self._store.copy()
        return d

    __copy__ = copy

    def __deepcopy__(self, memo) -> MemoryDataDict:
        d = MemoryDataDict()
        d._store = copy.deepcopy(self._store, memo)
        d._views = {addr: copy.deepcopy(view, memo) for addr, view in self._views.items()}
        return d

    def __getstate__(self):
        return {"store": self._store, "views": self._views}

    def __setstate__(self, state):
        self._store = state["store"]
        self._views = state["views"]

    def serialize_records(self) -> list:
        """MemoryData protobuf messages of every record, by address."""
        msgs = []
        for addr, size, reference_size, sort, _, _ in self._store.records():
            cmsg = cfg_pb2.MemoryData()
            cmsg.ea = addr
            if size is not None:
                cmsg.size = size
            if reference_size is not None:
                cmsg.reference_size = reference_size
            cmsg.type = _SORT_TO_IDX[sort]
            msgs.append(cmsg)
        return msgs
