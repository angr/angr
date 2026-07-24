"""
LRU + LMDB spilling containers for ``CFGModel.memory_data`` (a sorted ``addr -> MemoryData`` map) and
``CFGModel.insn_addr_to_memory_data``.

``MemoryData`` is serialized with :mod:`pickle` rather than its protobuf message on purpose: the protobuf
form is lossy (it drops ``max_size``, ``pointer_addr`` and ``content``), all of which are read and written
during ``CFGModel.tidy_data_references``. Pickle round-trips every field, which is required for
byte-identical CFG output when entries are spilled and reloaded mid-recovery. The pickled bytes only ever
live in the ephemeral RuntimeDb, so there is no on-disk format-stability concern.

``CFGModel.memory_data`` is the single owner of all MemoryData objects. ``insn_addr_to_memory_data``
(:class:`InsnAddrToMemoryDataMap`) stores only the referenced *data addresses* (plain ints) and looks the
objects up in ``memory_data`` on access; holding the objects themselves would pin every referenced
MemoryData resident regardless of what ``memory_data`` evicts.
"""

from __future__ import annotations

import pickle
from typing import TYPE_CHECKING

from angr.knowledge_plugins.spilling_dict import SpillingObjectDict

if TYPE_CHECKING:
    from .cfg_model import CFGModel
    from .memory_data import MemoryData

_no_entry = object()


class SpillingMemoryDataDict(SpillingObjectDict[int, "MemoryData"]):
    """
    A sorted, dict-like container of ``addr -> MemoryData`` with LRU caching and LMDB spilling.

    Drop-in compatible with the ``SortedDict`` that previously backed ``CFGModel.memory_data``: it supports
    item access, ``get``, ``keys``/``values``/``items`` (sorted), ``irange``, ``islice``, ``bisect_left``,
    ``bisect_right``, ``copy``, and iteration in sorted key order.
    """

    _DB_NAME = "memory_data"
    # MemoryData objects may be mutated in place through references held by callers (e.g. during
    # tidy_data_references), so a reloaded copy must never diverge from a still-live one.
    _CANONICAL_IDENTITY = True


class InsnAddrToMemoryDataMap(SpillingObjectDict[int, int]):
    """
    The ``instruction address -> MemoryData`` map, redesigned so that ``CFGModel.memory_data`` remains the
    single owner of MemoryData objects: internally each entry is just the referenced *data address* (a
    plain int, spilled to LMDB like every other entry), and the dict-style read API (``[]``, ``get``,
    ``values``, ``items``) materializes the MemoryData by looking the address up in the model's
    ``memory_data`` map. Assigning a MemoryData through ``__setitem__`` stores only its address.

    A key whose data address no longer exists in ``memory_data`` behaves as missing on read.
    """

    _DB_NAME = "insn_md_map"

    def __init__(self, rtdb, model: CFGModel | None = None, cache_limit=None, db_batch_size=200):
        super().__init__(rtdb, cache_limit=cache_limit, db_batch_size=db_batch_size)
        self._model: CFGModel | None = model

    def set_model(self, model: CFGModel) -> None:
        """(Re-)attach the owning CFGModel (e.g. after unpickling or copying)."""
        self._model = model

    def _serialize_value(self, value: int) -> bytes:
        return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)

    def _new_like(self) -> InsnAddrToMemoryDataMap:
        return InsnAddrToMemoryDataMap(
            self.rtdb, model=self._model, cache_limit=self._cache_limit, db_batch_size=self._db_batch_size
        )

    def _restore_extra_state(self, state: dict) -> None:
        self._model = None

    #
    # Raw (int) access
    #

    def set_by_addr(self, ins_addr: int, data_addr: int) -> None:
        """Record that the instruction at ``ins_addr`` references the memory data at ``data_addr``."""
        super().__setitem__(ins_addr, data_addr)

    def get_addr(self, ins_addr: int, default=None):
        """Get the referenced data address (an int) without materializing the MemoryData."""
        return super().get(ins_addr, default)

    #
    # Materializing read/write API
    #

    def _materialize(self, ins_addr: int, data_addr: int) -> MemoryData:
        assert self._model is not None
        md = self._model.memory_data.get(data_addr)
        if md is None:
            raise KeyError(ins_addr)
        return md

    def __getitem__(self, ins_addr: int) -> MemoryData:  # type: ignore[override]
        return self._materialize(ins_addr, super().__getitem__(ins_addr))

    def __setitem__(self, ins_addr: int, value) -> None:
        # accept a MemoryData (storing only its address) or a raw data address (e.g. while unpickling)
        super().__setitem__(ins_addr, value if isinstance(value, int) else value.addr)

    def get(self, ins_addr: int, default=None):
        data_addr = super().get(ins_addr, _no_entry)
        if data_addr is _no_entry:
            return default
        try:
            return self._materialize(ins_addr, data_addr)
        except KeyError:
            return default

    def values(self):  # type: ignore[override]
        for key in list(self._list):
            yield self[key]

    def items(self):  # type: ignore[override]
        for key in list(self._list):
            yield key, self[key]

    def pop(self, ins_addr: int, default=_no_entry):
        try:
            value = self[ins_addr]
        except KeyError:
            if default is _no_entry:
                raise
            del_present = ins_addr in self
            if del_present:
                del self[ins_addr]
            return default
        del self[ins_addr]
        return value
