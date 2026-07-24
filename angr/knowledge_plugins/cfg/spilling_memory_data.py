"""
LRU + LMDB spilling container for ``CFGModel.memory_data`` (a sorted ``addr -> MemoryData`` map).

``MemoryData`` is serialized with :mod:`pickle` rather than its protobuf message on purpose: the protobuf
form is lossy (it drops ``max_size``, ``pointer_addr`` and ``content``), all of which are read and written
during ``CFGModel.tidy_data_references``. Pickle round-trips every field, which is required for
byte-identical CFG output when entries are spilled and reloaded mid-recovery. The pickled bytes only ever
live in the ephemeral RuntimeDb, so there is no on-disk format-stability concern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.knowledge_plugins.spilling_dict import SpillingObjectDict

if TYPE_CHECKING:
    pass


class SpillingMemoryDataDict(SpillingObjectDict[int, "MemoryData"]):
    """
    A sorted, dict-like container of ``addr -> MemoryData`` with LRU caching and LMDB spilling.

    Drop-in compatible with the ``SortedDict`` that previously backed ``CFGModel.memory_data``: it supports
    item access, ``get``, ``keys``/``values``/``items`` (sorted), ``irange``, ``islice``, ``bisect_left``,
    ``bisect_right``, ``copy``, and iteration in sorted key order.
    """

    _DB_NAME = "memory_data"
    # MemoryData objects are shared by reference (insn_addr_to_memory_data, XRef.memory_data) and mutated in
    # place during tidy_data_references, so a reloaded copy must never diverge from a still-live one.
    _CANONICAL_IDENTITY = True
