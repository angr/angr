"""
LRU + LMDB spilling container for the ``XRefManager`` indexes (``xrefs_by_ins_addr`` and ``xrefs_by_dst``).

Each entry maps an address to a ``set`` of :class:`XRef`. The set is serialized as a pickled list of the
XRef identity/location fields (``ins_addr``, ``block_addr``, ``stmt_idx``, ``insn_op_idx``, ``dst``,
``type``). The volatile ``memory_data`` back-reference is intentionally not persisted: it is only consumed
after CFG recovery (angrdb serialization, code tagging) and is re-derivable from ``dst``; keeping it would
force each spilled XRef to drag along a private copy of a MemoryData object. The pickled bytes only ever
live in the ephemeral RuntimeDb.
"""

from __future__ import annotations

import pickle

from angr.knowledge_plugins.spilling_dict import SpillingObjectDict

from .xref import XRef


class SpillingXrefDict(SpillingObjectDict[int, "set[XRef]"]):
    """
    A sorted, ``defaultdict(set)``-like container of ``addr -> set[XRef]`` with LRU caching and LMDB
    spilling. Accessing a missing key auto-creates and stores an empty set (mirroring the ``XrefDict``
    ``__missing__`` behavior the manager relies on).
    """

    _VIVIFY = True

    def __init__(self, rtdb, cache_limit=None, db_batch_size=200, db_name="xrefs"):
        super().__init__(rtdb, cache_limit=cache_limit, db_batch_size=db_batch_size)
        # xrefs_by_ins_addr and xrefs_by_dst are two independent indexes; give them distinct LMDB names.
        self._DB_NAME = db_name

    def _make_default(self) -> set[XRef]:
        return set()

    def _serialize_value(self, value: set[XRef]) -> bytes:
        return pickle.dumps(
            [(x.ins_addr, x.block_addr, x.stmt_idx, x.insn_op_idx, x.dst, x.type) for x in value],
            protocol=pickle.HIGHEST_PROTOCOL,
        )

    def _deserialize_value(self, data: bytes) -> set[XRef]:
        result: set[XRef] = set()
        for ins_addr, block_addr, stmt_idx, insn_op_idx, dst, xref_type in pickle.loads(data):
            result.add(
                XRef(
                    ins_addr=ins_addr,
                    block_addr=block_addr,
                    stmt_idx=stmt_idx,
                    insn_op_idx=insn_op_idx,
                    dst=dst,
                    xref_type=xref_type,
                )
            )
        return result

    def _pickle_extra_state(self) -> dict:
        return {"db_name": self._DB_NAME}

    def _restore_extra_state(self, state: dict) -> None:
        self._DB_NAME = state.get("db_name", "xrefs")

    def _new_like(self) -> SpillingXrefDict:
        return SpillingXrefDict(
            self.rtdb, cache_limit=self._cache_limit, db_batch_size=self._db_batch_size, db_name=self._DB_NAME
        )

    def get_xrefs_in_range(self, start: int, end: int) -> set[XRef]:
        """Get a set of XRef objects whose key address falls in ``[start, end]``."""
        result: set[XRef] = set()
        for k in self._list.islice(self._list.bisect_left(start), self._list.bisect_right(end) + 1):
            result.update(self[k])
        return result
