"""
LRU + LMDB spilling containers for the ``XRefManager`` indexes.

``xrefs_by_ins_addr`` (:class:`SpillingXrefDict`) is the single owner of all XRef objects: each entry maps
an instruction address to a ``set`` of :class:`XRef`. The set is serialized as a pickled list of the XRef
identity/location fields (``ins_addr``, ``block_addr``, ``stmt_idx``, ``insn_op_idx``, ``dst``, ``type``),
which together fully describe an XRef (the corresponding MemoryData, if any, is the model's ``memory_data``
entry at ``dst``). The pickled bytes only ever live in the ephemeral RuntimeDb.

``xrefs_by_dst`` (:class:`SpillingXrefDstIndex`) holds no XRef objects at all -- only the instruction
addresses (plain ints) that reference each destination. Holding the objects themselves would pin every
XRef resident regardless of what the owner map evicts (a Python object is only freed once *all* containers
referencing it drop their entries, and two independently-evicting LRU caches essentially never do so at the
same time). Its read API materializes ``set[XRef]`` on demand from the owner map.
"""

from __future__ import annotations

import pickle

from angr.knowledge_plugins.spilling_dict import SpillingObjectDict

from .xref import XRef

_no_entry = object()


class SpillingXrefDict(SpillingObjectDict[int, "set[XRef]"]):
    """
    A sorted, ``defaultdict(set)``-like container of ``addr -> set[XRef]`` with LRU caching and LMDB
    spilling. Accessing a missing key auto-creates and stores an empty set (mirroring the ``XrefDict``
    ``__missing__`` behavior the manager relies on).
    """

    _VIVIFY = True

    def __init__(self, rtdb, cache_limit=None, db_batch_size=200, db_name="xrefs"):
        super().__init__(rtdb, cache_limit=cache_limit, db_batch_size=db_batch_size)
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


class SpillingXrefDstIndex(SpillingObjectDict[int, "set[int]"]):
    """
    The ``dst -> xrefs`` secondary index. Internally each entry is the set of *instruction addresses*
    (plain ints) referencing the destination; the owning ``xrefs_by_ins_addr`` map is the only container
    that holds XRef objects. The dict-style read API (``[]``, ``get``, ``values``, ``items``,
    ``get_xrefs_in_range``) materializes ``set[XRef]`` on demand by loading the owner's entries for the
    recorded instruction addresses and filtering on ``dst``, so existing consumers keep seeing sets of
    XRefs. Materialized sets are fresh snapshots -- do not mutate them to modify the index.

    An instruction-address entry may become stale when an xref is replaced (e.g. the Offset-overwrite
    logic in ``XRefManager.add_xref``); materialization is self-healing in that case, since the owner no
    longer yields a matching XRef for it.
    """

    _VIVIFY = True
    _DB_NAME = "xrefs_by_dst"

    def __init__(self, rtdb, owner: SpillingXrefDict | None = None, cache_limit=None, db_batch_size=200):
        super().__init__(rtdb, cache_limit=cache_limit, db_batch_size=db_batch_size)
        self._owner: SpillingXrefDict | None = owner

    def set_owner(self, owner: SpillingXrefDict) -> None:
        """(Re-)attach the owning by-instruction-address map (e.g. after unpickling or copying)."""
        self._owner = owner

    def _make_default(self) -> set[int]:
        return set()

    def _serialize_value(self, value: set[int]) -> bytes:
        return pickle.dumps(sorted(value), protocol=pickle.HIGHEST_PROTOCOL)

    def _deserialize_value(self, data: bytes) -> set[int]:
        return set(pickle.loads(data))

    def _new_like(self) -> SpillingXrefDstIndex:
        return SpillingXrefDstIndex(
            self.rtdb, owner=self._owner, cache_limit=self._cache_limit, db_batch_size=self._db_batch_size
        )

    def _restore_extra_state(self, state: dict) -> None:
        self._owner = None

    #
    # Raw (int-set) access, used by XRefManager
    #

    def add_ref(self, dst: int, ins_addr: int) -> None:
        """Record that the instruction at ``ins_addr`` references ``dst``."""
        raw: set[int] = super().__getitem__(dst)
        raw.add(ins_addr)

    #
    # Materializing read API
    #

    def _materialize(self, dst: int, ins_addrs: set[int]) -> set[XRef]:
        assert self._owner is not None
        result: set[XRef] = set()
        for ins_addr in ins_addrs:
            for xref in self._owner.get(ins_addr, ()):
                if xref.dst == dst:
                    result.add(xref)
        return result

    def __getitem__(self, dst: int) -> set[XRef]:  # type: ignore[override]
        return self._materialize(dst, super().__getitem__(dst))

    def get(self, dst: int, default=None):
        raw = super().get(dst, _no_entry)
        if raw is _no_entry:
            return default
        return self._materialize(dst, raw)

    def values(self):  # type: ignore[override]
        for key in list(self._list):
            yield self[key]

    def items(self):  # type: ignore[override]
        for key in list(self._list):
            yield key, self[key]

    def get_xrefs_in_range(self, start: int, end: int) -> set[XRef]:
        """Get a set of XRef objects whose destination falls in ``[start, end]``."""
        result: set[XRef] = set()
        for k in list(self._list.islice(self._list.bisect_left(start), self._list.bisect_right(end) + 1)):
            result.update(self[k])
        return result
