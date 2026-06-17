from __future__ import annotations

from typing import TYPE_CHECKING, Self, TypedDict

from angr.ailment.manager import Manager

if TYPE_CHECKING:
    from typing import Unpack

    from angr.sim_type import SimType


class TagDict(TypedDict, total=False):
    """
    Typed dict of tags for TaggedObject.
    """

    always_propagate: bool
    block_idx: int
    deref_src_addr: int
    extra_def: bool
    extra_defs: list[int]
    ins_addr: int
    is_prototype_guessed: bool
    keep_in_slice: bool
    orig_ins_addr: int
    reg_name: str
    type: dict[str, SimType]
    uninitialized: bool
    vex_block_addr: int
    vex_stmt_idx: int
    write_size: int
    outlining_artifact: bool


class TaggedObject:
    """
    A class that takes tags.
    """

    __slots__ = (
        "_hash",
        "idx",
        "tags",
    )

    def __init__(self, idx: int, **kwargs: Unpack[TagDict]):
        self.tags: TagDict = kwargs
        self.idx = idx
        self._hash = None

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = self._hash_core()
        return self._hash

    def _hash_core(self) -> int:
        raise NotImplementedError

    def copy(self) -> Self:
        raise NotImplementedError

    def deep_copy(self, manager: Manager) -> Self:
        raise NotImplementedError

    def _transfer_varmap[T: TaggedObject](self, new: T, manager: Manager) -> T:
        """
        Helper for deep_copy: when a manager carries a VariableMap, transfer this object's variable information to the
        freshly deep-copied object ``new`` (which has a new .idx). Returns ``new`` for convenient chaining.
        """
        if manager.variable_map is not None:
            manager.variable_map.transfer(self, new)
        return new
