from __future__ import annotations

from typing import Any, TypedDict, TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Unpack

    from angr.sim_type import SimType
    from angr.sim_variable import SimVariable


class TagDict(TypedDict, total=False):
    """
    Typed dict of tags for TaggedObject.
    """

    always_propagate: bool
    block_idx: int
    custom_string: bool
    deref_src_addr: int
    ins_addr: int
    is_prototype_guessed: bool
    keep_in_slice: bool
    orig_ins_addr: int
    reference_values: dict[SimType, Any]
    reference_variable_offset: int
    reference_variable: SimVariable
    reg_name: str
    struct_member_info: tuple[int, SimVariable, SimType]
    type: dict[str, SimType]
    vex_block_addr: int
    vex_stmt_idx: int
    write_size: int


class TaggedObject:
    """
    A class that takes tags.
    """

    __slots__ = (
        "_hash",
        "idx",
        "tags",
    )

    def __init__(self, idx: int | None, **kwargs: Unpack[TagDict]):
        self.tags: TagDict = kwargs
        self.idx = idx
        self._hash = None

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = self._hash_core()
        return self._hash

    def _hash_core(self):
        raise NotImplementedError
