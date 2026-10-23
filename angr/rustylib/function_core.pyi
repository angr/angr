from typing import Any, Self

from .function_graph import FunctionGraph

class FunctionCore:
    """
    The plain-data state of a Function: address, names, flags, returning status, dirty bookkeeping and the
    FunctionGraph. Attribute names are those of the former Function slots.
    """

    addr: int
    _name: str
    is_default_name: bool
    previous_names: list[str]
    binary_name: str | None
    _from_signature: str | None
    _prototype_libname: str | None
    _is_syscall: bool
    _is_simprocedure: bool
    _is_plt: bool
    _is_alignment: bool
    _returning: bool | None
    normalized: bool
    ran_cca: bool
    bp_on_stack: bool
    retaddr_on_stack: bool
    _dirty: bool
    meta_only: bool
    evicted: bool
    _graph: FunctionGraph | None
    is_plt: bool
    is_simprocedure: bool
    is_syscall: bool
    is_alignment: bool

    def __new__(cls, *args: Any, **kwargs: Any) -> Self: ...
    @property
    def name(self) -> str: ...
    @property
    def returning(self) -> bool | None: ...
    @property
    def from_signature(self) -> str | None: ...
    @property
    def prototype_libname(self) -> str | None: ...
    @property
    def dirty(self) -> bool: ...
    def mark_dirty(self) -> None: ...
    def _add_previous_name(self, name: str) -> None: ...
    def _core_state(self) -> dict[str, Any]: ...
