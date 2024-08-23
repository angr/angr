import claripy
from angr.state_plugins.sim_action_object import SimActionObject

_Coerce = int | claripy.ast.bv.BV | SimActionObject

class DefaultMemory:
    SUPPORTS_CONCRETE_LOAD: bool
    id: str
    endness: str
    def store(
        self,
        addr: _Coerce,
        data: _Coerce | bytes,
        size: _Coerce | None = None,
        condition: claripy.ast.bool.Bool | None = None,
        **kwargs,
    ) -> None: ...
    def load(
        self,
        addr: _Coerce,
        size: _Coerce | None = None,
        condition: claripy.ast.bool.Bool | None = None,
        fallback: _Coerce | None = None,
        **kwargs,
    ) -> claripy.ast.bv.BV: ...
    def find(
        self, addr: _Coerce, what: _Coerce, max_search: int, default: _Coerce | None = None, **kwargs
    ) -> claripy.ast.bv.BV: ...
    def copy_contents(
        self, dst: _Coerce, src: _Coerce, size: _Coerce, condition: claripy.ast.bool.Bool | None = None, **kwargs
    ) -> None: ...
    def copy(self, memo: dict) -> DefaultMemory: ...
    @property
    def category(self) -> str: ...
    @property
    def variable_key_prefix(self) -> str: ...
    def merge(
        self,
        others: list[DefaultMemory],
        merge_conditions: list[claripy.ast.bool.Bool],
        common_ancestor: DefaultMemory | None = ...,
    ) -> bool: ...
    def permissions(self, addr: _Coerce, permissions: _Coerce | None = ..., **kwargs) -> None: ...
    def map_region(self, addr: _Coerce, length: int, permissions: _Coerce, init_zero: bool = ..., **kwargs) -> None: ...
    def unmap_region(self, addr: _Coerce, length: int, **kwargs) -> None: ...
    def concrete_load(self, addr: _Coerce, size: int, writing: bool = ..., **kwargs) -> memoryview: ...
    def erase(self, addr, size: int = ..., **kwargs) -> None: ...
    def replace_all(self, old: claripy.ast.BV, new: claripy.ast.BV): ...
