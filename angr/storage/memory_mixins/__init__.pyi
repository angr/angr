import claripy
from typing import Union, Optional, List
from angr.state_plugins.sim_action_object import SimActionObject

_Coerce = Union[int, claripy.ast.bv.BV, SimActionObject]

class DefaultMemory:
    SUPPORTS_CONCRETE_LOAD: bool
    id: str
    endness: str
    def store(
        self,
        addr: _Coerce,
        data: Union[_Coerce, bytes],
        size: Optional[_Coerce] = None,
        condition: Optional[claripy.ast.bool.Bool] = None,
        **kwargs,
    ) -> None: ...
    def load(
        self,
        addr: _Coerce,
        size: Optional[_Coerce] = None,
        condition: Optional[claripy.ast.bool.Bool] = None,
        fallback: Optional[_Coerce] = None,
        **kwargs,
    ) -> claripy.ast.bv.BV: ...
    def find(
        self, addr: _Coerce, what: _Coerce, max_search: int, default: Optional[_Coerce] = None, **kwargs
    ) -> claripy.ast.bv.BV: ...
    def copy_contents(
        self, dst: _Coerce, src: _Coerce, size: _Coerce, condition: Optional[claripy.ast.bool.Bool] = None, **kwargs
    ) -> None: ...
    def copy(self, memo: dict) -> DefaultMemory: ...
    @property
    def category(self) -> str: ...
    @property
    def variable_key_prefix(self) -> str: ...
    def merge(
        self,
        others: List[DefaultMemory],
        merge_conditions: List[claripy.ast.bool.Bool],
        common_ancestor: Optional[DefaultMemory] = ...,
    ) -> bool: ...
    def permissions(self, addr: _Coerce, permissions: Optional[_Coerce] = ..., **kwargs) -> None: ...
    def map_region(self, addr: _Coerce, length: int, permissions: _Coerce, init_zero: bool = ..., **kwargs) -> None: ...
    def unmap_region(self, addr: _Coerce, length: int, **kwargs) -> None: ...
    def concrete_load(self, addr: _Coerce, size: int, writing: bool = ..., **kwargs) -> memoryview: ...
    def erase(self, addr, size: int = ..., **kwargs) -> None: ...
    def replace_all(self, old: claripy.ast.BV, new: claripy.ast.BV): ...
