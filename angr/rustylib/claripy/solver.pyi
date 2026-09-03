"""Type stubs for ``angr.rustylib.claripy.solver``."""

from collections.abc import Iterable, Sequence
from typing import Any

from angr.rustylib.claripy.ast.base import Base
from angr.rustylib.claripy.ast.bool import Bool
from angr.rustylib.claripy.ast.bv import BV

type _BoolLike = Bool | bool | int | BV

class Solver:
    timeout: int | None
    def __init__(self, timeout: int | None = None, track: bool = False) -> None: ...
    def blank_copy(self) -> Solver: ...
    @property
    def constraints(self) -> list[Bool]: ...
    @property
    def variables(self) -> set[str]: ...
    def split(self) -> list[Solver]: ...
    def branch(self) -> Solver: ...
    def merge(
        self,
        others: Sequence[Solver],
        merge_conditions: Sequence[Bool],
        common_ancestor: Solver | None = None,
    ) -> tuple[bool, Solver]: ...
    def add(self, exprs: _BoolLike | Iterable[_BoolLike]) -> list[Bool]: ...
    def simplify(self) -> None: ...
    def downsize(self) -> None: ...
    def to_smt2(self) -> str: ...
    def satisfiable(self, extra_constraints: Sequence[_BoolLike] | None = None, exact: bool | None = None) -> bool: ...
    def unsat_core(self, extra_constraints: Sequence[_BoolLike] | None = None) -> list[int]: ...
    def eval_to_ast(
        self,
        expr: Base,
        n: int,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> list[Base]: ...
    def eval(
        self,
        expr: Base,
        n: int,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> list[Any]: ...
    def batch_eval(
        self,
        exprs: Sequence[Base],
        n: int,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> list[tuple[Any, ...]]: ...
    def solution(
        self,
        expr: Base | bool | int,
        value: Any,
        extra_constraints: Sequence[Bool] | None = None,
        exact: bool | None = None,
    ) -> bool: ...
    def is_true(
        self,
        expr: _BoolLike,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> bool: ...
    def is_false(
        self,
        expr: _BoolLike,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> bool: ...
    def has_true(
        self,
        expr: Bool,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> bool: ...
    def has_false(
        self,
        expr: Bool,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
    ) -> bool: ...
    def min(
        self,
        expr: BV,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
        signed: bool = False,
    ) -> int: ...
    def max(
        self,
        expr: BV,
        extra_constraints: Sequence[_BoolLike] | None = None,
        exact: bool | None = None,
        signed: bool = False,
    ) -> int: ...
    def add_replacement(self, old: Base, new: Base) -> None: ...
    def clear_replacements(self) -> None: ...
    def __getstate__(self) -> tuple[Any, ...]: ...
    def __setstate__(self, state: tuple[Any, ...]) -> None: ...

class SolverConcrete(Solver):
    def __init__(self) -> None: ...

class SolverZ3(Solver):
    def __init__(self) -> None: ...

class SolverCacheless(Solver):
    def __init__(self, timeout: int | None = None, track: bool = False) -> None: ...

class SolverVSA(Solver):
    def __init__(self) -> None: ...

class SolverHybrid(Solver):
    def __init__(self, timeout: int | None = None, track: bool = False, approximate_first: bool = False) -> None: ...

class SolverReplacement(Solver):
    def __init__(self, auto_replace: bool = True) -> None: ...

class SolverComposite(Solver):
    def __init__(self, timeout: int | None = None, track: bool = False) -> None: ...

__all__ = [
    "Solver",
    "SolverCacheless",
    "SolverComposite",
    "SolverConcrete",
    "SolverHybrid",
    "SolverReplacement",
    "SolverVSA",
    "SolverZ3",
]
