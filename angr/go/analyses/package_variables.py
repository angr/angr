"""
Type package-level variables from their initializers.

Constant-initialized variables live in ``.data`` and need no code, so everything a package initializer
(``pkg.init``, ``pkg.init.N``) and ``main.main`` store into a global is a computed value whose shape names its
type: a runtime type descriptor or itab word followed by a data word (an interface), an allocator result
(``newobject`` -> ``*T``, ``makeslice`` -> ``[]T``, ``makemap`` -> ``map[K]V``), a read-only pointer plus a
length (``string``), a static funcval (a ``func``), or the result registers of a call with a known Go signature.
The scan works on raw AIL with a per-register environment; no SSA or simplification is needed.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import TYPE_CHECKING

from angr.ailment.expression import BinaryOp, Call, Const
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.calling_conventions import default_cc_for_project
from angr.go.analyses.block_scan import (
    CONST,
    TYPED,
    RegisterEnv,
    allocator,
    call_target,
    callee_name,
    function_blocks,
    is_function_addr,
    lift_ail,
)
from angr.go.analyses.runtime_globals import is_readonly_data, is_writable_data
from angr.go.signature import GoVariable
from angr.go.sim_type import GoSimTypeFunction, GoSimTypeTuple, go_type_repr
from angr.go.utils.types import go_type_name_at
from angr.sim_type import SimTypeFloat
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from angr.project import Project

l = logging.getLogger(__name__)

_INIT_RE = re.compile(r"^(?P<pkg>.+?)\.init(?:\.\d+)?$")
_MAX_STRING = 1 << 20
_CLOSURE_STRUCT = "*struct { F uintptr"
_PRESERVING = ("runtime.gcWriteBarrier", "runtime.wbMove", "runtime.wbZero", "runtime.duffzero", "runtime.duffcopy")


def initializer_package(name: str) -> str | None:
    """The package of an initializer (``pkg.init``, ``pkg.init.N``, ``main.main``); None for anything else."""
    name = normalize_go_func_name(name)
    if name == "main.main":
        return "main"
    m = _INIT_RE.match(name)
    if m is None:
        return None
    pkg = m.group("pkg")
    # a method called init spells its receiver between the package and the name
    if "." in pkg.rsplit("/", 1)[-1] or "(" in pkg:
        return None
    return pkg


class _Scan:
    """One project-wide scan: stores into globals collected from every initializer, then turned into types."""

    def __init__(self, project: Project):
        self.project = project
        self.arch = project.arch
        self.kb = project.kb
        self.sigs = project.kb.go_signatures
        self.ptr = project.arch.bytes
        cc = default_cc_for_project(project)
        regs = getattr(cc, "ARG_REGS", None) if cc is not None else None
        self.result_regs = [self.arch.registers[r][0] for r in regs] if regs else []
        # address -> [(size, value, package)]
        self.stores: dict[int, list[tuple[int, tuple | None, str]]] = defaultdict(list)
        # origin of a typed closure record -> the code pointer stored at its word 0
        self.closure_fn: dict[int, int] = {}
        self._origin = 0

    # ------------------------------------------------------------------ driver

    def run(self) -> list[GoVariable]:
        for addr, pkg in self._initializers():
            try:
                self._scan_function(addr, pkg)
            except Exception:  # pylint:disable=broad-exception-caught
                l.debug("Scanning initializer %#x failed", addr, exc_info=True)
        return self._derive()

    def _initializers(self) -> list[tuple[int, str]]:
        out = []
        for sym in self.project.loader.main_object.symbols:
            if not sym.is_function:
                continue
            pkg = initializer_package(sym.name)
            if pkg is not None:
                out.append((sym.rebased_addr, pkg))
        out.sort()
        return out

    def _scan_function(self, addr: int, pkg: str) -> None:
        order, succs = function_blocks(self.project, addr)
        if not order:
            return
        entry = addr if addr in succs else order[0]
        envs_in: dict[int, RegisterEnv] = {entry: RegisterEnv(self.arch)}
        worklist = [entry]
        budget = 8 * len(order)
        while worklist and budget > 0:
            budget -= 1
            block = worklist.pop(0)
            out_env = self._scan_block(block, envs_in[block].copy(), pkg)
            for succ in succs.get(block, ()):
                if succ not in envs_in:
                    envs_in[succ] = out_env.copy()
                    worklist.append(succ)
                    continue
                merged = envs_in[succ].merge(out_env)
                if merged.values != envs_in[succ].values:
                    envs_in[succ] = merged
                    worklist.append(succ)

    def _scan_block(self, addr: int, env: RegisterEnv, pkg: str) -> RegisterEnv:
        for stmt in lift_ail(self.project, addr):
            if isinstance(stmt, Assignment):
                env.assign(stmt)
            elif isinstance(stmt, Store):
                self._store(stmt, env, pkg)
            elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                self._call(stmt.expr, env)
        return env

    # ------------------------------------------------------------------ statements

    def _base_and_offset(self, env: RegisterEnv, expr) -> tuple[tuple | None, int]:
        if isinstance(expr, BinaryOp) and expr.op == "Add":
            a, b = expr.operands
            if isinstance(b, Const) and isinstance(b.value, int):
                return env.eval(a), b.value
            if isinstance(a, Const) and isinstance(a.value, int):
                return env.eval(b), a.value
        return env.eval(expr), 0

    def _store(self, stmt: Store, env: RegisterEnv, pkg: str) -> None:
        base, off = self._base_and_offset(env, stmt.addr)
        if base is None:
            return
        data = env.eval(stmt.data)
        if base[0] == TYPED:
            # a field store through a fresh allocation: a closure record's code pointer
            if (
                off == 0
                and base[1].startswith(_CLOSURE_STRUCT)
                and data is not None
                and data[0] == CONST
                and is_function_addr(self.project, data[1])
            ):
                self.closure_fn[base[4]] = data[1]
            return
        if base[0] != CONST:
            return
        target = base[1] + off
        if not is_writable_data(self.project, target):
            return
        self.stores[target].append((stmt.size, data, pkg))

    def _call(self, stmt: Call, env: RegisterEnv) -> None:
        target = call_target(stmt)
        name = callee_name(self.project, target) if target is not None else None
        if name is not None and name.startswith(_PRESERVING):
            # write-barrier and duff helpers are assembly that leaves the argument registers alone
            return
        pre = env.registers()
        env.clear_call_clobbers()
        if target is None:
            return
        self._origin += 1
        alloc = allocator(name)
        if alloc is not None:
            prefix, arg = alloc
            if arg is None or arg >= len(self.result_regs):
                return
            desc = pre.get(self.result_regs[arg])
            type_name = go_type_name_at(self.project, desc[1]) if desc is not None and desc[0] == CONST else None
            if type_name is None:
                return
            words = 3 if prefix == "[]" else 1
            env.values[("r", self.result_regs[0])] = (TYPED, prefix + type_name, 0, words, self._origin)
            return
        proto = self.sigs.prototype(name) if name is not None else None
        if proto is None:
            proto = self.sigs.prototype_at(target)
        if not isinstance(proto, GoSimTypeFunction) or proto.returnty is None:
            return
        results = list(proto.returnty.elems) if isinstance(proto.returnty, GoSimTypeTuple) else [proto.returnty]
        reg = 0
        for ty in results:
            if _has_float(ty):
                return
            words = max(1, (ty.size or self.arch.bits) // self.arch.bits) if ty.size != 0 else 0
            if reg + words > len(self.result_regs):
                return
            spelling = go_type_repr(ty)
            for k in range(words):
                env.values[("r", self.result_regs[reg + k])] = (TYPED, spelling, k, words, self._origin)
            reg += words
            self._origin += 1

    # ------------------------------------------------------------------ types

    def _derive(self) -> list[GoVariable]:
        records: dict[int, tuple[str, str]] = {}
        for addr in sorted(self.stores):
            for size, value, pkg in self.stores[addr]:
                if size != self.ptr:
                    continue
                type_str = self._type_of(addr, value)
                if type_str is None:
                    continue
                existing = records.get(addr)
                if existing is None or (existing[0] == "any" and type_str != "any"):
                    records[addr] = (type_str, pkg)
        by_pkg: dict[str, list[int]] = defaultdict(list)
        for addr, (_, pkg) in records.items():
            by_pkg[pkg].append(addr)
        out = []
        for pkg, addrs in by_pkg.items():
            for i, addr in enumerate(sorted(addrs)):
                out.append(GoVariable(f"{pkg}.var_{i}", addr, records[addr][0]))
        return out

    def _stored_at(self, addr: int) -> bool:
        return any(size == self.ptr for size, _, _ in self.stores.get(addr, ()))

    def _type_of(self, addr: int, value: tuple | None) -> str | None:
        if value is None:
            return None
        if value[0] == TYPED:
            _, type_str, word, words, origin = value
            if word != 0 or not all(self._stored_at(addr + k * self.ptr) for k in range(1, words)):
                return None
            if type_str.startswith(_CLOSURE_STRUCT) and origin in self.closure_fn:
                return self._func_type(self.closure_fn[origin]) or type_str
            return type_str
        if value[0] != CONST:
            return None
        const = value[1]
        go_types = self.kb.go_types
        itab = go_types.itab_at(const)
        if itab is not None:
            return itab[0] if self._stored_at(addr + self.ptr) else None
        if go_types.name_at(const) is not None:
            return "any" if self._stored_at(addr + self.ptr) else None
        if not is_readonly_data(self.project, const):
            return None
        length = next(
            (v[1] for size, v, _ in self.stores.get(addr + self.ptr, ()) if size == self.ptr and v and v[0] == CONST),
            None,
        )
        if (
            length is not None
            and 0 < length < _MAX_STRING
            and self.project.loader.main_object.contains_addr(const + length - 1)
        ):
            return "string"
        if const % self.ptr == 0:
            try:
                code = self.project.loader.memory.unpack_word(const, size=self.ptr)
            except KeyError:
                return None
            if is_function_addr(self.project, code):
                return self._func_type(code)
        return None

    def _func_type(self, code: int) -> str | None:
        """``func(...)`` spelling of the function at ``code`` when a signature source knows it."""
        name = callee_name(self.project, code)
        proto = self.sigs.prototype(name) if name is not None else None
        if proto is None:
            proto = self.sigs.prototype_at(code)
        return go_type_repr(proto) if isinstance(proto, GoSimTypeFunction) else None


def _has_float(ty) -> bool:
    if isinstance(ty, SimTypeFloat):
        return True
    fields = getattr(ty, "fields", None)
    return any(_has_float(f) for f in fields.values()) if isinstance(fields, dict) else False


def infer_package_variables(project: Project) -> list[GoVariable]:
    """Package-level variables typed from the stores in the binary's initializers, named ``pkg.var_N``."""
    return _Scan(project).run()
