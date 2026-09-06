"""
Locate the Go runtime's own package-level variables by shape when no data symbol names them:

- ``runtime.writeBarrier``: the word every compiled pointer store tests right before calling ``gcWriteBarrierN``;
- ``runtime.zerobase``: the address ``mallocgc`` returns for a zero-size allocation;
- ``runtime.staticuint64s``: the read-only table ``[256]uint64{0, 1, 2, ...}`` small boxed integers point into;
- ``runtime.firstmoduledata``: the moduledata the type-descriptor reader already found.
"""

from __future__ import annotations

import logging
import struct
from collections import Counter
from typing import TYPE_CHECKING

from angr.ailment.statement import Assignment, ConditionalJump, Store
from angr.go.analyses.block_scan import CONST, RegisterEnv, function_blocks, is_return, lift_ail, loads_in
from angr.go.signature import GoVariable
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from angr.project import Project

l = logging.getLogger(__name__)

_BARRIER_PREFIXES = ("runtime.gcWriteBarrier", "runtime.wbMove", "runtime.wbZero")
_RESULT_REGISTERS = ("rax", "x0", "eax")

WRITE_BARRIER_TYPE = "struct { enabled bool; pad [3]uint8; alignme uint64 }"
STATICUINT64S_TYPE = "[256]uint64"
ZEROBASE_TYPE = "uintptr"


def is_writable_data(project: Project, addr: int) -> bool:
    """``addr`` lies in a writable, non-executable region of the main object."""
    obj = project.loader.main_object
    if not obj.contains_addr(addr):
        return False
    region = obj.find_section_containing(addr) or obj.find_segment_containing(addr)
    return region is not None and region.is_writable and not region.is_executable


def is_readonly_data(project: Project, addr: int) -> bool:
    """``addr`` lies in a read-only, non-code region of the main object."""
    obj = project.loader.main_object
    if not obj.contains_addr(addr):
        return False
    section = obj.find_section_containing(addr)
    if section is not None:
        return not section.is_writable and section.name not in (".text", "__text")
    segment = obj.find_segment_containing(addr)
    return segment is not None and not segment.is_writable and not segment.is_executable


def _result_register(project: Project) -> int | None:
    for name in _RESULT_REGISTERS:
        if name in project.arch.registers:
            return project.arch.registers[name][0]
    return None


def find_write_barrier(project: Project) -> int | None:
    """The address tested by the conditional block in front of the write-barrier calls in the CFG."""
    functions = project.kb.functions
    barriers = {
        s.rebased_addr
        for s in project.loader.main_object.symbols
        if s.is_function and normalize_go_func_name(s.name).startswith(_BARRIER_PREFIXES)
    }
    if not barriers:
        return None
    callgraph = functions.callgraph
    votes: Counter = Counter()
    sites = 0
    for barrier in barriers:
        if barrier not in callgraph:
            continue
        for caller in list(callgraph.predecessors(barrier))[:32]:
            if not functions.contains_addr(caller):
                continue
            func = functions.get_by_addr(caller)
            for site in func.get_call_sites():
                if func.get_call_target(site) != barrier:
                    continue
                node = func.get_node(site)
                if node is None:
                    continue
                for pred in func.graph.predecessors(node):
                    addr = _tested_global(project, pred.addr, getattr(pred, "size", None))
                    if addr is not None:
                        votes[addr] += 1
                sites += 1
                if sites >= 64:
                    break
            if sites >= 64:
                break
    if not votes:
        return None
    addr, count = votes.most_common(1)[0]
    return addr if count * 2 > sum(votes.values()) else None


def _tested_global(project: Project, addr: int, size: int | None) -> int | None:
    """The last narrow load from a constant data address in a block that ends with a conditional jump."""
    stmts = lift_ail(project, addr, size)
    if not stmts or not isinstance(stmts[-1], ConditionalJump):
        return None
    env = RegisterEnv(project.arch)
    found = None
    for stmt in stmts:
        if isinstance(stmt, Assignment):
            loads: list = []
            loads_in(stmt.src, loads)
            for load in loads:
                if load.size not in (1, 4):
                    continue
                target = env.eval(load.addr)
                if target is not None and target[0] == CONST and is_writable_data(project, target[1]):
                    found = target[1]
            env.assign(stmt)
    return found


def find_zerobase(project: Project) -> int | None:
    """``mallocgc`` returns ``&zerobase`` from a block that only loads the address and returns."""
    sym = project.loader.find_symbol("runtime.mallocgc")
    ret_reg = _result_register(project)
    if sym is None or ret_reg is None:
        return None
    order, _ = function_blocks(project, sym.rebased_addr, limit=16)
    for addr in order[:16]:
        stmts = lift_ail(project, addr)
        if not stmts or not is_return(stmts[-1]):
            continue
        env = RegisterEnv(project.arch)
        stores = 0
        for stmt in stmts:
            if isinstance(stmt, Assignment):
                env.assign(stmt)
            elif isinstance(stmt, Store):
                stores += 1
        value = env.values.get(("r", ret_reg))
        # the frame teardown stores nothing; a stack write means this is a real return path
        if stores == 0 and value is not None and value[0] == CONST and is_writable_data(project, value[1]):
            return value[1]
    return None


def find_staticuint64s(project: Project) -> int | None:
    endian = "<" if project.arch.memory_endness == "Iend_LE" else ">"
    needle = b"".join(struct.pack(endian + "Q", i) for i in range(256))
    obj = project.loader.main_object
    for section in obj.sections:
        if section.is_writable or section.is_executable or not section.memsize or section.memsize < len(needle):
            continue
        try:
            data = project.loader.memory.load(section.vaddr, section.memsize)
        except KeyError:
            continue
        pos = data.find(needle)
        if pos != -1:
            return section.vaddr + pos
    return None


def find_runtime_globals(project: Project) -> dict[str, GoVariable]:
    """Every runtime global recognized by shape, keyed by its Go name."""
    out: dict[str, GoVariable] = {}
    for name, finder, type_str in (
        ("runtime.writeBarrier", find_write_barrier, WRITE_BARRIER_TYPE),
        ("runtime.zerobase", find_zerobase, ZEROBASE_TYPE),
        ("runtime.staticuint64s", find_staticuint64s, STATICUINT64S_TYPE),
    ):
        try:
            addr = finder(project)
        except Exception:  # pylint:disable=broad-exception-caught
            l.debug("Locating %s failed", name, exc_info=True)
            continue
        if addr is not None:
            out[name] = GoVariable(name, addr, type_str)
    go_types = getattr(project.kb, "go_types", None)
    md = go_types.descriptors.moduledata_addr if go_types is not None else None
    if md is not None:
        sigs = project.kb.go_signatures
        sigs.load_sources()
        type_str = "runtime.moduledata" if sigs.named_type("runtime.moduledata") is not None else "unsafe.Pointer"
        out["runtime.firstmoduledata"] = GoVariable("runtime.firstmoduledata", md, type_str)
    return out


__all__ = [
    "STATICUINT64S_TYPE",
    "WRITE_BARRIER_TYPE",
    "ZEROBASE_TYPE",
    "find_runtime_globals",
    "find_staticuint64s",
    "find_write_barrier",
    "find_zerobase",
    "is_readonly_data",
    "is_writable_data",
]
