"""
Find the func-typed parameters a function's func value is passed to. A Go func value points to a funcval, a record
whose first word is the function's code address: a static one in data for a function used as a value without
captures, or, for a closure built on the stack, a stack slot filled right before the call. A parameter of func type
that receives it has the function's exact type, which no signature source names for a closure in a stripped
binary.
"""

from __future__ import annotations

import contextlib
from collections import defaultdict
from typing import TYPE_CHECKING

from angr.ailment.expression import Call
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.calling_conventions import SimRegArg, go_cc_class_for_project
from angr.go.analyses.block_scan import CONST, SP, RegisterEnv, call_target, callee_name, lift_ail
from angr.go.sim_type import GoSimTypeFunc, GoSimTypeFunction

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.project import Project


def static_funcvals(project: Project, kb: KnowledgeBase) -> dict[int, list[int]]:
    """Function entry -> the referenced words that hold it, which include its static funcvals."""
    word = project.arch.bytes
    out: dict[int, list[int]] = defaultdict(list)
    for addr in kb.xrefs.xrefs_by_dst:
        if addr % word:
            continue
        with contextlib.suppress(KeyError):
            code = project.loader.memory.unpack_word(addr, size=word)
            if code != addr and kb.functions.contains_addr(code):
                out[code].append(addr)
    return out


def passed_func_types(project: Project, kb: KnowledgeBase, code: int, funcvals: list[int]) -> list[GoSimTypeFunc]:
    """
    The func types of the register parameters that receive a func value of the function at ``code``: its stack
    funcval (a slot whose first word is ``code``) or one of its static ``funcvals``. Only the block holding the
    reference is scanned, up to its first call, so a func value built in an earlier block is not seen. Arguments are
    placed by angr's Go calling convention for the architecture; without one, nothing is found.
    """
    cc_cls = go_cc_class_for_project(project)
    if cc_cls is None:
        return []
    cc = cc_cls(project.arch)
    sigs = kb.go_signatures
    refs = [(x.block_addr, code) for x in kb.xrefs.get_xrefs_by_dst(code)]
    for fv in funcvals:
        refs.extend((x.block_addr, fv) for x in kb.xrefs.get_xrefs_by_dst(fv))
    out = []
    for block_addr, ref in refs:
        if block_addr is None:
            continue
        env = RegisterEnv(project.arch)
        for stmt in lift_ail(project, block_addr):
            if isinstance(stmt, Assignment):
                env.assign(stmt)
            elif isinstance(stmt, Store):
                env.store(stmt.addr, stmt.data, stmt.size)
            elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                out.extend(_receiving_params(project, sigs, cc, env, stmt.expr, code, ref))
                break
    return out


def _receiving_params(project: Project, sigs, cc, env: RegisterEnv, call: Call, code: int, ref: int):
    target = call_target(call)
    if target is None:
        return []
    name = callee_name(project, target)
    proto = sigs.prototype(name) if name is not None else None
    if proto is None:
        proto = sigs.prototype_at(target)
    if not isinstance(proto, GoSimTypeFunction):
        return []
    try:
        locs = cc.arg_locs(proto)
    except Exception:  # pylint:disable=broad-exception-caught
        return []
    out = []
    for loc, ty in zip(locs, proto.args):
        if not isinstance(ty, GoSimTypeFunc) or not isinstance(loc, SimRegArg):
            continue
        value = env.values.get(("r", project.arch.registers[loc.reg_name][0]))
        if value is None:
            continue
        if ref == code:
            passed = value[0] == SP and env.values.get(("s", value[1])) == (CONST, code)
        else:
            passed = value == (CONST, ref)
        if passed:
            out.append(ty)
    return out
