from __future__ import annotations

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import Call, Register
from angr.ailment.statement import Return, SideEffectStatement
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.calling_conventions import SimCCGoAMD64
from angr.enums import Flavors
from angr.go.optimization_passes.multi_value import GoCallResultBinder
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeLongLong
from tests.common import bin_location


def _run_binder(returnty):
    project = angr.Project(f"{bin_location}/tests/x86_64/go/go1.27.1/floatret_stripped", auto_load_libs=False)
    function = project.kb.functions.function(addr=project.entry, create=True)
    assert function is not None
    function.calling_convention = SimCCGoAMD64(project.arch)
    function.set_prototype(
        Flavors.GO_FLAVOR,
        SimTypeFunction([], returnty).with_arch(project.arch),
        source=PrototypeSource.GUESSED,
    )

    manager = Manager()
    rax = Register(manager.next_atom(), project.arch.registers["rax"][0], 64, reg_name="rax")
    xmm0 = Register(manager.next_atom(), project.arch.registers["xmm0"][0], 128, reg_name="xmm0")
    target = Register(manager.next_atom(), project.arch.registers["rdx"][0], 64, reg_name="rdx")
    call = Call(manager.next_atom(), target, args=[])
    block = Block(
        project.entry,
        16,
        statements=[
            SideEffectStatement(manager.next_atom(), call, rax, xmm0, ins_addr=project.entry),
            Return(manager.next_atom(), [xmm0 if isinstance(returnty, SimTypeDouble) else rax]),
        ],
    )
    graph = networkx.DiGraph()
    graph.add_node(block)
    binder = GoCallResultBinder(function, manager, graph=graph)
    return project, manager, block, call, binder


def test_guessed_float_return_binds_indirect_fp_result():
    project, manager, block, call, binder = _run_binder(SimTypeDouble())

    assert binder.out_graph is not None
    stmt = block.statements[0]
    assert isinstance(stmt, SideEffectStatement)
    assert stmt.fp_ret_expr is not None
    returnty = variable_map_of(manager).returnty(call)
    assert returnty is not None and returnty.size == 64
    rec = project.kb.go_signatures.callsite_record(project.entry)
    assert rec is not None and rec.fp_results == {0: "float64"}


def test_guessed_integer_return_does_not_bind_indirect_result():
    project, manager, _block, call, binder = _run_binder(SimTypeLongLong())

    assert binder.out_graph is None
    assert variable_map_of(manager).returnty(call) is None
    assert project.kb.go_signatures.callsite_record(project.entry) is None
