from __future__ import annotations

import archinfo

import angr
from angr.ailment import AILBlockViewer, Expr


class _ControlTransferCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.jumps = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)
        return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Jump(self, stmt_idx, stmt, block):
        self.jumps.append(stmt)
        return super()._handle_Jump(stmt_idx, stmt, block)


def _decompile_raw(code: bytes, function_starts: list[int]):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        code,
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=function_starts,
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    function = cfg.functions[0]
    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        generate_code=False,
        save_unoptimized_graph=True,
    )
    assert decompilation.unoptimized_ail_graph is not None
    return function, decompilation.unoptimized_ail_graph


def _constant_call_targets(graph) -> list[int]:
    collector = _ControlTransferCollector()
    for block in graph:
        collector.walk(block)
    return [call.target.value for call in collector.calls if isinstance(call.target, Expr.Const)]


def _constant_jump_targets(graph) -> list[int]:
    collector = _ControlTransferCollector()
    for block in graph:
        collector.walk(block)
    return [jump.target.value for jump in collector.jumps if isinstance(jump.target, Expr.Const)]


def test_self_jump_is_not_rewritten_as_a_recursive_tail_call():
    function, graph = _decompile_raw(bytes.fromhex("ebfe"), [0])  # jmp 0

    assert any(source.addr == target.addr == 0 for source, target in function.graph.edges)
    assert 0 in _constant_jump_targets(graph)
    assert 0 not in _constant_call_targets(graph)


def test_backedge_after_fake_return_is_not_rewritten_as_a_recursive_tail_call():
    # call 8; jmp 0; padding; ret. This models the call/fake-return/backedge shape found in Bang-like loops.
    function, graph = _decompile_raw(bytes.fromhex("e80500ebfb909090c3"), [0, 8])

    entry = next(node for node in function.graph if node.addr == 0)
    continuation = next(node for node in function.graph if node.addr == 3)
    assert function.graph.edges[entry, continuation]["type"] == "fake_return"
    assert function.graph.edges[continuation, entry]["type"] == "transition"
    assert 0 in _constant_jump_targets(graph)
    assert 0 not in _constant_call_targets(graph)
    assert 8 in _constant_call_targets(graph)


def test_cross_function_tail_jump_is_still_rewritten_as_a_call():
    _function, graph = _decompile_raw(bytes.fromhex("eb029090c3"), [0, 4])  # jmp 4; padding; ret

    assert 4 in _constant_call_targets(graph)
    assert 4 not in _constant_jump_targets(graph)
