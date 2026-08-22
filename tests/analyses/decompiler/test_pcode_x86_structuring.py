from __future__ import annotations

import logging

import archinfo
import claripy
import networkx
import pytest

import angr
from angr import ailment
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import ConditionNode
from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer
from angr.errors import AngrRuntimeError
from angr.knowledge_plugins.functions import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction

pytest.importorskip("pypcode")


_BASE = 0x1000
_SEGMENTED_MEMORY_BINDINGS = {
    "x86-protected-16:16": {
        "endness": archinfo.Endness.LE,
        "loads": {2: "guest_load_u16"},
        "stores": {2: "guest_store_u16"},
    }
}

# Reduced from a source-blind Win16 command-line parser. Memory operations were replaced by same-width NOPs, leaving
# only the two intertwined parser loops and their ordinary RET. The leading NOP is significant: it makes the initial
# jump and its later-reachable fallthrough part of one function. SAILR cannot structure the connected root, while a
# fresh single-exit region tree is completely handled by DREAM.
_MULTI_EXIT_LOOP_BYTES = bytes.fromhex(
    "90eb0333c090903c2074fb3c0974f73c0d747c0ac0747890909043434e903c2074e13c0974dd3c0d74620ac0745e"
    "3c2274273c5c740390ebe433c941903c5c74fa3c227406b05c9090ebd1b05cd1e990907306b02290ebc54e903c0d"
    "742e0ac0742a3c2274b73c5c740390ebec33c941903c5c74fa3c227406b05c9090ebd9b05cd1e990907396b02290"
    "ebcd33c090909090909090c3909090"
)

# pop word ptr [0x432]; sub sp,dx; mov ax,sp; mov [0x400],ax; mov word ptr [bx],0; jmp word ptr [0x432]
_DYNAMIC_RETURN_THUNK_BYTES = bytes.fromhex("8f06320429d489e0a30004c7070000ff263204")


def _cfg(machine_code: bytes):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        machine_code,
        arch=arch,
        load_address=_BASE,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    cfg = project.analyses.CFGFast(
        function_starts=[_BASE],
        regions=[(_BASE, _BASE + len(machine_code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=True,
    )
    function = cfg.functions[_BASE]
    function.calling_convention = project.factory.cc()
    function.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(project.arch)
    function.prototype_source = PrototypeSource.USER
    return project, cfg, function


def _region_identifier_project():
    return angr.load_shellcode(
        b"\x90",
        arch=archinfo.ArchPcode("x86:LE:16:Protected Mode"),
        load_address=_BASE,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )


def _const(manager: ailment.Manager, value: int, bits: int = 16):
    return ailment.Expr.Const(manager.next_atom(), value, bits)


def _graph_block_statement_bytes(graph):
    rows = [
        (node.addr, node.idx, tuple(statement.to_bytes() for statement in node.statements))
        for node in graph
        if isinstance(node, ailment.Block)
    ]
    return sorted(rows, key=lambda row: (row[0], -1 if row[1] is None else row[1], row[2]))


def _structured_block_addrs(node):
    addrs = set()

    def collect(block, **_kwargs):
        addrs.add(block.addr)

    SequenceWalker(handlers={ailment.Block: collect}).walk(node)
    return addrs


def test_phoenix_root_failure_retries_dream_on_a_fresh_single_exit_region_tree(monkeypatch, caplog):
    project, cfg, function = _cfg(_MULTI_EXIT_LOOP_BYTES)
    caplog.set_level(logging.INFO, logger="angr.analyses.decompiler.structuring.recursive_structurer")
    graph_transactions = []
    original_structure = RecursiveStructurer._structure_overlay_tree

    def assert_transactional_structure(self):
        before = _graph_block_statement_bytes(self._region.manager.graph)
        original_structure(self)
        after = _graph_block_statement_bytes(self._region.manager.graph)
        graph_transactions.append((before, after))

    monkeypatch.setattr(RecursiveStructurer, "_structure_overlay_tree", assert_transactional_structure)

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        save_unoptimized_graph=True,
    )

    assert decompilation.codegen is not None
    assert "return;" in decompilation.codegen.text
    assert not decompilation.codegen.unsupported_constructs
    assert any("DREAM completed it after an exact overlay rollback" in record.message for record in caplog.records)
    assert not any("Structuring failed to complete" in record.message for record in caplog.records)
    assert graph_transactions and all(before == after for before, after in graph_transactions)

    # Both formerly disconnected parser corridors and the final return block survive into the exact AIL snapshot.
    assert decompilation.unoptimized_ail_graph is not None
    ail_addrs = {node.addr for node in decompilation.unoptimized_ail_graph}
    assert {_BASE + 0x1D, _BASE + 0x59, _BASE + 0x8C}.issubset(ail_addrs)
    # They must also survive the structured result consumed by code generation; an input-only assertion would allow
    # a non-None but code-dropping DREAM result to be called complete.
    assert decompilation.seq_node is not None
    # The final simplifier coalesces the input tail block at +0x8c into the actual RET block at +0x8f.
    assert {_BASE + 0x1D, _BASE + 0x59, _BASE + 0x8F}.issubset(_structured_block_addrs(decompilation.seq_node))


def test_dream_fallback_failure_keeps_the_existing_incomplete_result(monkeypatch, caplog):
    project, cfg, function = _cfg(_MULTI_EXIT_LOOP_BYTES)
    primary_results = {}
    retained_results = {}
    fallback_condition_isolation = []
    fallback_inherited_primary_conditions = []
    original_once = RecursiveStructurer._structure_overlay_tree_once
    original_structure = RecursiveStructurer._structure_overlay_tree

    def record_primary(self, root, structurer_cls, *, condition_processor=None):
        result, complete = original_once(self, root, structurer_cls, condition_processor=condition_processor)
        if structurer_cls is self.structurer_cls:
            assert result is not None and not complete
            self.cond_proc._condition_mapping["synthetic_primary_condition"] = None
            primary_results[id(self)] = result.dbg_repr()
        return result, complete

    def record_retained(self):
        original_structure(self)
        assert self.result is not None and self.result_incomplete
        assert "synthetic_fallback_only" not in self.cond_proc._condition_mapping
        retained_results[id(self)] = self.result.dbg_repr()

    def fail_fallback(self, _root, _input_graph, dream_cond_proc):
        fallback_condition_isolation.append(dream_cond_proc is not self.cond_proc)
        fallback_inherited_primary_conditions.append(
            "synthetic_primary_condition" in dream_cond_proc._condition_mapping
        )
        dream_cond_proc._condition_mapping["synthetic_fallback_only"] = None
        raise RuntimeError("synthetic DREAM region-identification failure")

    monkeypatch.setattr(RecursiveStructurer, "_structure_overlay_tree_once", record_primary)
    monkeypatch.setattr(RecursiveStructurer, "_structure_overlay_tree", record_retained)
    monkeypatch.setattr(RecursiveStructurer, "_make_dream_region_tree", fail_fallback)
    caplog.set_level(logging.INFO, logger="angr.analyses.decompiler.structuring.recursive_structurer")

    # The fallback is optional recovery for output that is already incomplete. Its own failure must be contained.
    decompilation = project.analyses.Decompiler(function, cfg=cfg.model, fail_fast=True)

    assert decompilation.codegen is not None
    assert any(
        "DREAM fallback after sailr root failure did not complete" in record.message for record in caplog.records
    )
    assert any("Structuring failed to complete" in record.message for record in caplog.records)
    assert not any("DREAM completed it after an exact overlay rollback" in record.message for record in caplog.records)
    assert primary_results
    assert retained_results == primary_results
    assert fallback_condition_isolation and all(fallback_condition_isolation)
    assert fallback_inherited_primary_conditions and all(fallback_inherited_primary_conditions)


def test_dream_loop_guard_redirects_exact_interior_transfers_and_preserves_the_self_loop(caplog):
    """Model the interior exit and terminal self-loop emitted by a p-code REP instruction without source code."""

    project = _region_identifier_project()
    manager = ailment.Manager(arch=project.arch)
    exit_one = ailment.Block(
        0x1200,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1200)],
        idx=1,
    )
    exit_two = ailment.Block(
        0x1300,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1300)],
        idx=2,
    )
    head = ailment.Block(
        0x1100,
        2,
        idx=7,
        statements=[
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                _const(manager, 1, 1),
                _const(manager, exit_one.addr),
                _const(manager, 0x1100),
                true_target_idx=exit_one.idx,
                false_target_idx=7,
                ins_addr=0x1100,
                marker="first-exit",
            ),
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                _const(manager, 1, 1),
                _const(manager, exit_two.addr),
                _const(manager, 0x1100),
                true_target_idx=exit_two.idx,
                false_target_idx=7,
                ins_addr=0x1100,
                marker="second-exit",
            ),
            ailment.Stmt.Jump(
                manager.next_atom(),
                _const(manager, 0x1100),
                target_idx=7,
                transfer_kind="near",
                ins_addr=0x1100,
                stmt_idx=9,
                marker="terminal-self-loop",
            ),
        ],
    )
    entry = ailment.Block(
        _BASE,
        1,
        statements=[ailment.Stmt.Jump(manager.next_atom(), _const(manager, head.addr), ins_addr=_BASE)],
    )
    graph = networkx.DiGraph()
    # The entry-to-exit edges keep the exit blocks outside the loop while RegionIdentifier refines it.
    graph.add_edges_from(
        [
            (entry, head),
            (entry, exit_one),
            (entry, exit_two),
            (head, head),
            (head, exit_one),
            (head, exit_two),
        ]
    )
    graph[head][exit_one]["edge_class"] = "guardable-exit"
    graph[head][exit_two]["edge_class"] = "guardable-exit"
    tail_before = head.statements[-1].to_bytes()
    tail_tags_before = dict(head.statements[-1].tags)
    caplog.set_level(logging.WARNING, logger="angr.analyses.decompiler.region_identifier")

    result = project.analyses.RegionIdentifier(
        None,
        graph=graph,
        ail_manager=manager,
        entry_node_addr=(entry.addr, None),
        force_loop_single_exit=True,
    )

    first_exit, second_exit, terminal_self_loop = head.statements
    assert isinstance(first_exit, ailment.Stmt.ConditionalJump)
    assert isinstance(second_exit, ailment.Stmt.ConditionalJump)
    assert first_exit.true_target.value == second_exit.true_target.value
    guard_addr = first_exit.true_target.value
    assert guard_addr not in {exit_one.addr, exit_two.addr, head.addr}
    assert first_exit.true_target_idx is None and second_exit.true_target_idx is None
    assert first_exit.false_target.value == head.addr and second_exit.false_target.value == head.addr
    assert first_exit.false_target_idx == 7 and second_exit.false_target_idx == 7
    assert first_exit.tags["marker"] == "first-exit" and second_exit.tags["marker"] == "second-exit"

    assert terminal_self_loop.to_bytes() == tail_before
    assert terminal_self_loop.tags == tail_tags_before
    assert terminal_self_loop.target.value == head.addr
    assert terminal_self_loop.target_idx == 7
    assert terminal_self_loop.transfer_kind == "near"

    assert result.overlay_manager is not None
    shared_graph = result.overlay_manager.graph
    guard = next(node for node in shared_graph if isinstance(node, ConditionNode) and node.addr == guard_addr)
    ordered_successors = sorted((exit_one, exit_two), key=lambda node: result._node_order[node])
    assert guard.false_node is ordered_successors[0]
    assert guard.true_node is ordered_successors[1]
    assert shared_graph.has_edge(head, head)
    assert shared_graph.has_edge(head, guard)
    assert shared_graph[head][guard] == {"edge_class": "guardable-exit"}
    assert shared_graph.has_edge(guard, exit_one) and shared_graph.has_edge(guard, exit_two)
    assert not shared_graph.has_edge(head, exit_one) and not shared_graph.has_edge(head, exit_two)
    assert not [record for record in caplog.records if record.name == "angr.analyses.decompiler.region_identifier"]


def test_dream_loop_guard_redirects_nested_condition_owners_without_mutating_destination_code():
    project = _region_identifier_project()
    manager = ailment.Manager(arch=project.arch)
    exit_one = ailment.Block(
        0x1200,
        1,
        idx=1,
        statements=[
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                _const(manager, 1, 1),
                _const(manager, 0x1200),
                _const(manager, 0x1400),
                true_target_idx=1,
                ins_addr=0x1200,
                marker="preserve-self-target",
            )
        ],
    )
    exit_two = ailment.Block(
        0x1300,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1300)],
    )
    end = ailment.Block(
        0x1400,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1400)],
    )
    head = ailment.Block(
        0x1100,
        1,
        statements=[ailment.Stmt.Jump(manager.next_atom(), _const(manager, 0xFF001000), ins_addr=0x1100)],
    )
    entry = ailment.Block(
        _BASE,
        1,
        statements=[ailment.Stmt.Jump(manager.next_atom(), _const(manager, head.addr), ins_addr=_BASE)],
    )
    tail_guard = ConditionNode(
        0xFF001001,
        None,
        claripy.BoolS("nested_exit"),
        exit_two,
        false_node=head,
    )
    old_guard = ConditionNode(
        0xFF001000,
        None,
        claripy.BoolS("first_exit"),
        exit_one,
        false_node=tail_guard,
    )
    graph = networkx.DiGraph()
    graph.add_edges_from(
        [
            (entry, head),
            (entry, exit_one),
            (entry, exit_two),
            (head, old_guard),
            (old_guard, head),
            (old_guard, exit_one),
            (old_guard, exit_two),
            (exit_one, exit_one),
            (exit_one, end),
        ]
    )
    exit_statement_before = exit_one.statements[0].to_bytes()

    project.analyses.RegionIdentifier(
        None,
        graph=graph,
        ail_manager=manager,
        entry_node_addr=(entry.addr, None),
        force_loop_single_exit=True,
    )

    assert exit_one.statements[0].to_bytes() == exit_statement_before
    assert exit_one.statements[0].true_target.value == exit_one.addr
    assert isinstance(old_guard.true_node, ConditionNode)
    assert tail_guard.true_node is old_guard.true_node
    assert tail_guard.false_node is head


def test_dream_loop_guard_rejects_ambiguous_address_only_owners_before_mutation():
    project = _region_identifier_project()
    manager = ailment.Manager(arch=project.arch)
    exit_one = ailment.Block(
        0x1200,
        1,
        idx=1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1200)],
    )
    exit_two = ailment.Block(
        0x1200,
        1,
        idx=2,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1200)],
    )
    head = ailment.Block(
        0x1100,
        2,
        idx=7,
        statements=[
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                _const(manager, 1, 1),
                _const(manager, 0x1200),
                _const(manager, 0x1100),
                true_target_idx=None,
                false_target_idx=7,
                ins_addr=0x1100,
            ),
            ailment.Stmt.Jump(
                manager.next_atom(),
                _const(manager, 0x1100),
                target_idx=7,
                ins_addr=0x1100,
            ),
        ],
    )
    entry = ailment.Block(
        _BASE,
        1,
        statements=[ailment.Stmt.Jump(manager.next_atom(), _const(manager, head.addr), ins_addr=_BASE)],
    )
    graph = networkx.DiGraph()
    graph.add_edges_from(
        [
            (entry, head),
            (entry, exit_one),
            (entry, exit_two),
            (head, head),
            (head, exit_one),
            (head, exit_two),
        ]
    )
    statements_before = [statement.to_bytes() for statement in head.statements]

    with pytest.raises(AngrRuntimeError, match="no exact AIL transfer owner"):
        project.analyses.RegionIdentifier(
            None,
            graph=graph,
            ail_manager=manager,
            entry_node_addr=(entry.addr, None),
            force_loop_single_exit=True,
        )

    assert [statement.to_bytes() for statement in head.statements] == statements_before


def test_dream_loop_guard_rejects_conflicting_collapsed_edge_metadata_before_mutation():
    project = _region_identifier_project()
    manager = ailment.Manager(arch=project.arch)
    exit_one = ailment.Block(
        0x1200,
        1,
        idx=1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1200)],
    )
    exit_two = ailment.Block(
        0x1300,
        1,
        idx=2,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x1300)],
    )
    head = ailment.Block(
        0x1100,
        2,
        idx=7,
        statements=[
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                _const(manager, 1, 1),
                _const(manager, exit_one.addr),
                _const(manager, exit_two.addr),
                true_target_idx=exit_one.idx,
                false_target_idx=exit_two.idx,
                ins_addr=0x1100,
            ),
            ailment.Stmt.Jump(
                manager.next_atom(),
                _const(manager, 0x1100),
                target_idx=7,
                ins_addr=0x1100,
            ),
        ],
    )
    entry = ailment.Block(
        _BASE,
        1,
        statements=[ailment.Stmt.Jump(manager.next_atom(), _const(manager, head.addr), ins_addr=_BASE)],
    )
    graph = networkx.DiGraph()
    graph.add_edges_from(
        [
            (entry, head),
            (entry, exit_one),
            (entry, exit_two),
            (head, head),
        ]
    )
    graph.add_edge(head, exit_one, branch_kind="true")
    graph.add_edge(head, exit_two, branch_kind="false")
    statements_before = [statement.to_bytes() for statement in head.statements]
    nodes_before = set(graph)
    edge_data_before = {(source, target): dict(data) for source, target, data in graph.edges(data=True)}

    with pytest.raises(AngrRuntimeError, match="conflicting metadata"):
        project.analyses.RegionIdentifier(
            None,
            graph=graph,
            ail_manager=manager,
            entry_node_addr=(entry.addr, None),
            force_loop_single_exit=True,
        )

    assert [statement.to_bytes() for statement in head.statements] == statements_before
    assert set(graph) == nodes_before
    assert {(source, target): dict(data) for source, target, data in graph.edges(data=True)} == edge_data_before


def test_dynamic_stack_return_thunk_has_complete_tail_without_exposing_the_control_token(caplog):
    project, cfg, function = _cfg(_DYNAMIC_RETURN_THUNK_BYTES)
    assert {site.addr for site in function.ret_sites} == {_BASE}
    caplog.set_level(logging.WARNING, logger="angr.analyses.decompiler.clinic")

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        register_state_bindings={"ax": "guest_ax", "bx": "guest_bx", "ds": "guest_ds", "dx": "guest_dx"},
        segmented_memory_bindings=_SEGMENTED_MEMORY_BINDINGS,
        save_unoptimized_graph=True,
    )

    assert decompilation.codegen is not None
    code = decompilation.codegen.text
    assert "return;" in code
    assert "guest_dx" in code and "0x400" in code
    assert "guest_store_u16" in code
    assert "1074" not in code and "0x432" not in code
    assert not decompilation.codegen.unsupported_constructs
    assert not any("Inconsistency found during stack pointer tracking" in record.message for record in caplog.records)


def test_mutated_return_slot_fails_closed_and_keeps_the_machine_effects():
    # Overwrite the saved continuation before the terminal jump.
    machine_code = bytes.fromhex("8f06320429d489e0a30004c70632040000ff263204")
    project, cfg, function = _cfg(machine_code)

    assert not function.ret_sites
    assert _BASE in cfg.kb.unresolved_indirect_jumps

    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=True,
        register_state_bindings={"ax": "guest_ax", "ds": "guest_ds", "dx": "guest_dx"},
        segmented_memory_bindings=_SEGMENTED_MEMORY_BINDINGS,
    )

    assert decompilation.codegen is not None
    code = decompilation.codegen.text
    assert "1074" in code
    assert "return;" not in code
    assert decompilation.codegen.unsupported_constructs
