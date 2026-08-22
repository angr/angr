"""Source-free graph regressions for segmented jump-table structuring."""

from __future__ import annotations

import archinfo
import networkx

import angr
from angr import ailment
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import SequenceNode, SwitchCaseNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType, JumptableResolutionEvidence


def test_phoenix_structures_exact_segmented_offset_jump_table():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    manager = ailment.Manager(arch=arch)
    vvar = ailment.Expr.VirtualVariable
    category = ailment.Expr.VirtualVariableCategory

    index = vvar(manager.next_atom(), 1, 16, category.REGISTER, oident=0)
    scaled_definition = vvar(manager.next_atom(), 2, 16, category.REGISTER, oident=2)
    scaled_use = vvar(manager.next_atom(), 2, 16, category.REGISTER, oident=2)
    target_definition = vvar(manager.next_atom(), 3, 16, category.UNKNOWN)
    target_use = vvar(manager.next_atom(), 3, 16, category.UNKNOWN)
    selector = vvar(manager.next_atom(), 4, 16, category.REGISTER, oident=4)

    def segmented(offset):
        return ailment.Expr.SegmentedAddress(
            manager.next_atom(),
            selector,
            offset,
            "x86-protected-16:16",
        )

    scaled_index = ailment.Expr.BinaryOp(
        manager.next_atom(),
        "Mul",
        (index, ailment.Expr.Const(manager.next_atom(), 2, 16)),
        False,
        bits=16,
    )
    table_offset = ailment.Expr.BinaryOp(
        manager.next_atom(),
        "Add",
        (scaled_use, ailment.Expr.Const(manager.next_atom(), 0x100, 16)),
        False,
        bits=16,
    )
    table_load = ailment.Expr.Load(
        manager.next_atom(),
        segmented(table_offset),
        2,
        "Iend_LE",
        bits=16,
    )
    dispatch = ailment.Block(
        0x100,
        4,
        statements=[
            ailment.Stmt.Assignment(manager.next_atom(), scaled_definition, scaled_index, ins_addr=0x100),
            ailment.Stmt.Assignment(manager.next_atom(), target_definition, table_load, ins_addr=0x102),
            ailment.Stmt.Jump(manager.next_atom(), segmented(target_use), ins_addr=0x102),
        ],
    )
    case_zero = ailment.Block(
        0x200,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x200)],
    )
    case_one = ailment.Block(
        0x300,
        1,
        statements=[ailment.Stmt.Return(manager.next_atom(), [], ins_addr=0x300)],
    )
    graph = networkx.DiGraph([(dispatch, case_zero), (dispatch, case_one)])
    overlay_manager = OverlayManager(graph)
    region = overlay_manager.root.create_subregion(dispatch, graph.nodes, cyclic=False)
    jump_table = IndirectJump(
        0x100,
        0x102,
        0x100,
        "Ijk_Boring",
        -1,
        resolved_targets=[0x200, 0x300],
        jumptable=True,
        jumptable_addr=0x100,
        jumptable_size=4,
        jumptable_entry_size=2,
        jumptable_entries=[0x200, 0x300],
        jumptable_entries_guessed=False,
        type_=IndirectJumpType.Jumptable_AddressLoadedFromMemory,
        jumptable_resolution_evidence=JumptableResolutionEvidence(
            "synthetic-exact-table",
            "source-free-two-entry-proof",
        ),
    )

    structurer = project.analyses[PhoenixStructurer](
        region,
        condition_processor=ConditionProcessor(arch, manager),
        jump_tables={dispatch.addr: jump_table},
        ail_manager=manager,
    )

    assert isinstance(structurer.result, SequenceNode)
    switch = next(node for node in structurer.result.nodes if isinstance(node, SwitchCaseNode))
    assert switch.switch_expr.likes(index)
    assert list(switch.cases) == [0, 1]
