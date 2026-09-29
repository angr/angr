# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import struct
import unittest

import angr
from angr.analyses.cfg import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver
from angr.knowledge_plugins.cfg import IndirectJumpType
from angr.knowledge_plugins.xrefs import XRef, XRefType

_BASE = 0x400000
_TABLE = _BASE + 0x100
_CASES = [_BASE + 0x20 + i for i in range(4)]


class _OverlappingTablesResolver(IndirectJumpResolver):
    """Supply controlled overlapping-table metadata through the normal CFGFast resolution path."""

    def __init__(self, project, guessed):
        super().__init__(project, timeless=False)
        self.guessed = guessed

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return addr in {_BASE, _BASE + 0x10} and jumpkind == "Ijk_Boring"

    def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete=True, **kwargs):
        first = addr == _BASE
        table, count = (_TABLE, 4) if first else (_TABLE + 8, 2)
        entries = [self.project.loader.memory.unpack_word(table + i * 4, size=4) for i in range(count)]
        jump = cfg.indirect_jumps[addr]
        jump.jumptable = True
        jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
        jump.add_jumptable(table, count * 4, 4, entries, entries_guessed=first and self.guessed)
        jump.resolved_targets = set(entries)
        return True, entries


def _overlapping_tables(*, repeated=False, guessed=True):
    entries = [_CASES[0], _CASES[1], _CASES[0] if repeated else _CASES[2], _CASES[3]]
    code = bytearray(b"\x90" * 0x100)
    code[:7] = b"\xff\x24\x85" + struct.pack("<I", _TABLE)
    code[0x10:0x17] = b"\xff\x24\x8d" + struct.pack("<I", _TABLE + 8)
    code[0x20:0x24] = b"\xc3" * 4
    code += struct.pack("<4I", *entries)
    project = angr.load_shellcode(bytes(code), arch="x86", load_address=_BASE)
    cfg = project.analyses[CFGFast].prep(fail_fast=True)(
        normalize=True,
        start_at_entry=False,
        function_starts=[_BASE, _BASE + 0x10],
        regions=[(_BASE, _BASE + 0x24)],
        force_complete_scan=False,
        indirect_jump_resolvers=[_OverlappingTablesResolver(project, guessed)],
    )
    return cfg, entries


class TestGuessedJumptableRepair(unittest.TestCase):
    def test_resolved_targets_follow_repaired_entries(self):
        cfg, entries = _overlapping_tables()
        jump = cfg.jump_tables[_BASE]
        assert jump.jumptable_entries == entries[:2]
        assert jump.jumptable_size == 8
        assert jump.resolved_targets == set(entries[:2])

    def test_knowledge_base_targets_follow_repaired_entries(self):
        cfg, entries = _overlapping_tables()
        assert set(cfg.kb.indirect_jumps.resolved[_BASE]) == set(entries[:2])

    def test_repair_preserves_repeated_case_edges(self):
        cfg, entries = _overlapping_tables(repeated=True)
        source = cfg.model.get_any_node(_BASE)
        assert source is not None
        assert {node.addr for node in cfg.graph.successors(source)} == set(entries[:2])
        function = cfg.kb.functions[_BASE]
        block = function.get_node(_BASE)
        assert {node.addr for node in function.transition_graph.successors(block)} == set(entries[:2])
        second = cfg.model.get_any_node(_BASE + 0x10)
        assert second is not None
        assert {node.addr for node in cfg.graph.successors(second)} == set(entries[2:])

    def test_exact_table_is_not_trimmed(self):
        cfg, entries = _overlapping_tables(guessed=False)
        jump = cfg.jump_tables[_BASE]
        assert jump.jumptable_entries == entries
        assert jump.jumptable_size == 16
        assert jump.resolved_targets == set(entries)
        assert set(cfg.kb.indirect_jumps.resolved[_BASE]) == set(entries)
        source = cfg.model.get_any_node(_BASE)
        assert source is not None
        assert {node.addr for node in cfg.graph.successors(source)} == set(entries)

    def test_repair_is_idempotent(self):
        cfg, _ = _overlapping_tables(repeated=True)
        targets = cfg.jump_tables[_BASE].resolved_targets.copy()
        kb_targets = cfg.kb.indirect_jumps.resolved[_BASE].copy()
        edges = {(source.addr, target.addr) for source, target in cfg.graph.edges()}
        cfg._repair_guessed_jumptables()  # pylint:disable=protected-access
        assert cfg.jump_tables[_BASE].resolved_targets == targets
        assert cfg.kb.indirect_jumps.resolved[_BASE] == kb_targets
        assert {(source.addr, target.addr) for source, target in cfg.graph.edges()} == edges

    def test_repair_preserves_other_knowledge_base_targets(self):
        cfg, entries = _overlapping_tables(guessed=False)
        other_target = _BASE + 0x80
        cfg.kb.indirect_jumps.update_resolved_addrs(_BASE, [other_target])
        cfg.jump_tables[_BASE].jumptables[0].entries_guessed = True
        cfg._repair_guessed_jumptables()  # pylint:disable=protected-access
        assert cfg.jump_tables[_BASE].resolved_targets == set(entries[:2])
        assert set(cfg.kb.indirect_jumps.resolved[_BASE]) == set(entries[:2]) | {other_target}

    def test_data_reference_can_further_bound_a_guessed_table(self):
        cfg, entries = _overlapping_tables(repeated=True)
        cfg.kb.xrefs.add_xref(XRef(ins_addr=_BASE + 0x80, dst=_TABLE + 4, xref_type=XRefType.Read))
        cfg._repair_guessed_jumptables()  # pylint:disable=protected-access
        jump = cfg.jump_tables[_BASE]
        assert jump.jumptable_entries == entries[:1]
        assert jump.jumptable_size == 4
        assert jump.resolved_targets == set(entries[:1])
        assert set(cfg.kb.indirect_jumps.resolved[_BASE]) == set(entries[:1])
        source = cfg.model.get_any_node(_BASE)
        assert source is not None
        assert {node.addr for node in cfg.graph.successors(source)} == set(entries[:1])


if __name__ == "__main__":
    unittest.main()
