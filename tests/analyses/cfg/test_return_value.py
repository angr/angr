from __future__ import annotations

# pylint:disable=no-self-use,protected-access
import struct
import unittest
from unittest.mock import patch

import angr
from angr.analyses.cfg import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers import JumpTableResolver
from angr.analyses.cfg.indirect_jump_resolvers.return_value import get_x86_return_range
from angr.codenode import BlockNode
from angr.sim_type import SimTypeBool, SimTypeFunction

_SUMMARY = "angr.analyses.cfg.indirect_jump_resolvers.jumptable.get_x86_return_range"
_BASE = 0x400000
_CALLEE = _BASE + 0x80
_BOOLEAN = bytes.fromhex("8b44240485c00f95c0c3")


def _leaf(code):
    project = angr.load_shellcode(code, arch="x86", load_address=_BASE)
    cfg = project.analyses[CFGFast].prep(fail_fast=True)(normalize=True, force_complete_scan=False)
    return project, cfg, cfg.kb.functions[_BASE]


def _dispatch(leaf=_BOOLEAN, mask=False, zero_extend=True, post_call=b""):
    caller = b"\x50\xe8" + struct.pack("<i", _CALLEE - (_BASE + 6)) + b"\x83\xc4\x04"
    caller += post_call
    if zero_extend:
        caller += b"\x0f\xb6\xc0"
    if mask:
        caller += b"\x83\xe0\x01"
    caller += b"\xff\x24\x85" + struct.pack("<I", _BASE + 0x200)
    targets = [_BASE + len(caller), _BASE + len(caller) + 6]
    caller += bytes.fromhex("b801000000c3b802000000c3")
    data = (caller.ljust(0x80, b"\0") + leaf).ljust(0x200, b"\0") + struct.pack("<II", *targets)
    project = angr.load_shellcode(data.ljust(0x600, b"\0"), arch="x86", load_address=_BASE)
    cfg = project.analyses[CFGFast].prep(fail_fast=True)(
        regions=[(_BASE, _BASE + len(caller)), (_CALLEE, _CALLEE + len(leaf))],
        function_starts=[_BASE, _CALLEE],
        normalize=True,
        force_complete_scan=False,
    )
    return project, cfg, targets


class TestReturnValue(unittest.TestCase):
    """Conservative return summaries and their post-call jump-table integration."""

    def test_ranges_and_register_overlap(self):
        cases = {
            "boolean": (_BOOLEAN, (0, 1)),
            "zero": (bytes.fromhex("b000c3"), (0, 0)),
            "one": (bytes.fromhex("b001c3"), (1, 1)),
            "two": (bytes.fromhex("b002c3"), (2, 2)),
            "ah_only": (bytes.fromhex("0f95c0b4ffc3"), (0, 1)),
            "ax_overwrite": (bytes.fromhex("0f95c066b80200c3"), (2, 2)),
            "eax_overwrite": (bytes.fromhex("0f95c0b802000000c3"), (2, 2)),
            "volatile_register": (bytes.fromhex("b10188c8c3"), (1, 1)),
            "two_returns": (bytes.fromhex("85c07403b000c3b001c3"), (0, 1)),
            "non_boolean_return": (bytes.fromhex("85c07403b000c3b002c3"), (0, 2)),
            "join": (bytes.fromhex("85c07404b000eb02b001c3"), (0, 1)),
        }
        for name, (code, expected) in cases.items():
            with self.subTest(name=name):
                project, cfg, function = _leaf(code)
                assert get_x86_return_range(project, function, cfg.kb) == expected

    def test_unknown_return_is_not_boolean(self):
        for code in (b"\xc3", bytes.fromhex("0f95c088d0c3"), bytes.fromhex("89e0c3")):
            with self.subTest(code=code.hex()):
                project, cfg, function = _leaf(code)
                bounds = get_x86_return_range(project, function, cfg.kb)
                assert bounds is None or bounds == (0, 255)

    def test_callee_saved_register_writes(self):
        for opcode in (0xBB, 0xBD, 0xBE, 0xBF):
            with self.subTest(opcode=opcode):
                project, cfg, function = _leaf(bytes([opcode]) + bytes.fromhex("01000000b001c3"))
                assert get_x86_return_range(project, function, cfg.kb) is None

    def test_unsupported_effects_and_graphs(self):
        cases = {
            "global_load": bytes.fromhex("a010004000c3").ljust(16, b"\0") + b"\x01",
            "global_then_setcc": bytes.fromhex("a01000400084c00f95c0c3").ljust(16, b"\0") + b"\x01",
            "indirect_load": bytes.fromhex("8b4424048a00c3"),
            "store": bytes.fromhex("c60001b001c3"),
            "stack_store": bytes.fromhex("c6042401b001c3"),
            "push_pop": bytes.fromhex("5058b001c3"),
            "sp_write": bytes.fromhex("83c404b001c3"),
            "sp_overwrite": bytes.fromhex("bc00004000b001c3"),
            "ret_cleanup": bytes.fromhex("b001c20400"),
            "call": bytes.fromhex("e803000000b001c3c3"),
            "indirect_jump": bytes.fromhex("ffe0"),
            "cycle": bytes.fromhex("85c074fcb001c3"),
            "no_return": bytes.fromhex("ebfe"),
            "syscall": bytes.fromhex("cd80b001c3"),
            "dirty": bytes.fromhex("0fa2b001c3"),
            "privileged": bytes.fromhex("0f22c0b001c3"),
        }
        for name, code in cases.items():
            with self.subTest(name=name):
                project, cfg, function = _leaf(code)
                assert get_x86_return_range(project, function, cfg.kb) is None

    def test_missing_return_successor(self):
        project, cfg, function = _leaf(bytes.fromhex("85c07403b000c3b001c3"))
        graph = function.graph
        function.remove_graph_node(next(node for node in graph if node.addr == _BASE + 7))
        assert get_x86_return_range(project, function, cfg.kb) is None

    def test_extra_successor_and_unreachable_node(self):
        for reachable in (False, True):
            with self.subTest(reachable=reachable):
                project, cfg, function = _leaf(bytes.fromhex("b001c3"))
                graph = function.graph
                entry = next(iter(graph))
                extra = BlockNode(_BASE + 0x80, 3)
                function.register_node(True, extra)
                if reachable:
                    function.add_graph_edge(entry, extra, type="transition")
                assert len(function.graph) == 2
                assert get_x86_return_range(project, function, cfg.kb) is None

    def test_hooked_callee(self):
        project, cfg, function = _leaf(_BOOLEAN)
        project.hook(_BASE, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
        assert get_x86_return_range(project, function, cfg.kb) is None

    def test_cfgfast_recovers_exact_edges(self):
        with patch(_SUMMARY, return_value=None):
            _, baseline, _ = _dispatch()
        assert _BASE + 6 not in baseline.jump_tables
        _, cfg, targets = _dispatch()
        jump = cfg.jump_tables[_BASE + 6]
        assert jump.jumptable_entries == targets
        assert not jump.jumptable_entries_guessed
        node = cfg.model.get_any_node(_BASE + 6)
        assert node is not None
        assert {successor.addr for successor in cfg.graph.successors(node)} == set(targets)

    def test_existing_success_does_not_run_summary(self):
        with patch(_SUMMARY, side_effect=AssertionError("Summary must remain a fallback")):
            _, cfg, targets = _dispatch(mask=True)
        assert cfg.jump_tables[_BASE + 6].jumptable_entries == targets

    def test_al_only_injection(self):
        instrument = JumpTableResolver._instrument_statements
        observed = []

        def record(state, *args):
            observed.append((state.solver.max(state.regs.al), state.solver.max(state.regs.eax)))
            return instrument(state, *args)

        with patch.object(JumpTableResolver, "_instrument_statements", staticmethod(record)):
            _dispatch()
        assert any(al == 1 and eax > 255 for al, eax in observed)

    def test_no_zero_extension_preserves_existing_result(self):
        with patch(_SUMMARY, return_value=None):
            _, baseline, _ = _dispatch(zero_extend=False)
        _, cfg, _ = _dispatch(zero_extend=False)
        assert {addr: jump.jumptable_entries for addr, jump in cfg.jump_tables.items()} == {
            addr: jump.jumptable_entries for addr, jump in baseline.jump_tables.items()
        }

    def test_invalid_callsite_predecessors(self):
        for kind in ("multiple", "non_call", "non_fallthrough"):
            with self.subTest(kind=kind), patch(_SUMMARY, return_value=None) as summary:
                project, cfg, _ = _dispatch()
                summary.reset_mock()
                node = cfg.model.get_any_node(_BASE + 6)
                predecessor = cfg.model.get_any_node(_BASE)
                callee_node = cfg.model.get_any_node(_CALLEE)
                assert node is not None and predecessor is not None and callee_node is not None
                if kind == "multiple":
                    cfg.graph.add_edge(callee_node, node, jumpkind="Ijk_Boring")
                elif kind == "non_call":
                    cfg.graph.add_edge(predecessor, node, jumpkind="Ijk_Boring")
                else:
                    cfg.graph.remove_edge(predecessor, node)
                    cfg.graph.add_edge(callee_node, node, jumpkind="Ijk_FakeRet")
                assert JumpTableResolver(project)._get_return_range(cfg, _BASE + 6) is None
                summary.assert_not_called()

    def test_non_boolean_and_unsupported_callees_stay_unresolved(self):
        for leaf in (b"\xc3", bytes.fromhex("b002c3"), bytes.fromhex("c60001b001c3"), bytes.fromhex("a014004000c3")):
            with self.subTest(leaf=leaf.hex()):
                _, cfg, _ = _dispatch(leaf=leaf)
                assert _BASE + 6 not in cfg.jump_tables

    def test_caller_overwrites_return_value(self):
        for post_call in (bytes.fromhex("b002"), bytes.fromhex("88d0")):
            with self.subTest(post_call=post_call.hex()):
                _, cfg, _ = _dispatch(post_call=post_call)
                assert _BASE + 6 not in cfg.jump_tables

    def test_constant_boolean_dispatch(self):
        for value in (0, 1):
            with self.subTest(value=value):
                _, cfg, targets = _dispatch(leaf=bytes([0xB0, value, 0xC3]))
                assert set(cfg.indirect_jumps[_BASE + 6].resolved_targets) == {targets[value]}
                node = cfg.model.get_any_node(_BASE + 6)
                assert node is not None
                assert {successor.addr for successor in cfg.graph.successors(node)} == {targets[value]}
                assert _BASE + 6 not in cfg.jump_tables

    def test_work_limits(self):
        cases = {
            "blocks": bytes.fromhex("85c07402b000") * 4 + bytes.fromhex("b001c3"),
            "bytes": b"\x83\xc0\x01" * 86 + bytes.fromhex("b001c3"),
            "statements": b"\x31\xc8" * 80 + bytes.fromhex("b001c3"),
        }
        for kind, code in cases.items():
            with self.subTest(kind=kind):
                project, cfg, function = _leaf(code)
                if kind == "blocks":
                    assert len(function.graph) > 8
                elif kind == "bytes":
                    assert any(node.size > 256 for node in function.graph)
                else:
                    assert len(function.graph) <= 8 and all(node.size <= 256 for node in function.graph)
                    assert (
                        sum(
                            len(
                                project.factory.block(
                                    n.addr, size=n.size, opt_level=1, cross_insn_opt=False
                                ).vex.statements
                            )
                            for n in function.graph
                        )
                        > 256
                    )
                assert get_x86_return_range(project, function, cfg.kb) is None

    def test_project_initial_registers_are_not_callsite_invariants(self):
        project, cfg, function = _leaf(bytes.fromhex("88d0c3"))
        with patch.object(project.simos, "function_initial_registers", {"edx": 1}):
            bounds = get_x86_return_range(project, function, cfg.kb)
        assert bounds is None or bounds == (0, 255)

    def test_boolean_prototype_is_not_a_range(self):
        project, cfg, function = _leaf(b"\xc3")
        prototype = SimTypeFunction([], SimTypeBool()).with_arch(project.arch)
        assert isinstance(prototype, SimTypeFunction)
        function.prototype = prototype
        assert get_x86_return_range(project, function, cfg.kb) is None

    def test_all_setcc_conditions(self):
        for opcode in range(0x90, 0xA0):
            with self.subTest(opcode=opcode):
                project, cfg, function = _leaf(bytes([0x0F, opcode, 0xC0, 0xC3]))
                assert get_x86_return_range(project, function, cfg.kb) == (0, 1)

    def test_base_state_and_incomplete_caller_are_not_summarized(self):
        with patch(_SUMMARY, return_value=None) as summary:
            project, cfg, _ = _dispatch()
            summary.reset_mock()
            resolver = JumpTableResolver(project)
            resolver.base_state = project.factory.blank_state()
            assert resolver._get_return_range(cfg, _BASE + 6) is None
            resolver.base_state = None
            resolver.resolve(
                cfg,
                _BASE + 6,
                _BASE,
                project.factory.block(_BASE + 6).vex,
                "Ijk_Boring",
                func_graph_complete=False,
            )
            summary.assert_not_called()


if __name__ == "__main__":
    unittest.main()
