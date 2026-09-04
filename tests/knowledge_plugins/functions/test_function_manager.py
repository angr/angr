#!/usr/bin/env python3
# pylint:disable=no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import copy
import gc
import os
import pickle
import unittest
import weakref
from unittest import mock

import networkx
from archinfo import ArchAMD64
from networkx import NetworkXError

import angr
from angr.calling_conventions import SimCCUsercall, SimRegArg, SimStackArg
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.knowledge_plugins.functions import Function, FunctionManager
from angr.knowledge_plugins.functions.function_manager import FunctionDict
from angr.knowledge_plugins.functions.observable_graph import ObservableDiGraph, ObservableMultiDiGraph
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypePointer
from angr.utils.constants import DEFAULT_STATEMENT
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFunctionManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

    def test_amd64(self):
        expected_functions = {
            0x4004E0,
            0x400510,
            0x400520,
            0x400530,
            0x400540,
            0x400550,
            0x400560,
            0x400570,
            0x400580,
            0x4005AC,
            0x400640,
            0x400664,
            0x4006ED,
            0x4006FD,
            0x40071D,
            0x4007E0,
            0x400880,
        }
        expected_blocks = {
            0x40071D,
            0x40073E,
            0x400754,
            0x40076A,
            0x400774,
            0x40078A,
            0x4007A0,
            0x4007B3,
            0x4007C7,
            0x4007C9,
            0x4007BD,
            0x4007D3,
        }
        expected_callsites = {0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007BD, 0x4007C9}
        expected_callsite_targets = {4195600, 4195632, 4195940, 4196077, 4196093}
        expected_callsite_returns = {
            0x40073E,
            0x400754,
            0x40076A,
            0x400774,
            0x40078A,
            0x4007A0,
            0x4007B3,
            0x4007C7,
            None,
        }

        self.project.analyses.CFGEmulated()
        assert {k for k in self.project.kb.functions if k < 0x500000} == expected_functions

        main = self.project.kb.functions.function(name="main")
        assert main.startpoint.addr == 0x40071D
        assert set(main.block_addrs) == expected_blocks
        assert [bl.addr for bl in main.endpoints] == [0x4007D3]
        assert set(main.get_call_sites()) == expected_callsites
        assert set(map(main.get_call_target, main.get_call_sites())) == expected_callsite_targets
        assert set(map(main.get_call_return, main.get_call_sites())) == expected_callsite_returns
        assert main.has_return

        rejected = self.project.kb.functions.function(name="rejected")
        assert rejected.returning is False

        # transition graph
        main_g = main.transition_graph
        main_g_edges_ = main_g.edges(data=True)

        # Convert nodes those edges from blocks to addresses
        main_g_edges = []
        for src_node, dst_node, data in main_g_edges_:
            main_g_edges.append((src_node.addr, dst_node.addr, data))

        edges = [
            (0x40071D, 0x400510, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x400739}),
            (0x40071D, 0x400510, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x400739}),
            (0x40071D, 0x40073E, {"type": "fake_return", "confirmed": True, "outside": False}),
            (0x40073E, 0x400530, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x40074F}),
            (0x40073E, 0x400754, {"type": "fake_return", "confirmed": True, "outside": False}),
            # rejected() does not return
            (0x4007C9, 0x4006FD, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x4007CE}),
            (0x4007C9, 0x4007D3, {"type": "fake_return", "outside": False}),
        ]
        for edge in edges:
            assert edge in main_g_edges

        # test function renaming
        rejected.name = "renamed_rejected"
        assert self.project.kb.functions.function(name="rejected") is None
        assert self.project.kb.functions.function(name="rejected", check_previous_names=True) is rejected
        assert self.project.kb.functions.function(name="rejected", check_previous_names=True).name == "renamed_rejected"
        assert self.project.kb.functions.function(name="rejected", check_previous_names=True).previous_names == [
            "rejected"
        ]

        # These tests fail for reasons of fastpath, probably
        # assert main.bp_on_stack
        # assert main.name == 'main'
        # assert main.retaddr_on_stack
        # assert 0x50 == main.sp_difference

        # TODO: Check the result returned
        # func_man.dbg_draw()

    def test_call_to(self):
        self.project.arch = ArchAMD64()

        self.project.kb.functions._add_call_to(0x400000, 0x400410, 0x400420, 0x400414)
        assert 0x400000 in self.project.kb.functions
        assert 0x400420 in self.project.kb.functions

    def test_query(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, data_references=True)

        assert proj.kb.functions["::read"].addr == 0x400530
        assert proj.kb.functions["::0x400530::read"].addr == 0x400530
        assert proj.kb.functions["::libc.so.0::read"].addr == 0x700010
        with self.assertRaises(KeyError):
            proj.kb.functions["::0x400531::read"]  # pylint:disable=pointless-statement
        with self.assertRaises(KeyError):
            proj.kb.functions["::bad::read"]  # pylint:disable=pointless-statement

    def test_codenode_semantic_identity_seals_on_graph_binding(self):
        node = BlockNode(0xDEAD_1000, 4, thumb=False)
        hash(node)
        for field, temporary in (("addr", 0xDEAD_1001), ("size", 5), ("thumb", True)):
            original = getattr(node, field)
            setattr(node, field, temporary)
            setattr(node, field, original)

        graph = ObservableDiGraph()
        node.set_graph(graph)
        node.set_graph(graph)
        graph.add_node(node)
        for field, changed in (("addr", 0xDEAD_1001), ("size", 1), ("thumb", True)):
            original = getattr(node, field)
            setattr(node, field, original)
            if type(original) is int:  # bool is handled by the identity case above
                setattr(node, field, int(str(original)))
            with self.assertRaisesRegex(ValueError, "copy and replace"):
                setattr(node, field, changed)
            with self.assertRaisesRegex(ValueError, "copy and replace"):
                delattr(node, field)
            assert getattr(node, field) == original
            assert node in graph

        graph.remove_node(node)
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            node.size = 1
        with self.assertRaisesRegex(ValueError, "copied before insertion"):
            node.set_graph(ObservableDiGraph())
        with self.assertRaisesRegex(ValueError, "cannot be reinitialized"):
            node.__init__(node.addr, node.size, thumb=node.thumb)

        dead_graph = ObservableDiGraph()
        dead_node = BlockNode(0xDEAD_1010, 2)
        dead_node.set_graph(dead_graph)
        dead_graph_ref = weakref.ref(dead_graph)
        del dead_graph
        gc.collect()
        assert dead_graph_ref() is None
        with self.assertRaisesRegex(ValueError, "collected graph"):
            dead_node.set_graph(ObservableDiGraph())
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            dead_node.addr = 0xDEAD_1011

        for clone in (copy.copy(node), copy.deepcopy(node), pickle.loads(pickle.dumps(node, -1))):
            assert clone._graph is None
            assert not clone._semantic_identity_sealed
            clone.addr += 1
            clone.addr -= 1
            clone.size += 1
            clone.size -= 1
            clone.thumb = not clone.thumb
            clone.thumb = not clone.thumb

        edited_after_hash = BlockNode(0xDEAD_1012, 2)
        hash(edited_after_hash)
        edited_after_hash.addr = 0xDEAD_1013
        edited_after_hash.size = 3
        edited_graph = ObservableDiGraph()
        edited_after_hash.set_graph(edited_graph)
        edited_graph.add_node(edited_after_hash)
        equivalent = BlockNode(0xDEAD_1013, 3)
        assert equivalent == edited_after_hash
        assert equivalent in edited_graph

        for offset, field in enumerate(("addr", "size", "thumb")):
            complete = BlockNode(0xDEAD_1014 + offset, 2)
            with self.assertRaisesRegex(ValueError, "required CodeNode"):
                delattr(complete, field)
            complete_graph = ObservableDiGraph()
            complete.set_graph(complete_graph)
            complete_graph.add_node(complete)
            assert complete._graph_owner() is complete_graph

        unknown_name = "unknown-callee"
        unknown = FuncNode(-1, unknown_name)
        unknown_graph = ObservableDiGraph()
        with self.assertRaisesRegex(ValueError, "required CodeNode"):
            del unknown.func_name
        unknown.set_graph(unknown_graph)
        unknown_graph.add_node(unknown)
        unknown.func_name = unknown_name
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            unknown.func_name = f"{unknown_name}-changed"
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            del unknown.func_name
        assert unknown in unknown_graph

        known = FuncNode(0xDEAD_1020, "before")
        known_graph = ObservableDiGraph()
        known.set_graph(known_graph)
        known.func_name = "after"
        assert known.func_name == "after"

        hook = HookNode(0xDEAD_1030, 1, None)
        hook_graph = ObservableDiGraph()
        with self.assertRaisesRegex(ValueError, "required CodeNode"):
            del hook.sim_procedure
        hook.set_graph(hook_graph)
        hook_graph.add_node(hook)
        hook.sim_procedure = None
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            hook.sim_procedure = mock.sentinel.replacement_hook
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            del hook.sim_procedure
        assert hook in hook_graph

        function = Function(
            None,
            0xDEAD_1040,
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=True,
            binary_name="test",
        )
        owned = BlockNode(function.addr, 2)
        function.transition_graph.add_node(owned)
        assert owned._graph_owner() is function.transition_graph
        assert owned._semantic_identity_sealed

        class FailingBlockNode(BlockNode):
            def set_graph(self, new_graph):
                super().set_graph(new_graph)
                raise RuntimeError("node binding failed")

        rejected = FailingBlockNode(0xDEAD_1041, 1)
        with self.assertRaisesRegex(RuntimeError, "node binding failed"):
            function.transition_graph.add_node(rejected)
        assert rejected not in function.transition_graph
        assert rejected._graph is None
        assert not rejected._semantic_identity_sealed
        rejected.size = 2

        copied_function = function.copy()
        copied_owned = next(iter(copied_function.transition_graph))
        assert copied_owned is not owned
        assert copied_owned._semantic_identity_sealed
        assert copied_owned._graph_owner() is copied_function.transition_graph
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            copied_owned.size += 1

        roundtripped_function = pickle.loads(pickle.dumps(copied_function, -1))
        roundtripped_owned = next(iter(roundtripped_function.transition_graph))
        assert roundtripped_owned._semantic_identity_sealed
        assert roundtripped_owned._graph_owner() is roundtripped_function.transition_graph
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            roundtripped_owned.thumb = not roundtripped_owned.thumb

    def test_funcnode_hash_matches_equality(self):
        known = FuncNode(0xDEAD_1050, "before")
        equivalent_known = FuncNode(known.addr, "different")
        self.assertEqual(known, equivalent_known)
        self.assertTrue(equivalent_known == known)
        self.assertEqual(hash(known), hash(equivalent_known))

        known_dict = {known: "known"}
        known_set = {known}
        graph = ObservableDiGraph()
        graph.add_node(known)
        known.func_name = "after"
        lookup = FuncNode(known.addr, "lookup")
        self.assertEqual(known_dict[known], "known")
        self.assertEqual(known_dict[lookup], "known")
        self.assertIn(known, known_set)
        self.assertIn(lookup, known_set)
        self.assertIn(known, graph)
        self.assertIn(lookup, graph)

        unknown = FuncNode(-1, "unknown")
        equivalent_unknown = FuncNode(-1, "unknown")
        different_unknown = FuncNode(-1, "different")
        self.assertEqual(unknown, equivalent_unknown)
        self.assertEqual(hash(unknown), hash(equivalent_unknown))
        self.assertNotEqual(unknown, different_unknown)
        self.assertEqual(len({unknown, equivalent_unknown, different_unknown}), 2)

        different_size = FuncNode(known.addr, known.func_name)
        different_size.size = 1
        different_thumb = FuncNode(known.addr, known.func_name, thumb=True)
        self.assertNotEqual(known, different_size)
        self.assertNotEqual(known, different_thumb)

        class SpecializedFuncNode(FuncNode):
            pass

        specialized = SpecializedFuncNode(known.addr, known.func_name)
        self.assertNotEqual(known, specialized)
        self.assertTrue(specialized != known)
        self.assertEqual(len({known, specialized}), 2)

    def test_funcnode_copy_and_pickle_preserve_semantic_identity(self):
        for node in (FuncNode(0xDEAD_1060, "known", thumb=True), FuncNode(-1, "unknown", thumb=True)):
            node.size = 7
            for clone in (copy.copy(node), copy.deepcopy(node), pickle.loads(pickle.dumps(node, -1))):
                self.assertIs(type(clone), type(node))
                self.assertEqual(clone, node)
                self.assertEqual(hash(clone), hash(node))
                self.assertEqual(clone.size, 7)
                self.assertIs(clone.thumb, True)
                self.assertIsNone(clone._graph)
                self.assertFalse(clone._semantic_identity_sealed)

        legacy = FuncNode.__new__(FuncNode)
        legacy.__setstate__((0xDEAD_1061, "legacy"))
        self.assertEqual(legacy, FuncNode(0xDEAD_1061, "different-known-name"))
        self.assertEqual(legacy.size, 0)
        self.assertIs(legacy.thumb, False)

        rejected = FuncNode.__new__(FuncNode)
        with self.assertRaisesRegex(TypeError, "pickle state type"):
            rejected.__setstate__(None)
        for malformed in ((1,), (1, None, 0), (1, None, 0, False, "extra")):
            rejected = FuncNode.__new__(FuncNode)
            with self.assertRaisesRegex(ValueError, "pickle state length"):
                rejected.__setstate__(malformed)

    def test_funcnode_function_copy_preserves_semantic_identity(self):
        function = Function(
            None,
            0xDEAD_1070,
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=True,
            binary_name="test",
        )
        callee = FuncNode(0xDEAD_1071, "callee", thumb=True)
        callee.size = 7
        function.transition_graph.add_node(callee)

        for copied_function in (function.copy(), pickle.loads(pickle.dumps(function, -1))):
            copied_callee = next(iter(copied_function.transition_graph))
            self.assertIsNot(copied_callee, callee)
            self.assertEqual(copied_callee, callee)
            self.assertEqual(hash(copied_callee), hash(callee))
            self.assertEqual(copied_callee.size, 7)
            self.assertIs(copied_callee.thumb, True)
            self.assertTrue(copied_callee._semantic_identity_sealed)
            self.assertIs(copied_callee._graph_owner(), copied_function.transition_graph)

    def test_function_graph_ownership_and_snapshot_views(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]

        main._callout_sites.add(main.startpoint)
        main._add_endpoint(main.startpoint, "call")
        argument_register = next(iter(proj.arch.argument_registers))
        main._add_argument_register(argument_register)
        main._add_argument_stack_variable(0x10)
        main.from_signature = "flirt"
        main.is_default_name = True
        main.tags = {"nested": ["source"]}
        main.prototype = SimTypeFunction((SimTypePointer(SimTypeBottom()),), SimTypeInt()).with_arch(proj.arch)
        main.calling_convention = SimCCUsercall(
            proj.arch,
            [SimRegArg("rdi", proj.arch.bytes), SimStackArg(0, proj.arch.bytes)],
            SimRegArg("rax", proj.arch.bytes),
        )
        copied = main.copy()
        copied_twice = copied.copy()
        assert copied._function_manager is None
        assert copied_twice._function_manager is None
        assert copied.startpoint is not main.startpoint
        assert copied_twice.startpoint is not copied.startpoint
        assert {node.addr for node in copied.callout_sites} == {node.addr for node in main.callout_sites}
        assert all(
            copied_node is not source_node for copied_node in copied.callout_sites for source_node in main.callout_sites
        )
        assert copied._argument_registers == [argument_register]
        assert copied._argument_stack_variables == [0x10]
        assert copied.from_signature == "flirt"
        assert copied.is_default_name
        assert copied.tags == main.tags
        copied.tags["nested"].append("copy")
        assert main.tags == {"nested": ["source"]}
        assert copied.prototype is not main.prototype
        assert copied_twice.prototype is not copied.prototype
        assert copied.prototype.args[0] is not main.prototype.args[0]
        assert copied.prototype.returnty is not main.prototype.returnty
        assert copied.prototype._arch is main.prototype._arch
        assert copied.prototype.args[0]._arch is main.prototype.args[0]._arch is proj.arch
        assert copied.prototype.returnty._arch is main.prototype.returnty._arch is proj.arch
        assert copied.calling_convention is not main.calling_convention
        assert copied_twice.calling_convention is not copied.calling_convention
        assert copied.calling_convention.arch is main.calling_convention.arch is proj.arch
        assert copied.calling_convention.args is not main.calling_convention.args
        assert copied.calling_convention.args[0] is not main.calling_convention.args[0]
        assert copied.calling_convention.ret_loc is not main.calling_convention.ret_loc
        assert copied._project is main._project

        copied.prototype.args[0].offset = 4
        copied.prototype.args[0].pts_to.label = "copy-only"
        copied.prototype.args = ()
        copied.prototype.returnty = SimTypeLongLong().with_arch(proj.arch)
        copied.calling_convention.args.append(SimRegArg("rsi", proj.arch.bytes))
        copied.calling_convention.args[0].reg_name = "rcx"
        copied.calling_convention.ret_loc.reg_name = "rdx"
        assert len(main.prototype.args) == 1
        assert main.prototype.args[0].offset == 0
        assert main.prototype.args[0].pts_to.label is None
        assert isinstance(main.prototype.returnty, SimTypeInt)
        assert len(main.calling_convention.args) == 2
        assert main.calling_convention.args[0].reg_name == "rdi"
        assert main.calling_convention.ret_loc.reg_name == "rax"
        assert len(copied_twice.prototype.args) == 1
        assert copied_twice.prototype.args[0].offset == 0
        assert copied_twice.prototype.args[0].pts_to.label is None
        assert len(copied_twice.calling_convention.args) == 2
        assert copied_twice.calling_convention.args[0].reg_name == "rdi"
        assert copied_twice.calling_convention.ret_loc.reg_name == "rax"
        for source_node in main.transition_graph:
            copied_node = next(node for node in copied.transition_graph if node == source_node)
            assert copied_node is not source_node
            assert {node.addr for node in copied_node.successors()} == {
                node.addr for node in main.transition_graph.successors(source_node)
            }
            assert all(successor in copied.transition_graph for successor in copied_node.successors())
        for copied_node in copied.transition_graph:
            copied_twice_node = next(node for node in copied_twice.transition_graph if node == copied_node)
            assert copied_twice_node is not copied_node
            assert all(successor in copied_twice.transition_graph for successor in copied_twice_node.successors())

        roundtripped = pickle.loads(pickle.dumps(copied, -1))
        for node in roundtripped.transition_graph:
            assert node.successors() == list(roundtripped.transition_graph.successors(node))
            assert node.predecessors() == list(roundtripped.transition_graph.predecessors(node))

        endpoint_snapshot = main.endpoints_with_type
        expected_return_sites = set(main.endpoints_with_type["return"])
        endpoint_snapshot["return"].clear()
        endpoint_snapshot["invented"].add(BlockNode(0xBAD0, 1))
        assert set(main.endpoints_with_type["return"]) == expected_return_sites
        assert "invented" not in main.endpoints_with_type

        generation = functions.function_graph_generation
        copied.startpoint = next(node for node in copied.transition_graph if node is not copied.startpoint)
        assert functions.function_graph_generation == generation

        cached_graph = main.graph
        assert main._local_transition_graph is cached_graph
        generation = functions.function_graph_generation
        main.startpoint = main.startpoint
        assert functions.function_graph_generation == generation
        assert main._local_transition_graph is cached_graph
        main.startpoint = next(node for node in main.transition_graph if node is not main.startpoint)
        assert functions.function_graph_generation != generation
        assert main._local_transition_graph is None

    def test_function_manager_copy_and_replacement_ownership(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]
        manager_copy = functions.copy()

        generation = functions.function_graph_generation
        copy_generation = manager_copy.function_graph_generation
        manager_copy[main.addr] = main
        assert functions.function_graph_generation == generation
        assert manager_copy.function_graph_generation == copy_generation
        assert main._function_manager._function_map is functions._function_map

        other_kb = angr.KnowledgeBase(proj)
        source_generation = functions.function_graph_generation
        target_generation = other_kb.functions.function_graph_generation
        source_trust = functions.callgraph_trusted
        target_trust = other_kb.functions.callgraph_trusted
        with self.assertRaises(ValueError):
            other_kb.functions[main.addr] = main
        assert other_kb.functions.get(main.addr, None) is None
        assert main._function_manager._function_map is functions._function_map
        assert functions.function_graph_generation == source_generation
        assert other_kb.functions.function_graph_generation == target_generation
        assert functions.callgraph_trusted == source_trust
        assert other_kb.functions.callgraph_trusted == target_trust

        replacement = main.copy()
        replacement.transition_graph.clear_edges()
        functions[main.addr] = replacement
        assert main._function_manager is None
        assert replacement._function_manager._function_map is functions._function_map
        assert not functions.callgraph_trusted
        with self.assertRaises(ValueError):
            functions[replacement.addr + 1] = replacement

    def test_untrusted_callgraph_stays_untrusted_across_pickle(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]
        functions.add_key_func_addr("alloca_probe", main.addr)
        functions.callgraph.add_edge(main.addr, 0xDEAD_0000, type="call")
        assert not functions.callgraph_trusted

        roundtripped = pickle.loads(pickle.dumps(proj, -1))
        assert not roundtripped.kb.functions.callgraph_trusted
        roundtripped_main = roundtripped.kb.functions["main"]
        assert roundtripped.kb.functions.get_key_func_addrs("alloca_probe") == {roundtripped_main.addr}
        assert roundtripped.kb.functions.get_key_func_type_and_addrs()["alloca_probe"] == {roundtripped_main.addr}
        roundtripped.kb.functions.add_key_func_addr("jmp_rax", roundtripped_main.addr)
        assert roundtripped.kb.functions.get_key_func_addrs("jmp_rax") == {roundtripped_main.addr}
        argument_register = next(iter(roundtripped.arch.argument_registers))
        roundtripped_main._add_argument_register(argument_register)
        assert argument_register in roundtripped_main.arguments

    def test_legacy_manager_pickle_rebuilds_key_and_argument_caches(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        main = proj.kb.functions["main"]
        main.info["is_alloca_probe"] = True

        legacy_state = proj.kb.functions.__getstate__().copy()
        function_map = FunctionDict(None, key_types=proj.kb.functions.function_address_types)
        for addr, func in proj.kb.functions.items():
            function_map[addr] = func.copy()
        legacy_state["_function_map"] = function_map
        legacy_state["callgraph"] = proj.kb.functions.callgraph.copy()
        del legacy_state["key_func_addrs"]
        del legacy_state["arg_registers"]
        restored = FunctionManager.__new__(FunctionManager)
        restored.__setstate__(legacy_state)
        restored.set_kb(proj.kb)

        restored_main = restored[main.addr]
        assert restored.get_key_func_addrs("alloca_probe") == {main.addr}
        argument_register = next(iter(proj.arch.argument_registers))
        restored_main._add_argument_register(argument_register)
        assert argument_register in restored_main.arguments

    def test_public_function_graph_mutations_advance_generation(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]

        def generation() -> int:
            return int(functions.function_graph_generation.rsplit(":", 1)[1])

        node_a = BlockNode(0xDEAD_0000, 1)
        node_b = BlockNode(0xDEAD_0001, 1)
        before = generation()
        main.transition_graph.add_nodes_from([node_a, node_b])
        assert generation() == before + 1

        before = generation()
        main.transition_graph.add_nodes_from([node_a, node_b])
        assert generation() == before

        before = generation()
        main.transition_graph.add_edges_from(
            [(node_a, node_b, {"type": "transition"}), (node_b, node_a, {"type": "transition"})]
        )
        assert generation() == before + 1

        before = generation()
        main.transition_graph.add_edge(node_a, node_b, type="transition")
        assert generation() == before

        edge_dicts = (
            main.transition_graph.edges[node_a, node_b],
            main.transition_graph[node_a][node_b],
            main.transition_graph.adj[node_a][node_b],
            main.transition_graph.succ[node_a][node_b],
            main.transition_graph.pred[node_b][node_a],
        )
        for idx, edge_data in enumerate(edge_dicts):
            _ = main.graph
            assert main._local_transition_graph is not None
            before = generation()
            edge_data["type"] = f"transition-{idx}"
            assert generation() == before + 1
            assert main._local_transition_graph is None

        edge_data = main.transition_graph[node_a][node_b]
        _ = main.cyclomatic_complexity
        assert main._cyclomatic_complexity is not None
        before = generation()
        edge_data.update(type=edge_data["type"])
        edge_data.setdefault("type", "ignored")
        assert generation() == before

        baseline_type = edge_data["type"]
        before = generation()
        edge_data.update((("type", "temporary"), ("type", baseline_type)))
        assert generation() == before
        main.transition_graph.add_edges_from(
            (
                (node_a, node_b, {"type": "temporary"}),
                (node_a, node_b, {"type": baseline_type}),
            )
        )
        assert generation() == before

        edge_data["weight"] = 7
        before = generation()
        main.transition_graph.add_weighted_edges_from(((node_a, node_b, 9), (node_a, node_b, 7)))
        assert generation() == before

        def partial_aba_edge_data():
            yield "type", "temporary"
            yield "type", baseline_type
            raise ValueError("edge metadata update failed after returning to its baseline")

        before = generation()
        with self.assertRaises(ValueError):
            edge_data.update(partial_aba_edge_data())
        assert generation() == before + 1

        def partial_aba_edges():
            yield node_a, node_b, {"type": "temporary"}
            yield node_a, node_b, {"type": baseline_type}
            raise ValueError("bulk edge update failed after returning to its baseline")

        before = generation()
        with self.assertRaises(ValueError):
            main.transition_graph.add_edges_from(partial_aba_edges())
        assert generation() == before + 1

        before = generation()
        edge_data.setdefault("outside", True)
        assert generation() == before + 1
        assert main._cyclomatic_complexity is None
        before = generation()
        assert edge_data.pop("outside") is True
        assert generation() == before + 1
        before = generation()
        edge_data |= {"outside": False}
        assert generation() == before + 1

        class Uncomparable:
            def __eq__(self, other):
                raise TypeError

        before = generation()
        edge_data["opaque"] = Uncomparable()
        assert generation() == before + 1
        before = generation()
        edge_data["opaque"] = Uncomparable()
        assert generation() == before + 1

        def partial_edge_data():
            yield "prefix", True
            raise ValueError

        before = generation()
        with self.assertRaises(ValueError):
            edge_data.update(partial_edge_data())
        assert edge_data["prefix"] is True
        assert generation() == before + 1

        detached = main.transition_graph.copy()
        before = generation()
        detached.add_edge(node_a, BlockNode(0xDEAD_0002, 1))
        assert generation() == before

        before = generation()
        main.transition_graph.remove_edges_from([(node_a, node_b), (node_b, node_a)])
        assert generation() == before + 1
        before = generation()
        main.transition_graph.remove_edges_from([(node_a, node_b), (node_b, node_a)])
        assert generation() == before

        partial_node = BlockNode(0xDEAD_0003, 1)

        def partial_nodes():
            yield partial_node
            raise ValueError

        before = generation()
        with self.assertRaises(ValueError):
            main.transition_graph.add_nodes_from(partial_nodes())
        assert partial_node in main.transition_graph
        assert partial_node.successors() == []
        assert generation() == before + 1

        partial_edge_node = BlockNode(0xDEAD_0004, 1)

        def partial_edges():
            yield partial_node, partial_edge_node, {"type": "transition"}
            raise ValueError

        before = generation()
        with self.assertRaises(ValueError):
            main.transition_graph.add_edges_from(partial_edges())
        assert main.transition_graph.has_edge(partial_node, partial_edge_node)
        assert partial_edge_node.successors() == []
        assert generation() == before + 1

        cg_node_a, cg_node_b = 0xBEEF_0000, 0xBEEF_0001
        before = generation()
        functions.callgraph.add_nodes_from([cg_node_a, cg_node_b])
        assert generation() == before + 1
        before = generation()
        functions.callgraph.add_nodes_from([cg_node_a, cg_node_b])
        assert generation() == before

        before = generation()
        edge_key = functions.callgraph.add_edge(cg_node_a, cg_node_b, type="call")
        assert generation() == before + 1
        before = generation()
        functions.callgraph[cg_node_a][cg_node_b][edge_key]["type"] = "transition"
        assert generation() == before + 1
        assert not functions.callgraph_trusted
        before = generation()
        functions.callgraph[cg_node_a][cg_node_b][edge_key]["type"] = "transition"
        assert generation() == before

        detached_callgraph = functions.callgraph.copy()
        before = generation()
        detached_callgraph.add_edge(cg_node_b, cg_node_a)
        assert generation() == before

        other = functions.function(addr=0xDEAD_0100, create=True)
        assert other is not None
        other.transition_graph = main.transition_graph.copy()
        assert other.transition_graph is not main.transition_graph
        for source_node in main.transition_graph:
            other_node = next(node for node in other.transition_graph if node == source_node)
            assert other_node is not source_node
            assert source_node.successors() == list(main.transition_graph.successors(source_node))
            assert all(successor in other.transition_graph for successor in other_node.successors())
            assert all(
                successor is not source_successor
                for successor in other_node.successors()
                for source_successor in main.transition_graph
            )
        source_only_node = BlockNode(0xDEAD_0101, 1)
        before = generation()
        main.transition_graph.add_node(source_only_node)
        assert generation() == before + 1
        assert source_only_node.successors() == []
        before = generation()
        with self.assertRaises(ValueError):
            other.transition_graph.add_node(source_only_node)
        assert generation() == before
        assert source_only_node not in other.transition_graph
        assert source_only_node.successors() == []
        graphless_node = BlockNode(0xDEAD_0103, 1)
        before = generation()
        with self.assertRaises(ValueError):
            other.transition_graph.add_edge(graphless_node, source_only_node, type="transition")
        assert generation() == before
        assert graphless_node not in other.transition_graph
        assert graphless_node._graph is None

        other_kb = angr.KnowledgeBase(proj)
        target = Function(
            other_kb.functions,
            0xDEAD_0200,
            name="target",
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=True,
        )
        other_kb.functions[target.addr] = target
        target_graph = target.graph
        target_complexity = target.cyclomatic_complexity
        target_dirty = target.dirty
        source_generation = functions.function_graph_generation
        target_generation = other_kb.functions.function_graph_generation
        source_trust = functions.callgraph_trusted
        target_trust = other_kb.functions.callgraph_trusted
        source_topology = (main.transition_graph.number_of_nodes(), main.transition_graph.number_of_edges())
        source_successors = source_only_node.successors()
        with self.assertRaises(ValueError):
            target.add_jumpout_site(source_only_node)
        assert functions.function_graph_generation == source_generation
        assert other_kb.functions.function_graph_generation == target_generation
        assert functions.callgraph_trusted == source_trust
        assert other_kb.functions.callgraph_trusted == target_trust
        assert target.transition_graph.number_of_nodes() == 0
        assert (main.transition_graph.number_of_nodes(), main.transition_graph.number_of_edges()) == source_topology
        assert target.endpoints == []
        assert target._local_transition_graph is target_graph
        assert target.cyclomatic_complexity == target_complexity
        assert target.dirty == target_dirty
        assert source_only_node._graph == main.transition_graph
        assert source_only_node.successors() == source_successors

        outside_node = BlockNode(0xDEAD_0201, 1)
        assert target._register_node(False, outside_node) is outside_node
        equal_local_node = BlockNode(outside_node.addr, outside_node.size)
        registered_local_node = target._register_node(True, equal_local_node)
        assert registered_local_node is outside_node
        assert target._local_blocks[outside_node.addr] is outside_node
        assert outside_node.successors() == []
        assert equal_local_node._graph is None
        before = generation()
        other.transition_graph.add_node(BlockNode(0xDEAD_0102, 1))
        assert generation() == before + 1

        manager_copy = functions.copy()
        manager_copy.callgraph = functions.callgraph
        assert manager_copy.callgraph is not functions.callgraph
        copy_generation = manager_copy.function_graph_generation
        before = generation()
        functions.callgraph.add_node(0xBEEF_0002)
        assert generation() == before + 1
        assert manager_copy.function_graph_generation == copy_generation
        copy_generation = manager_copy.function_graph_generation
        manager_copy.callgraph.add_node(0xBEEF_0003)
        assert manager_copy.function_graph_generation != copy_generation

        before = generation()
        functions.callgraph.remove_edge(cg_node_a, cg_node_b, edge_key)
        assert generation() == before + 1
        before = generation()
        with self.assertRaises(NetworkXError):
            functions.callgraph.remove_edge(cg_node_a, cg_node_b, edge_key)
        assert generation() == before

        functions.rebuild_callgraph()
        assert functions.callgraph_trusted
        real_source, real_destination, real_key, real_data = next(iter(functions.callgraph.edges(keys=True, data=True)))
        callgraph_type = real_data["type"]
        before = generation()
        functions.callgraph.add_edges_from(
            (
                (real_source, real_destination, real_key, {"type": "temporary"}),
                (real_source, real_destination, real_key, {"type": callgraph_type}),
            )
        )
        assert generation() == before
        assert functions.callgraph_trusted

    def test_removed_edge_metadata_handles_are_detached(self):
        events = []

        def graph_mutated():
            events.append(True)

        for graph_type in (ObservableDiGraph, ObservableMultiDiGraph):
            with self.subTest(graph_type=graph_type.__name__, removal="edge"):
                graph = graph_type(mutation_callback=graph_mutated)
                key = graph.add_edge(1, 2, type="call")
                data = graph[1][2][key] if graph.is_multigraph() else graph[1][2]
                events.clear()
                graph.remove_edge(1, 2, key) if graph.is_multigraph() else graph.remove_edge(1, 2)
                assert len(events) == 1
                events.clear()
                data["type"] = "detached"
                assert not events

            with self.subTest(graph_type=graph_type.__name__, removal="clear_edges"):
                graph = graph_type(mutation_callback=graph_mutated)
                key = graph.add_edge(1, 2, type="call")
                data = graph[1][2][key] if graph.is_multigraph() else graph[1][2]
                events.clear()
                graph.clear_edges()
                assert len(events) == 1
                events.clear()
                data["type"] = "detached"
                assert not events

            with self.subTest(graph_type=graph_type.__name__, removal="node"):
                graph = graph_type(mutation_callback=graph_mutated)
                key = graph.add_edge(1, 2, type="call")
                data = graph[1][2][key] if graph.is_multigraph() else graph[1][2]
                events.clear()
                graph.remove_node(1)
                assert len(events) == 1
                events.clear()
                data["type"] = "detached"
                assert not events

    def test_singular_graph_mutations_do_not_scan_all_edges(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]

        node_a = BlockNode(0xDEAD_1000, 1)
        node_b = BlockNode(0xDEAD_1001, 1)
        generation = functions.function_graph_generation
        with mock.patch.object(main.transition_graph, "number_of_edges", side_effect=AssertionError):
            main.transition_graph.add_node(node_a)
            main.transition_graph.add_edge(node_a, node_b)
            main.transition_graph.add_edge(node_a, node_b)
            main.transition_graph.remove_edge(node_a, node_b)
            main.transition_graph.remove_node(node_b)
        assert functions.function_graph_generation != generation

        class NoIterationDict(dict):
            def __iter__(self):
                raise AssertionError("A singular multigraph mutation must not scan parallel edge keys")

        graph_events = []

        def graph_mutated():
            graph_events.append(True)

        multigraph = ObservableMultiDiGraph(mutation_callback=graph_mutated)
        for key in range(8192):
            networkx.MultiDiGraph.add_edge(multigraph, 1, 2, key=key)
        keydict = NoIterationDict(multigraph._succ[1][2])
        multigraph._succ[1][2] = keydict
        multigraph._pred[2][1] = keydict
        graph_events.clear()
        multigraph.add_edge(1, 2, key=8192)
        assert len(graph_events) == 1
        graph_events.clear()
        multigraph.remove_edge(1, 2, key=8192)
        assert len(graph_events) == 1

        generation = functions.function_graph_generation
        with mock.patch.object(functions.callgraph, "number_of_edges", side_effect=AssertionError):
            edge_key = functions.callgraph.add_edge(0xDEAD_2000, 0xDEAD_2001)
            functions.callgraph.add_edge(0xDEAD_2000, 0xDEAD_2001, key=edge_key)
            functions.callgraph.remove_edge(0xDEAD_2000, 0xDEAD_2001, edge_key)
            functions.callgraph.remove_node(0xDEAD_2001)
        assert functions.function_graph_generation != generation

    def test_observable_graph_adversarial_mutations_are_exact_and_atomic(self):
        graph_events = []

        def graph_mutated():
            graph_events.append(True)

        graph = ObservableDiGraph(mutation_callback=graph_mutated)
        graph.add_nodes_from((1, 2))
        graph_events.clear()

        class RaisingPairs:
            def __iter__(self):
                yield "partial", 1
                raise RuntimeError("attribute iteration failed")

        with self.assertRaises(RuntimeError):
            graph.add_edges_from(((1, 2, RaisingPairs()),))
        assert not graph.has_edge(1, 2)
        assert not graph_events

        graph.add_edge(1, 2)
        edge_data = graph[1][2]

        class MutatingTruth:
            def __init__(self, side_key):
                self.side_key = side_key

            def __bool__(self):
                edge_data[self.side_key] = True
                return False

        class MutatingEquality:
            def __init__(self, side_key):
                self.side_key = side_key

            def __eq__(self, _other):
                return MutatingTruth(self.side_key)

        edge_data["value"] = MutatingEquality("setitem_side_effect")
        graph_events.clear()
        edge_data["value"] = object()
        assert edge_data["setitem_side_effect"] is True
        assert len(graph_events) == 1

        edge_data["value"] = MutatingEquality("update_side_effect")
        graph_events.clear()
        edge_data.update({"value": object()})
        assert edge_data["update_side_effect"] is True
        assert len(graph_events) == 1

        class GraphSnapshotEquality:
            def __init__(self):
                self.edge_data = None

            def __eq__(self, _other):
                if self.edge_data is not None:
                    self.edge_data["graph_snapshot_side_effect"] = True
                return True

        old_value = GraphSnapshotEquality()
        edge_data["value"] = old_value
        old_value.edge_data = edge_data
        graph_events.clear()
        graph.add_edges_from(((1, 2, {"value": object()}), (1, 2, {"value": GraphSnapshotEquality()})))
        assert edge_data["graph_snapshot_side_effect"] is True
        assert len(graph_events) == 1

        class PartialClearDict(dict):
            def clear(self):
                super().__delitem__(next(iter(self)))
                raise RuntimeError("adjacency clear failed")

        graph._succ = PartialClearDict(graph._succ)
        graph_events.clear()
        with self.assertRaises(RuntimeError):
            graph.clear()
        assert len(graph_events) == 1

    def test_observable_graph_partial_predecessor_clear_is_observed(self):
        class PartialClearDict(dict):
            def clear(self):
                super().__delitem__(next(iter(self)))
                raise RuntimeError("predecessor adjacency clear failed")

        class RaisingClearDict(dict):
            def clear(self):
                raise RuntimeError("predecessor adjacency clear failed")

        def mutation_callback(events):
            def graph_mutated():
                events.append(True)

            return graph_mutated

        for graph_type in (ObservableDiGraph, ObservableMultiDiGraph):
            with self.subTest(graph_type=graph_type.__name__, partial=True):
                graph_events = []
                graph_mutated = mutation_callback(graph_events)
                graph = graph_type(mutation_callback=graph_mutated)
                graph.add_edges_from(((1, 2), (2, 3)))
                graph._pred[2] = PartialClearDict(graph._pred[2])
                graph_events.clear()

                with self.assertRaises(RuntimeError):
                    graph.clear_edges()

                assert not graph._pred[2]
                assert graph._succ[1]
                assert len(graph_events) == 1

            with self.subTest(graph_type=graph_type.__name__, partial=False):
                graph_events = []
                graph_mutated = mutation_callback(graph_events)
                graph = graph_type(mutation_callback=graph_mutated)
                graph.add_edges_from(((1, 2), (2, 3)))
                graph._pred[2] = RaisingClearDict(graph._pred[2])
                graph_events.clear()

                with self.assertRaises(RuntimeError):
                    graph.clear_edges()

                assert graph._pred[2]
                assert graph._succ[1]
                assert not graph_events

    def test_graph_and_node_annotation_attributes_are_nonsemantic(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        main = proj.kb.functions["main"]
        node = next(iter(main.transition_graph))
        generation = proj.kb.functions.function_graph_generation

        main.transition_graph.graph["layout_hint"] = "presentation-only"
        main.transition_graph.nodes[node]["layout_hint"] = "presentation-only"
        assert proj.kb.functions.function_graph_generation == generation

    def test_failed_graph_replacements_preserve_installed_observers(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        main = functions["main"]

        transition_graph = main.transition_graph
        generation = functions.function_graph_generation
        dirty = main.dirty
        with self.assertRaises((TypeError, NetworkXError)):
            main.transition_graph = object()
        assert main.transition_graph is transition_graph
        assert functions.function_graph_generation == generation
        assert main.dirty == dirty

        transition_graph.add_node(BlockNode(0xDEAD_3000, 1))
        assert functions.function_graph_generation != generation

        class FailingBlockNode(BlockNode):
            def set_graph(self, graph):
                super().set_graph(graph)
                raise RuntimeError("node binding failed")

        first = BlockNode(0xDEAD_3010, 1)
        failing = FailingBlockNode(0xDEAD_3011, 1)
        replacement = networkx.DiGraph()
        replacement.add_edge(first, failing)
        transition_graph = main.transition_graph
        generation = functions.function_graph_generation
        with self.assertRaises(RuntimeError):
            main.transition_graph = replacement
        assert main.transition_graph is transition_graph
        assert functions.function_graph_generation == generation
        assert first._graph is None
        assert failing._graph is None

        transition_graph.add_node(BlockNode(0xDEAD_3012, 1))
        assert functions.function_graph_generation != generation

        replacement = ObservableDiGraph()
        replacement_source = BlockNode(0xDEAD_3013, 1)
        replacement_destination = BlockNode(0xDEAD_3014, 1)
        replacement.add_edge(replacement_source, replacement_destination)
        replacement_edge_data = replacement[replacement_source][replacement_destination]
        original_replacement_set_callback = replacement_edge_data.set_mutation_callback
        late_node = BlockNode(0xDEAD_3015, 1)

        def add_node_during_callback_install(callback):
            original_replacement_set_callback(callback)
            replacement.add_node(late_node)

        replacement_edge_data.set_mutation_callback = add_node_during_callback_install
        main.transition_graph = replacement
        assert late_node in main.transition_graph
        assert late_node._semantic_identity_sealed
        assert late_node._graph_owner() is main.transition_graph
        with self.assertRaisesRegex(ValueError, "copy and replace"):
            late_node.size = 2

        callgraph = functions.callgraph
        generation = functions.function_graph_generation
        trusted = functions.callgraph_trusted
        with self.assertRaises((TypeError, NetworkXError)):
            functions.callgraph = object()
        assert functions.callgraph is callgraph
        assert functions.function_graph_generation == generation
        assert functions.callgraph_trusted == trusted

        callgraph.add_edge(0xDEAD_3001, 0xDEAD_3002, type="call")
        assert functions.function_graph_generation != generation
        assert not functions.callgraph_trusted

        rejected_callgraph = ObservableMultiDiGraph()
        edge_key = rejected_callgraph.add_edge(0xDEAD_3010, 0xDEAD_3011, type="call")
        edge_data = rejected_callgraph[0xDEAD_3010][0xDEAD_3011][edge_key]
        original_set_callback = edge_data.set_mutation_callback

        def fail_after_callback_install(callback):
            original_set_callback(callback)
            rejected_callgraph.add_node(0xDEAD_3012)
            raise RuntimeError("edge callback binding failed")

        edge_data.set_mutation_callback = fail_after_callback_install
        callgraph = functions.callgraph
        generation = functions.function_graph_generation
        trusted = functions.callgraph_trusted
        with self.assertRaises(RuntimeError):
            functions.callgraph = rejected_callgraph
        assert functions.callgraph is callgraph
        assert functions.function_graph_generation == generation
        assert functions.callgraph_trusted == trusted

        rejected_callgraph.add_node(0xDEAD_3014)
        edge_data["outside"] = True
        assert functions.function_graph_generation == generation
        callgraph.add_node(0xDEAD_3013)
        assert functions.function_graph_generation != generation

        old_edge_key = callgraph.add_edge(0xDEAD_3020, 0xDEAD_3021, type="call")
        old_edge_data = callgraph[0xDEAD_3020][0xDEAD_3021][old_edge_key]
        original_old_set_callback = old_edge_data.set_mutation_callback
        rejected_callgraph = ObservableMultiDiGraph()
        rejected_callgraph.add_edge(0xDEAD_3022, 0xDEAD_3023, type="call")

        def fail_old_callgraph_detach(callback):
            original_old_set_callback(callback)
            rejected_callgraph.add_node(0xDEAD_3024)
            raise RuntimeError("installed callgraph callback detachment failed")

        old_edge_data.set_mutation_callback = fail_old_callgraph_detach
        generation = functions.function_graph_generation
        trusted = functions.callgraph_trusted
        with self.assertRaises(RuntimeError):
            functions.callgraph = rejected_callgraph
        assert functions.callgraph is callgraph
        assert functions.function_graph_generation == generation
        assert functions.callgraph_trusted == trusted
        rejected_callgraph.add_node(0xDEAD_3025)
        assert functions.function_graph_generation == generation
        callgraph.add_node(0xDEAD_3026)
        assert functions.function_graph_generation != generation

        old_transition_graph = main.transition_graph
        old_source, old_destination = next(iter(old_transition_graph.edges))
        old_transition_edge_data = old_transition_graph[old_source][old_destination]
        original_old_transition_set_callback = old_transition_edge_data.set_mutation_callback
        replacement_transition_graph = ObservableDiGraph()
        replacement_source = BlockNode(0xDEAD_3030, 1)
        replacement_destination = BlockNode(0xDEAD_3031, 1)
        replacement_transition_graph.add_edge(replacement_source, replacement_destination, type="transition")

        def fail_old_transition_detach(callback):
            original_old_transition_set_callback(callback)
            replacement_transition_graph.add_node(BlockNode(0xDEAD_3032, 1))
            raise RuntimeError("installed transition callback detachment failed")

        old_transition_edge_data.set_mutation_callback = fail_old_transition_detach
        generation = functions.function_graph_generation
        dirty = main.dirty
        with self.assertRaises(RuntimeError):
            main.transition_graph = replacement_transition_graph
        assert main.transition_graph is old_transition_graph
        assert functions.function_graph_generation == generation
        assert main.dirty == dirty
        assert replacement_source._graph is None
        assert replacement_destination._graph is None
        replacement_transition_graph.add_node(BlockNode(0xDEAD_3033, 1))
        assert functions.function_graph_generation == generation
        old_transition_graph.add_node(BlockNode(0xDEAD_3034, 1))
        assert functions.function_graph_generation != generation

    def test_function_name_indices_survive_delete_and_replacement(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        functions = proj.kb.functions
        accepted = functions["accepted"]
        rejected = functions["rejected"]

        accepted.name = "shared_name"
        rejected.name = "shared_name"
        rejected.info["is_alloca_probe"] = True
        functions.add_key_func_addr("alloca_probe", rejected.addr)
        assert functions.get_addrs_by_name("shared_name") == {accepted.addr, rejected.addr}
        key_snapshot = functions.get_key_func_addrs("alloca_probe")
        assert key_snapshot == {rejected.addr}
        key_snapshot.clear()
        assert functions.get_key_func_addrs("alloca_probe") == {rejected.addr}
        del functions[rejected.addr]
        assert functions.get_addrs_by_name("shared_name") == {accepted.addr}
        assert not functions.get_key_func_addrs("alloca_probe")
        del functions[accepted.addr]
        assert functions.get_addrs_by_name("shared_name") == set()
        assert "shared_name" not in functions._func_name_to_addrs

        ghost_addr = 0xDEAD_BEEF
        functions.add_key_func_addr("alloca_probe", ghost_addr)
        del functions[ghost_addr]
        assert not functions.get_key_func_addrs("alloca_probe")

        old = functions["main"]
        old.name = "old_current"
        old.name = "old_latest"
        old.info["is_alloca_probe"] = True
        functions.add_key_func_addr("alloca_probe", old.addr)
        returning_caches = (
            old.addr in functions._non_returning_func_addrs,
            old.addr in functions._unknown_returning_func_addrs,
        )
        replacement = Function(
            functions,
            old.addr,
            name="replacement",
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=old.returning is False,
        )
        assert (
            old.addr in functions._non_returning_func_addrs,
            old.addr in functions._unknown_returning_func_addrs,
        ) == returning_caches
        replacement.startpoint = BlockNode(replacement.addr, 1)
        replacement.transition_graph.add_node(replacement.startpoint)
        replacement.previous_names = ["replacement_old"]
        replacement.info["is_jmp_rax"] = True
        functions[old.addr] = replacement

        assert functions.get_addrs_by_name("old_latest") == set()
        assert functions.get_addrs_by_name("old_current", check_previous_names=True) == set()
        assert functions.get_addrs_by_name("replacement") == {old.addr}
        assert functions.get_addrs_by_name("replacement_old", check_previous_names=True) == {old.addr}
        assert not functions.get_key_func_addrs("alloca_probe")
        assert functions.get_key_func_addrs("jmp_rax") == {old.addr}


if __name__ == "__main__":
    unittest.main()
