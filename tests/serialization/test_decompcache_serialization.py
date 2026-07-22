#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest

import networkx

import angr
from angr.ailment import Block as AilBlock
from angr.ailment import Expr
from angr.ailment.expression import Const
from angr.ailment.expression import Tmp as AilTmp
from angr.ailment.expression import VirtualVariable as AilVirtualVariable
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.notes.decompilation_note import (
    DecompilationNote,
    DecompilationNoteLevel,
)
from angr.analyses.decompiler.notes.deobfuscated_strings import DeobfuscatedStringsNote
from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBuffer, FixedBufferPtr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import CConstruct
from angr.analyses.decompiler.structured_codegen.c_serialize import (
    _DISPLAY_OPTION_ATTRS,
    _DISPLAY_OPTION_FIELD_FIRST,
)
from angr.knowledge_plugins.structured_code import SpillingDecompilationDict
from angr.protos import codegen_pb2
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.utils.ail_serialization import (
    pack_arg_vvars,
    pack_graph,
    pack_ite_exprs,
    pack_static_buffers,
    pack_static_vvars,
    parse_arg_vvars,
    parse_graph,
    parse_ite_exprs,
    parse_static_buffers,
    parse_static_vvars,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSubObjectSerialization(unittest.TestCase):
    def test_decompilation_note(self):
        n = DecompilationNote(
            key="warn1", name="Warning One", content={"foo": [1, 2]}, level=DecompilationNoteLevel.WARNING
        )
        back = DecompilationNote.from_json(n.to_json())
        assert type(back) is DecompilationNote
        assert back.key == n.key
        assert back.name == n.name
        assert back.level == n.level
        assert back.content == n.content

    def test_decompilation_note_non_jsonable_content(self):
        n = DecompilationNote(key="k", name="n", content=object())
        back = DecompilationNote.from_json(n.to_json())
        assert back.content is None

    def test_deobfuscated_strings_note_roundtrip(self):
        n = DeobfuscatedStringsNote()
        n.add_string("1", b"\x00binary\xffdata", ref_addr=0x400100)
        n.add_string("2", b"hello", ref_addr=0x400200)

        back = DecompilationNote.from_json(n.to_json())
        assert isinstance(back, DeobfuscatedStringsNote)
        assert back.key == n.key
        assert back.name == n.name
        assert set(back.strings) == {0x400100, 0x400200}
        assert back.strings[0x400100].value == b"\x00binary\xffdata"
        assert back.strings[0x400100].type == "1"
        assert back.strings[0x400200].value == b"hello"
        assert str(back) == str(n)

    def test_op_descriptor(self):
        op = OpDescriptor(block_addr=0x400500, stmt_idx=3, ins_addr=0x400502, op="Sub")
        back = OpDescriptor.from_json(op.to_json())
        assert back == op
        assert hash(back) == hash(op)


class TestAilSerializationHelpers(unittest.TestCase):
    def test_display_option_attrs_derived_from_proto(self):
        # _DISPLAY_OPTION_ATTRS is generated from the Codegen descriptor's trailing display-option block; every entry
        # must be an optional scalar (the serialize loop uses plain setattr, which cannot handle message fields).
        assert {"indent", "show_casts", "max_str_len"} <= set(_DISPLAY_OPTION_ATTRS)
        assert len(set(_DISPLAY_OPTION_ATTRS)) == len(_DISPLAY_OPTION_ATTRS)
        for name in _DISPLAY_OPTION_ATTRS:
            field = codegen_pb2.Codegen.DESCRIPTOR.fields_by_name[name]
            assert field.number >= _DISPLAY_OPTION_FIELD_FIRST
            # not a message and not repeated. Use the modern FieldDescriptor API: protobuf 7.x (the upb backend)
            # removed the ``label``/``type`` attributes and the LABEL_*/TYPE_* constants.
            assert field.message_type is None
            assert not field.is_repeated

    def test_tags_roundtrip_with_ins_offset(self):
        from angr.analyses.decompiler.structured_codegen.c_serialize import _parse_tags, _sanitize_tags

        # both addresses known: ins_addr rides as a delta but round-trips to the absolute value
        tags = {"ins_addr": 0x4010F0, "vex_block_addr": 0x401000, "vex_stmt_idx": 7, "custom": [1, 2]}
        key, msg = _sanitize_tags(tags)
        assert msg is not None and not msg.HasField("ins_addr") and msg.ins_offset == 0xF0
        assert _parse_tags(msg) == tags
        # ins_addr alone stays absolute
        key2, msg2 = _sanitize_tags({"ins_addr": 0x400123})
        assert msg2 is not None and msg2.HasField("ins_addr") and not msg2.HasField("ins_offset")
        assert _parse_tags(msg2) == {"ins_addr": 0x400123}
        assert key != key2

    def _blocks(self):
        b0 = AilBlock(0x1000, 4, statements=[Assignment(0, AilTmp(1, 2, 64), Const(2, 1, 64), ins_addr=0x1000)])
        b1 = AilBlock(0x1004, 4, statements=[Return(3, [], ins_addr=0x1004)])
        b2 = AilBlock(0x1008, 4, statements=[], idx=1)
        return b0, b1, b2

    def test_graph_roundtrip_with_edge_data(self):
        b0, b1, b2 = self._blocks()
        g = networkx.DiGraph()
        g.add_edge(b0, b1, type="fake_return", outside=False, confirmed=True)
        # ins_addr=None packs as unset and comes back as an absent key
        g.add_edge(b0, b2, type="transition", ins_addr=None, stmt_idx=-2)
        g.add_edge(b1, b2)  # no edge data at all

        back = parse_graph(pack_graph(g))
        assert set(back.nodes) == set(g.nodes)
        assert back[b0][b1] == {"type": "fake_return", "outside": False, "confirmed": True}
        assert back[b0][b2] == {"type": "transition", "stmt_idx": -2}
        assert back[b1][b2] == {}

    def test_graph_rejects_unknown_edge_attr(self):
        b0, b1, _ = self._blocks()
        g = networkx.DiGraph()
        g.add_edge(b0, b1, color="red")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_graph_rejects_unknown_edge_type_string(self):
        b0, b1, _ = self._blocks()
        g = networkx.DiGraph()
        g.add_edge(b0, b1, type="teleport")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_graph_rejects_non_block_node(self):
        g = networkx.DiGraph()
        g.add_node("not a block")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_arg_vvars_roundtrip(self):
        vvc = Expr.VirtualVariableCategory
        d = {
            0: (AilVirtualVariable(0, 1, 64, vvc.REGISTER), SimRegisterVariable(16, 8, ident="arg_0")),
            1: (AilVirtualVariable(1, 2, 64, vvc.STACK), SimStackVariable(-8, 8, ident="arg_1")),
        }
        back = parse_arg_vvars(pack_arg_vvars(d))
        assert back == d

    def test_ite_exprs_roundtrip(self):
        s = {(0x400123, Const(0, 5, 64)), (0x400456, Const(1, 7, 32))}
        assert parse_ite_exprs(pack_ite_exprs(s)) == s

    def test_static_vvars_roundtrip_both_arms(self):
        d = {3: FixedBufferPtr("buf0", offset=8), 4: Const(0, 0xDEAD, 64)}
        back = parse_static_vvars(pack_static_vvars(d))
        assert set(back) == {3, 4}
        assert isinstance(back[3], FixedBufferPtr)
        assert back[3].buffer_ident == "buf0" and back[3].offset == 8
        assert back[4] == d[4]

    def test_static_buffers_roundtrip(self):
        d = {"buf0": FixedBuffer("buf0", 16, b"\x00" * 16), "anon": FixedBuffer(None, 4, b"abcd")}
        back = parse_static_buffers(pack_static_buffers(d))
        assert set(back) == {"buf0", "anon"}
        assert back["buf0"].ident == "buf0" and back["buf0"].size == 16 and back["buf0"].content == b"\x00" * 16
        assert back["anon"].ident == "<unnamed>"  # FixedBuffer normalizes a None ident at construction time


class TestDecompilationCacheEndToEnd(unittest.TestCase):
    """End-to-end tests using a real fauxware decompilation."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.func = cls.proj.kb.functions.function(name="authenticate")
        cls.decompiler = cls.proj.analyses.Decompiler(cls.func, cfg=cls.cfg.model, generate_code=True)

    def test_codegen_roundtrip(self):
        codegen = self.decompiler.codegen
        blob = codegen.serialize()
        back = type(codegen).parse(blob, project=self.proj, kb=self.proj.kb)
        assert back.text == codegen.text
        assert back.cfunc is not None
        assert back.cfunc.name == codegen.cfunc.name
        assert back.cfunc.addr == codegen.cfunc.addr
        assert back.flavor == codegen.flavor
        # idx is the per-codegen unique node identity and doubles as the serialization node id
        assert back.cfunc.idx == codegen.cfunc.idx
        assert back.cfunc.ident == codegen.cfunc.ident

        live_nodes = {
            id(elem.obj): elem.obj for _, elem in codegen.map_pos_to_node.items() if isinstance(elem.obj, CConstruct)
        }
        assert live_nodes
        assert len({node.idx for node in live_nodes.values()}) == len(live_nodes)

        msg = codegen_pb2.Codegen()
        msg.ParseFromString(blob)
        node_ids = [n.node_id for n in msg.nodes]
        assert len(set(node_ids)) == len(node_ids)
        assert 0 not in node_ids
        # nodes created after deserialization must not collide with deserialized ones
        assert back._next_node_idx > max(node_ids)

    def test_clinic_roundtrip(self):
        clinic = self.decompiler.clinic
        back = type(clinic).parse(
            clinic.serialize(),
            project=self.proj,
            kb=self.proj.kb,
            function=clinic.function,
            cfg=clinic._cfg,
        )
        # the fields the decompiler's cache-reuse path consumes round-trip
        assert back.cc_graph.number_of_nodes() == clinic.cc_graph.number_of_nodes()
        assert back.graph.number_of_nodes() == clinic.graph.number_of_nodes()
        assert back.graph.number_of_edges() == clinic.graph.number_of_edges()
        # unoptimized_graph is only built (and serialized) with Decompiler(save_unoptimized_graph=True); this
        # decompiler used the default, so it is absent on both the live and the deserialized clinic
        assert clinic.unoptimized_graph is None and back.unoptimized_graph is None
        assert back._save_unoptimized_graph is False
        assert back.arg_vvars == clinic.arg_vvars
        assert len(back.externs) == len(clinic.externs)
        assert (back.arg_list is None) == (clinic.arg_list is None)
        assert back.vvar_id_start == clinic.vvar_id_start
        assert back.copied_var_ids == clinic.copied_var_ids
        assert back.edges_to_remove == clinic.edges_to_remove
        assert back.entry_node_addr == clinic.entry_node_addr
        assert back._mode == clinic._mode
        assert back._start_stage == clinic._start_stage
        assert back._end_stage == clinic._end_stage
        assert back._skip_stages == clinic._skip_stages
        assert back.flavor == clinic.flavor
        # regenerable / runtime-only state is not serialized, so the deserialized clinic comes back with the
        # default (the caller's fast-path reuse regenerates whatever it needs)
        for attr in (
            "_ail_graph",
            "_init_ail_graph",
            "_init_arg_vvars",
            "func_args",
            "func_ret_var",
            "reaching_definitions",
            "_blocks_by_addr_and_size",
            "typehoon",
        ):
            assert getattr(back, attr) is None, attr
        for attr in ("data_refs", "notes"):
            assert getattr(back, attr) == {}, attr
        # stack_items is primitive result data and is kept through downsize and serialization
        assert {k: (v.offset, v.size, v.name, v.item_type) for k, v in back.stack_items.items()} == {
            k: (v.offset, v.size, v.name, v.item_type) for k, v in clinic.stack_items.items()
        }
        assert clinic._inline_functions == set() and back._inline_functions == set()

    def test_clinic_roundtrip_with_save_unoptimized_graph(self):
        # Decompiler(save_unoptimized_graph=True) opts the unoptimized graph into serialization.
        dec = self.proj.analyses.Decompiler(
            self.func, cfg=self.cfg.model, save_unoptimized_graph=True, regen_clinic=True
        )
        clinic = dec.clinic
        assert clinic is not None and clinic.unoptimized_graph is not None
        back = type(clinic).parse(
            clinic.serialize(),
            project=self.proj,
            kb=self.proj.kb,
            function=clinic.function,
            cfg=clinic._cfg,
        )
        assert back._save_unoptimized_graph is True
        assert back.unoptimized_graph is not None
        assert back.unoptimized_graph.number_of_nodes() == clinic.unoptimized_graph.number_of_nodes()
        assert back.unoptimized_graph.number_of_edges() == clinic.unoptimized_graph.number_of_edges()

    def test_decompilation_cache_roundtrip(self):
        cache = self.decompiler.cache
        blob = cache.serialize()
        back = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            cfg=self.cfg.model,
        )
        assert back.addr == cache.addr
        assert back.errors == cache.errors
        assert back.function_summary == cache.function_summary
        assert back.codegen.text == cache.codegen.text
        # version and timestamp are set at decompile time and round-trip verbatim
        assert cache.version == angr.__version__
        assert cache.timestamp > 0
        assert back.version == cache.version
        assert back.timestamp == cache.timestamp
        # parameters preserves the 15 keys
        assert set(back.parameters.keys()) == set(cache.parameters.keys())
        assert len(back.parameters) == 15

    def test_cache_hit_on_deserialized_cache(self):
        cache = self.decompiler.cache
        blob = cache.serialize()
        parsed_cache = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            cfg=self.cfg.model,
        )

        # Replace the live cache with the parsed one.
        flavor = parsed_cache.parameters.get("flavor", "pseudocode")
        self.proj.kb.decompilations[(self.func.addr, flavor)] = parsed_cache

        # Second decompile run with the same inputs should consume the deserialized cache.
        d2 = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model, generate_code=True)
        assert d2.codegen.text == self.decompiler.codegen.text

    def test_full_reuse_fast_path(self):
        # With use_cache=True and regen_clinic=False (both defaults), a valid cache short-circuits the pipeline and
        # returns the cached clinic + codegen objects, re-rendered.
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="authenticate")
        d1 = proj.analyses.Decompiler(func, cfg=cfg.model)
        cache = proj.kb.decompilations[(func.addr, "pseudocode")]

        d2 = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert d2.codegen is d1.codegen
        assert d2.clinic is d1.clinic
        assert d2.codegen.text == d1.codegen.text
        assert d2.codegen.version == cache.version == angr.__version__
        assert d2.codegen.timestamp == cache.timestamp > 0

    def test_regen_clinic_forces_fresh_decompilation(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="authenticate")
        d1 = proj.analyses.Decompiler(func, cfg=cfg.model)
        d2 = proj.analyses.Decompiler(func, cfg=cfg.model, regen_clinic=True)
        assert d2.codegen is not d1.codegen
        assert d2.codegen.text == d1.codegen.text


class TestSpillingDecompilationDict(unittest.TestCase):
    """Tests for the LRU + RtDb-spilling backing store of StructuredCodeManager."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.auth_func = cls.proj.kb.functions.function(name="authenticate")
        cls.main_func = cls.proj.kb.functions.function(name="main")
        cls.auth_dec = cls.proj.analyses.Decompiler(cls.auth_func, cfg=cls.cfg.model, generate_code=True)
        cls.main_dec = cls.proj.analyses.Decompiler(cls.main_func, cfg=cls.cfg.model, generate_code=True)

    def test_default_backing_store_is_spilling(self):
        assert isinstance(self.proj.kb.decompilations.cached, SpillingDecompilationDict)

    def test_eviction_and_reload(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        auth_key = (self.auth_func.addr, "pseudocode")
        main_key = (self.main_func.addr, "pseudocode")
        d[auth_key] = self.auth_dec.cache
        d[main_key] = self.main_dec.cache

        # the LRU (authenticate) entry must have been spilled
        assert auth_key in d._spilled
        assert len(d) == 2
        assert auth_key in d
        assert main_key in d
        assert set(d) == {auth_key, main_key}

        # reloading the spilled entry deserializes it with full codegen and version/timestamp
        back = d[auth_key]
        assert back is not self.auth_dec.cache
        assert back.codegen.text == self.auth_dec.cache.codegen.text
        assert back.version == self.auth_dec.cache.version
        assert back.timestamp == self.auth_dec.cache.timestamp
        # ... and the reload evicted the other entry in turn
        assert main_key in d._spilled

    def test_mutations_survive_respill(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        auth_key = (self.auth_func.addr, "pseudocode")
        main_key = (self.main_func.addr, "pseudocode")
        d[auth_key] = self.auth_dec.cache
        d[main_key] = self.main_dec.cache

        # reload authenticate (spills main), mutate it in place, then spill it again by touching main
        d[auth_key].errors.append("synthetic error")
        _ = d[main_key]
        assert auth_key in d._spilled
        assert "synthetic error" in d[auth_key].errors

    def test_unserializable_cache_is_kept_in_memory(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        dummy_key = (0xDEAD, "pseudocode")
        dummy_cache = DecompilationCache(0xDEAD)
        dummy_cache.codegen = DummyStructuredCodeGenerator("pseudocode")
        d[dummy_key] = dummy_cache

        # inserting another entry evicts the dummy cache, which cannot be serialized and must be parked in memory
        main_key = (self.main_func.addr, "pseudocode")
        d[main_key] = self.main_dec.cache
        assert dummy_key in d._unspillable
        assert d[dummy_key] is dummy_cache
        assert len(d) == 2

    def test_delete_and_discard(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        auth_key = (self.auth_func.addr, "pseudocode")
        main_key = (self.main_func.addr, "pseudocode")
        d[auth_key] = self.auth_dec.cache
        d[main_key] = self.main_dec.cache

        del d[auth_key]  # spilled entry
        del d[main_key]  # in-memory entry
        assert len(d) == 0
        assert auth_key not in d
        with self.assertRaises(KeyError):
            _ = d[auth_key]

    def test_export_and_bulk_import_serialized(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        auth_key = (self.auth_func.addr, "pseudocode")
        main_key = (self.main_func.addr, "pseudocode")
        d[auth_key] = self.auth_dec.cache
        d[main_key] = self.main_dec.cache

        serialized, unserializable = d.export_serialized()
        assert not unserializable
        assert {key for key, _ in serialized} == {auth_key, main_key}

        d2 = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        d2.bulk_import_serialized(serialized)
        assert set(d2) == {auth_key, main_key}
        assert d2._spilled == {auth_key, main_key}
        assert d2[auth_key].codegen.text == self.auth_dec.cache.codegen.text

    def test_pickle_roundtrip(self):
        d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
        auth_key = (self.auth_func.addr, "pseudocode")
        main_key = (self.main_func.addr, "pseudocode")
        d[auth_key] = self.auth_dec.cache
        d[main_key] = self.main_dec.cache
        assert auth_key in d._spilled

        # serializable entries pickle as protobuf bytes: live caches hold unpicklable analysis internals
        back = pickle.loads(pickle.dumps(d, -1))
        assert set(back) == {auth_key, main_key}
        assert back._spilled == {auth_key, main_key}
        assert back[auth_key].codegen.text == self.auth_dec.cache.codegen.text

    def test_cache_hit_after_spill(self):
        manager = self.proj.kb.decompilations
        old_cached = manager.cached
        try:
            d = SpillingDecompilationDict(self.proj.kb, cache_limit=1)
            manager.cached = d
            manager[(self.auth_func.addr, "pseudocode")] = self.auth_dec.cache
            manager[(self.main_func.addr, "pseudocode")] = self.main_dec.cache
            assert (self.auth_func.addr, "pseudocode") in d._spilled

            d2 = self.proj.analyses.Decompiler(self.auth_func, cfg=self.cfg.model, generate_code=True)
            assert d2.codegen.text == self.auth_dec.codegen.text
        finally:
            manager.cached = old_cached


if __name__ == "__main__":
    unittest.main()
