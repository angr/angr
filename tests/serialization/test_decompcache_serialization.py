#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
"""Tests for the protobuf serialization of the DecompilationCache and its sub-objects.

These tests cover the work landed in commits 839fde31c..8780e1641 on the
feat/decompcache-serialization branch. The class-level round-trip tests guard against single-subclass regressions;
the end-to-end test asserts that a real fauxware decompilation round-trips with byte-identical rendered text; the
cache-hit test asserts that a deserialized cache can power a cache-hit in :class:`Decompiler` and produce the same
output as the original run."""

from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import os
import unittest

from archinfo import Endness

import angr
import angr.ailment as ailment
from angr.code_location import AILCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import (
    Atom,
    ConstantSrc,
    GuardUse,
    MemoryLocation,
    Register,
    Tmp,
    VirtualVariable,
)
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.tag import (
    FunctionTag,
    InitialValueTag,
    LocalVariableTag,
    ParameterTag,
    ReturnValueTag,
    SideEffectTag,
    Tag,
    UnknownSizeTag,
)
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestKeyDefSerialization(unittest.TestCase):
    """Round-trip tests for the atoms / codeloc / tag / Definition classes added in step 2."""

    def _roundtrip(self, obj):
        return type(obj).parse(obj.serialize())

    def test_atom_tmp(self):
        a = Tmp(7, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_register(self):
        a = Register(8, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_guarduse(self):
        a = GuardUse(0x401000)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_constantsrc(self):
        a = ConstantSrc(0xDEADBEEF, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_virtualvariable_int_oident(self):
        a = VirtualVariable(42, 4, ailment.Expr.VirtualVariableCategory.REGISTER, oident=16)
        b = self._roundtrip(a)
        assert b == a
        assert b.oident == 16

    def test_atom_virtualvariable_tuple_oident(self):
        # COMBO_REGISTER uses a tuple oident; JSON encoding turns it into a list, _tuplify restores it.
        a = VirtualVariable(43, 8, ailment.Expr.VirtualVariableCategory.COMBO_REGISTER, oident=(16, 24))
        b = self._roundtrip(a)
        assert b == a
        assert b.oident == (16, 24)

    def test_atom_memorylocation_int(self):
        a = MemoryLocation(0x1000, 4, endness=Endness.LE)
        assert self._roundtrip(a) == a

    def test_atom_memorylocation_spoffset(self):
        a = MemoryLocation(SpOffset(64, -16), 8, endness=Endness.LE)
        assert self._roundtrip(a) == a

    def test_atom_memorylocation_heapaddress(self):
        assert self._roundtrip(MemoryLocation(HeapAddress(0x1000), 4)) == MemoryLocation(HeapAddress(0x1000), 4)
        assert self._roundtrip(MemoryLocation(HeapAddress(UNDEFINED), 4)) == MemoryLocation(HeapAddress(UNDEFINED), 4)

    def test_atom_polymorphic_dispatch(self):
        # Atom.parse on the base class should dispatch to the correct concrete subclass.
        atoms_to_test = [
            Tmp(7, 4),
            Register(8, 4),
            GuardUse(0x401000),
            ConstantSrc(0xDEADBEEF, 4),
            VirtualVariable(42, 4, ailment.Expr.VirtualVariableCategory.REGISTER, oident=16),
            MemoryLocation(0x1000, 4, endness=Endness.LE),
        ]
        for a in atoms_to_test:
            b = Atom.parse(a.serialize())
            assert type(b) is type(a)
            assert b == a

    def test_ail_codeloc(self):
        for loc in [
            AILCodeLocation(0x400500, 0, 3, 0x400502),
            AILCodeLocation(0x400500, None, 3),
            AILCodeLocation.make_extern(7),
        ]:
            assert self._roundtrip(loc) == loc

    def test_tags(self):
        for tag in [
            Tag(metadata={"x": 1, "y": [1, 2, 3]}),
            Tag(),
            FunctionTag(function=0x400600),
            SideEffectTag(function=0x400700, metadata="side"),
            ParameterTag(function=None, metadata=None),
            LocalVariableTag(function=0x400800),
            ReturnValueTag(function=0x400900, metadata=[1, 2]),
            InitialValueTag(metadata="init"),
            UnknownSizeTag(),
        ]:
            back = self._roundtrip(tag)
            assert type(back) is type(tag)
            assert back.metadata == tag.metadata
            if isinstance(tag, FunctionTag):
                assert back.function == tag.function

    def test_definition_with_tags(self):
        d = Definition(
            Tmp(7, 4),
            AILCodeLocation(0x400500, 0, 3, 0x400502),
            dummy=True,
            tags={ParameterTag(function=0x400600), InitialValueTag(metadata="x")},
        )
        back = self._roundtrip(d)
        assert back.atom == d.atom
        assert back.codeloc == d.codeloc
        assert back.dummy is True
        assert len(back.tags) == 2
        assert any(isinstance(t, ParameterTag) and t.function == 0x400600 for t in back.tags)


class TestSubObjectSerialization(unittest.TestCase):
    """Round-trip tests for DecompilationNote and OpDescriptor (added in step 6)."""

    def test_decompilation_note(self):
        from angr.analyses.decompiler.notes.decompilation_note import (
            DecompilationNote,
            DecompilationNoteLevel,
        )

        n = DecompilationNote(
            key="warn1", name="Warning One", content={"foo": [1, 2]}, level=DecompilationNoteLevel.WARNING
        )
        back = DecompilationNote.parse(n.serialize())
        assert back.key == n.key
        assert back.name == n.name
        assert back.level == n.level
        assert back.content == n.content

    def test_op_descriptor(self):
        from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor

        op = OpDescriptor(block_addr=0x400500, stmt_idx=3, ins_addr=0x400502, op="Sub")
        back = OpDescriptor.parse(op.serialize())
        assert back == op


def _build_synthetic_srda_model(arch):
    """A small two-block SSA AIL graph exercising vvar defs/uses, tmp defs/uses, a function argument with no
    in-graph definition (extern def) and a use of an undefined vvar (extern-def fixup)."""
    import networkx

    from angr.ailment import Block as AilBlock
    from angr.ailment.expression import Const
    from angr.ailment.expression import Tmp as AilTmp
    from angr.ailment.expression import VirtualVariable as AilVirtualVariable
    from angr.ailment.statement import Assignment, Jump
    from angr.analyses.s_reaching_definitions import SRDAModel, populate_model

    vvc = ailment.Expr.VirtualVariableCategory

    b0 = AilBlock(
        0x400000,
        8,
        statements=[
            Assignment(0, AilVirtualVariable(0, 1, 64, vvc.REGISTER), Const(1, 42, 64), ins_addr=0x400000),
            Jump(5, Const(6, 0x400010, 64), ins_addr=0x400008),
        ],
    )
    b1 = AilBlock(
        0x400010,
        8,
        statements=[
            # tmps are block-local: def tmp5 (using vvar1), then use it in the same block
            Assignment(
                2, AilTmp(3, 5, 64), AilVirtualVariable(4, 1, 64, vvc.REGISTER), ins_addr=0x400010
            ),  # def tmp5, use vvar1
            Assignment(
                7, AilVirtualVariable(8, 2, 64, vvc.REGISTER), AilTmp(9, 5, 64), ins_addr=0x400014
            ),  # def vvar2, use tmp5
            Assignment(
                10,
                AilVirtualVariable(11, 3, 64, vvc.REGISTER),
                AilVirtualVariable(12, 9, 64, vvc.REGISTER),  # vvar9 is never defined -> extern-def fixup
                ins_addr=0x400018,
            ),
        ],
    )
    graph = networkx.DiGraph()
    graph.add_edge(b0, b1, type="transition", outside=False, ins_addr=0x400008, stmt_idx=-2)

    func_args = {AilVirtualVariable(20, 7, 64, vvc.PARAMETER)}  # no in-graph definition -> extern def
    model = SRDAModel(graph, None, arch)
    populate_model(model, {(b.addr, b.idx): b for b in graph}, func_args, track_tmps=True)
    return model


class TestSRDAModelSerialization(unittest.TestCase):
    """Round-trip test for SRDAModel: only func_graph / func_args / track_tmps are serialized; every derived dict
    must come back reconstructed (by re-scanning the deserialized graph) equal to the original."""

    def test_synthetic_srda_model(self):
        import archinfo

        from angr.analyses.s_reaching_definitions import SRDAModel

        arch = archinfo.ArchAMD64()
        model = _build_synthetic_srda_model(arch)
        # sanity: the synthetic graph really exercises every derived dict
        assert model.varid_to_vvar and model.all_vvar_uses and model.all_tmp_definitions and model.all_tmp_uses

        back = SRDAModel.parse(model.serialize(), arch=arch)

        assert back.arch is arch
        # graph round-trip (nodes compare by content, edges carry their data dicts)
        assert set(back.func_graph.nodes) == set(model.func_graph.nodes)
        assert {(u, v, tuple(sorted(d.items()))) for u, v, d in back.func_graph.edges(data=True)} == {
            (u, v, tuple(sorted(d.items()))) for u, v, d in model.func_graph.edges(data=True)
        }
        assert back.func_args == model.func_args
        # every derived dict is reconstructed equal to the original
        assert back.varid_to_vvar == model.varid_to_vvar
        assert back.all_vvar_definitions == model.all_vvar_definitions
        assert dict(back.all_vvar_uses) == dict(model.all_vvar_uses)
        assert dict(back.all_tmp_definitions) == dict(model.all_tmp_definitions)
        assert dict(back.all_tmp_uses) == dict(model.all_tmp_uses)
        assert back.phi_vvar_ids == model.phi_vvar_ids
        assert back.phivarid_to_varids == model.phivarid_to_varids
        assert back.phivarid_to_varids_with_unknown == model.phivarid_to_varids_with_unknown
        assert back.vvar_uses_by_loc == model.vvar_uses_by_loc
        # defaultdict semantics restored
        back.all_vvar_uses[99].append(("x",))


class TestAilSerializationHelpers(unittest.TestCase):
    """Unit round-trips for the typed pack/parse helpers in angr.utils.ail_serialization."""

    def _blocks(self):
        from angr.ailment import Block as AilBlock
        from angr.ailment.expression import Const
        from angr.ailment.expression import Tmp as AilTmp
        from angr.ailment.statement import Assignment, Return

        b0 = AilBlock(0x1000, 4, statements=[Assignment(0, AilTmp(1, 2, 64), Const(2, 1, 64), ins_addr=0x1000)])
        b1 = AilBlock(0x1004, 4, statements=[Return(3, [], ins_addr=0x1004)])
        b2 = AilBlock(0x1008, 4, statements=[], idx=1)
        return b0, b1, b2

    def test_graph_roundtrip_with_edge_data(self):
        import networkx

        from angr.utils.ail_serialization import pack_graph, parse_graph

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
        import networkx

        from angr.utils.ail_serialization import pack_graph

        b0, b1, _ = self._blocks()
        g = networkx.DiGraph()
        g.add_edge(b0, b1, color="red")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_graph_rejects_unknown_edge_type_string(self):
        import networkx

        from angr.utils.ail_serialization import pack_graph

        b0, b1, _ = self._blocks()
        g = networkx.DiGraph()
        g.add_edge(b0, b1, type="teleport")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_graph_rejects_non_block_node(self):
        import networkx

        from angr.utils.ail_serialization import pack_graph

        g = networkx.DiGraph()
        g.add_node("not a block")
        with self.assertRaises(TypeError):
            pack_graph(g)

    def test_arg_vvars_roundtrip(self):
        from angr.ailment.expression import VirtualVariable as AilVirtualVariable
        from angr.sim_variable import SimRegisterVariable, SimStackVariable
        from angr.utils.ail_serialization import pack_arg_vvars, parse_arg_vvars

        vvc = ailment.Expr.VirtualVariableCategory
        d = {
            0: (AilVirtualVariable(0, 1, 64, vvc.REGISTER), SimRegisterVariable(16, 8, ident="arg_0")),
            1: (AilVirtualVariable(1, 2, 64, vvc.STACK), SimStackVariable(-8, 8, ident="arg_1")),
        }
        back = parse_arg_vvars(pack_arg_vvars(d))
        assert back == d

    def test_vvar_set_roundtrip(self):
        from angr.ailment.expression import VirtualVariable as AilVirtualVariable
        from angr.utils.ail_serialization import pack_vvar_set, parse_vvar_set

        vvc = ailment.Expr.VirtualVariableCategory
        s = {AilVirtualVariable(0, 1, 64, vvc.REGISTER), AilVirtualVariable(1, 2, 32, vvc.PARAMETER)}
        assert parse_vvar_set(pack_vvar_set(s)) == s

    def test_type_hints_roundtrip(self):
        from angr.engines.light import SpOffset
        from angr.utils.ail_serialization import pack_type_hints, parse_type_hints

        vvc = ailment.Expr.VirtualVariableCategory
        hints = [
            (VirtualVariable(42, 8, vvc.REGISTER, oident=16), "char*"),
            (MemoryLocation(SpOffset(64, -0x20), 8), "struct sockaddr"),
        ]
        assert parse_type_hints(pack_type_hints(hints)) == hints

    def test_ite_exprs_roundtrip(self):
        from angr.ailment.expression import Const
        from angr.utils.ail_serialization import pack_ite_exprs, parse_ite_exprs

        s = {(0x400123, Const(0, 5, 64)), (0x400456, Const(1, 7, 32))}
        assert parse_ite_exprs(pack_ite_exprs(s)) == s

    def test_static_vvars_roundtrip_both_arms(self):
        from angr.ailment.expression import Const
        from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBufferPtr
        from angr.utils.ail_serialization import pack_static_vvars, parse_static_vvars

        d = {3: FixedBufferPtr("buf0", offset=8), 4: Const(0, 0xDEAD, 64)}
        back = parse_static_vvars(pack_static_vvars(d))
        assert set(back) == {3, 4}
        assert isinstance(back[3], FixedBufferPtr)
        assert back[3].buffer_ident == "buf0" and back[3].offset == 8
        assert back[4] == d[4]

    def test_static_buffers_roundtrip(self):
        from angr.analyses.decompiler.optimization_passes.static_vvar_rewriter import FixedBuffer
        from angr.utils.ail_serialization import pack_static_buffers, parse_static_buffers

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
        back = type(codegen).parse(blob, project=self.proj, kb=self.proj.kb, variable_kb=codegen._variable_kb)
        assert back.text == codegen.text
        assert back.cfunc is not None
        assert back.cfunc.name == codegen.cfunc.name
        assert back.cfunc.addr == codegen.cfunc.addr
        assert back.flavor == codegen.flavor

    def test_clinic_roundtrip(self):
        clinic = self.decompiler.clinic
        back = type(clinic).parse(
            clinic.serialize(),
            project=self.proj,
            kb=self.proj.kb,
            function=clinic.function,
            variable_kb=clinic.variable_kb,
            cfg=clinic._cfg,
        )
        assert back.graph.number_of_nodes() == clinic.graph.number_of_nodes()
        assert back.cc_graph.number_of_nodes() == clinic.cc_graph.number_of_nodes()
        assert back.vvar_id_start == clinic.vvar_id_start
        assert back.copied_var_ids == clinic.copied_var_ids
        assert back._mode == clinic._mode
        assert back._start_stage == clinic._start_stage
        assert back._end_stage == clinic._end_stage
        assert back._skip_stages == clinic._skip_stages
        assert back.flavor == clinic.flavor
        assert len(back.externs) == len(clinic.externs)
        # SRDA derived fields are reconstructed by re-scanning the deserialized graph rather than serialized, so
        # they must match a fresh scan of the original stored graph (NOT the stored model, which may be stale
        # relative to its own graph after later in-place simplifications).
        from angr.analyses.s_reaching_definitions import SRDAModel, populate_model

        rd = clinic.reaching_definitions
        fresh = SRDAModel(rd.func_graph, None, self.proj.arch)
        populate_model(
            fresh,
            {(b.addr, b.idx): b for b in rd.func_graph},
            rd.func_args,
            track_tmps=bool(rd.all_tmp_definitions) or bool(rd.all_tmp_uses),
        )
        assert back.reaching_definitions.varid_to_vvar == fresh.varid_to_vvar
        assert back.reaching_definitions.all_vvar_definitions == fresh.all_vvar_definitions
        assert dict(back.reaching_definitions.all_vvar_uses) == dict(fresh.all_vvar_uses)
        assert back.reaching_definitions.phi_vvar_ids == fresh.phi_vvar_ids
        # func_args is recomputed from arg_vvars rather than serialized
        assert back.func_args == clinic.func_args
        # _blocks_by_addr_and_size is rebuilt from _init_ail_graph: every original entry whose block is part of the
        # graph must be reconstructed (entries for unreachable, never-graphed blocks are dead weight and may differ)
        if clinic._blocks_by_addr_and_size and clinic._init_ail_graph is not None:
            graph_blocks = set(clinic._init_ail_graph)
            for key, blk in clinic._blocks_by_addr_and_size.items():
                if blk in graph_blocks:
                    assert back._blocks_by_addr_and_size.get(key) == blk

    def test_decompilation_cache_roundtrip(self):
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache

        cache = self.decompiler.cache
        blob = cache.serialize()
        back = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            variable_kb=cache.variable_kb,
            cfg=self.cfg.model,
        )
        assert back.addr == cache.addr
        assert back.errors == cache.errors
        assert back.function_summary == cache.function_summary
        assert back.codegen.text == cache.codegen.text
        # provenance stamps are set at decompile time and round-trip verbatim
        assert cache.version == angr.__version__
        assert cache.timestamp > 0
        assert back.version == cache.version
        assert back.timestamp == cache.timestamp
        # parameters preserves the 14 keys
        assert set(back.parameters.keys()) == set(cache.parameters.keys())
        assert len(back.parameters) == 14

    def test_cache_hit_on_deserialized_cache(self):
        """The decisive end-to-end test: serialize the cache, parse it back, install it in the KB, and re-run the
        decompiler. The second run must hit the cache and produce identical output."""
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache

        cache = self.decompiler.cache
        blob = cache.serialize()
        parsed_cache = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            variable_kb=cache.variable_kb,
            cfg=self.cfg.model,
        )

        # Replace the live cache with the parsed one.
        flavor = parsed_cache.parameters.get("flavor", "pseudocode")
        self.proj.kb.decompilations[(self.func.addr, flavor)] = parsed_cache

        # Second decompile run with the same inputs should consume the deserialized cache.
        d2 = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model, generate_code=True)
        assert d2.codegen.text == self.decompiler.codegen.text


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
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

        assert isinstance(self.proj.kb.decompilations.cached, SpillingDecompilationDict)

    def test_eviction_and_reload(self):
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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

        # reloading the spilled entry deserializes it with full codegen and provenance stamps
        back = d[auth_key]
        assert back is not self.auth_dec.cache
        assert back.codegen.text == self.auth_dec.cache.codegen.text
        assert back.version == self.auth_dec.cache.version
        assert back.timestamp == self.auth_dec.cache.timestamp
        # ... and the reload evicted the other entry in turn
        assert main_key in d._spilled

    def test_mutations_survive_respill(self):
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache
        from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
        import pickle

        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
        """The decisive test: force the freshly decompiled cache out to LMDB, then re-run the decompiler. The
        second run must transparently reload the spilled cache and produce identical output."""
        from angr.knowledge_plugins.structured_code import SpillingDecompilationDict

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
