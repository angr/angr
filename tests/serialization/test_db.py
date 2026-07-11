#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import os
import shutil
import sqlite3
import tempfile
import unittest
from collections import Counter
from unittest import mock

import archinfo
import cle

import angr
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.angrdb import AngrDB
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDb(unittest.TestCase):
    @staticmethod
    def _roundtrip_angrdb(proj, db_file):
        AngrDB(proj, nullpool=True).dump(db_file)
        return AngrDB(nullpool=True).load(db_file)

    @staticmethod
    def _assert_loader_state(proj, backend_cls, arch_name):
        assert isinstance(proj.loader.main_object, backend_cls)
        assert proj.arch.name == arch_name

    def test_angrdb_fauxware(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg: angr.analyses.CFGFast = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)
        proj.kb.comments[proj.entry] = "Entry point"

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        db = AngrDB(proj, nullpool=True)
        db.dump(db_file)

        db1 = AngrDB(nullpool=True)
        new_proj = db1.load(db_file)

        assert len(list(new_proj.kb.cfgs["CFGFast"].nodes())) == len(list(cfg.model.nodes()))
        assert len(new_proj.kb.functions) == len(proj.kb.functions)

        # compare each function
        for func in proj.kb.functions.values():
            new_func = new_proj.kb.functions[func.addr]

            assert func.addr == new_func.addr
            assert func.normalized == new_func.normalized

            assert len(func.transition_graph.nodes()) == len(new_func.transition_graph.nodes())
            assert {x.addr for x in func.transition_graph.nodes()} == {
                x.addr for x in new_func.transition_graph.nodes()
            }
            assert len(func.transition_graph.edges()) == len(new_func.transition_graph.edges())

            # new_func (which is just loaded out of angr db) should be marked as dirty so it can potentially be
            # saved to LMDB if it's evicted.
            assert new_func.dirty is True

        # compare call graph
        callgraph_nodes_old = set(proj.kb.callgraph.nodes)
        callgraph_nodes_new = set(new_proj.kb.callgraph.nodes)
        callgraph_edges_old = set(proj.kb.callgraph.edges)
        callgraph_edges_new = set(new_proj.kb.callgraph.edges)

        assert callgraph_nodes_old == callgraph_nodes_new
        assert callgraph_edges_old == callgraph_edges_new

        # compare CFG
        new_cfg = new_proj.kb.cfgs["CFGFast"]
        for node in cfg.model.nodes():
            new_node = new_cfg.get_any_node(node.addr)

            assert new_node.addr == node.addr
            assert new_node.size == node.size

        # compare memory data
        for addr, memory_data in cfg.model.memory_data.items():
            new_memory_data = new_cfg.memory_data[addr]

            assert memory_data.addr == new_memory_data.addr
            assert memory_data.size == new_memory_data.size
            assert memory_data.reference_size == new_memory_data.reference_size
            assert memory_data.sort == new_memory_data.sort
            assert memory_data.content == new_memory_data.content

        assert cfg.model.insn_addr_to_memory_data.keys() == new_cfg.insn_addr_to_memory_data.keys()

        # comments
        for addr, comment in proj.kb.comments.items():
            new_comment = new_proj.kb.comments.get(addr, None)

            assert comment == new_comment

    def test_angrdb_fast_load_spilled_functions(self):
        # When the database contains more functions than the function manager may keep in memory, the serialized
        # function bytes are moved directly into the LMDB backing store on load without being deserialized, and the
        # serialized callgraph is loaded directly instead of being rebuilt.
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        AngrDB(proj, nullpool=True).dump(db_file)

        def _edge_multiset(callgraph):
            return Counter(
                (src, dst, key, tuple(sorted(data.items())))
                for src, dst, key, data in callgraph.edges(keys=True, data=True)
            )

        # force the fast path by using a tiny function cache limit
        with mock.patch.object(
            angr.knowledge_plugins.functions.function_manager.FunctionManager,
            "get_default_cache_limit",
            return_value=3,
        ):
            new_proj = AngrDB(nullpool=True).load(db_file)

        funcs = new_proj.kb.functions
        assert len(funcs) == len(proj.kb.functions)
        # functions were spilled rather than deserialized into memory
        assert funcs.spilled_function_count > 0

        # the callgraph must round-trip exactly, including edge multiplicity and edge data
        assert set(proj.kb.functions.callgraph.nodes) == set(funcs.callgraph.nodes)
        assert _edge_multiset(proj.kb.functions.callgraph) == _edge_multiset(funcs.callgraph)

        # on-demand access must fully deserialize each function
        for func in proj.kb.functions.values():
            new_func = funcs[func.addr]
            assert new_func.addr == func.addr
            assert new_func.name == func.name
            assert new_func.is_default_name == func.is_default_name
            assert new_func.returning == func.returning
            assert new_func.block_addrs_set == func.block_addrs_set
            assert len(new_func.transition_graph.edges()) == len(func.transition_graph.edges())

        # manager caches must be populated without deserializing functions
        assert funcs.function_addrs_set == proj.kb.functions.function_addrs_set
        assert dict(funcs._func_block_counts) == dict(proj.kb.functions._func_block_counts)

        # backward compatibility: a database without a stored callgraph (i.e., produced by an older version of angr)
        # must fall back to rebuilding the callgraph from function transition graphs
        conn = sqlite3.connect(db_file)
        conn.execute("DELETE FROM callgraphs")
        conn.commit()
        conn.close()

        old_format_proj = AngrDB(nullpool=True).load(db_file)
        assert set(old_format_proj.kb.functions.callgraph.nodes) == set(proj.kb.functions.callgraph.nodes)
        assert set(old_format_proj.kb.functions.callgraph.edges()) == set(proj.kb.functions.callgraph.edges())

    def test_angrdb_dump_byte_copies_clean_spilled_functions(self):
        # When dumping a function manager whose functions are spilled to LMDB and clean, the serialized bytes are
        # copied directly out of the LMDB backing store; only dirty functions are re-serialized.
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")
        db_file2 = os.path.join(dtemp, "fauxware2.adb")

        AngrDB(proj, nullpool=True).dump(db_file)

        # force the load fast path so that all functions end up spilled and clean
        with mock.patch.object(
            angr.knowledge_plugins.functions.function_manager.FunctionManager,
            "get_default_cache_limit",
            return_value=3,
        ):
            loaded_proj = AngrDB(nullpool=True).load(db_file)

        funcs = loaded_proj.kb.functions
        num_funcs = len(funcs)

        # mixed state: mutate two functions so they become dirty and cached
        addrs = sorted(funcs)
        rename_addr = addrs[0]
        returning_addr = addrs[1]
        funcs[rename_addr].name = "renamed_for_dump_test"
        funcs[returning_addr].returning = funcs[returning_addr].returning is False

        # count byte-copied vs re-serialized functions during the dump
        spilling_dict_cls = angr.knowledge_plugins.functions.function_manager.SpillingFunctionDict
        orig_export = spilling_dict_cls.export_serialized
        stats = {}

        def counting_export(self):
            result = orig_export(self)
            stats["copied"] = sum(1 for _, _, copied in result if copied)
            stats["serialized"] = sum(1 for _, _, copied in result if not copied)
            return result

        with mock.patch.object(spilling_dict_cls, "export_serialized", counting_export):
            AngrDB(loaded_proj, nullpool=True).dump(db_file2)

        assert stats["copied"] + stats["serialized"] == num_funcs
        # the two mutated functions are re-serialized; everything else must have been byte-copied
        assert stats["serialized"] >= 2
        assert stats["copied"] >= num_funcs - 5

        # the dumped database must round-trip both the mutations and the byte-copied functions
        reloaded_proj = AngrDB(nullpool=True).load(db_file2)
        new_funcs = reloaded_proj.kb.functions
        assert len(new_funcs) == num_funcs
        assert new_funcs[rename_addr].name == "renamed_for_dump_test"
        assert new_funcs[returning_addr].returning == funcs[returning_addr].returning
        for func in proj.kb.functions.values():
            new_func = new_funcs[func.addr]
            if func.addr not in (rename_addr, returning_addr):
                assert new_func.name == func.name
                assert new_func.returning == func.returning
            assert new_func.block_addrs_set == func.block_addrs_set
            assert len(new_func.transition_graph.edges()) == len(func.transition_graph.edges())

    def test_angrdb_fast_load_spilled_cfg_nodes(self):
        # When the database contains more CFG nodes than the CFG node cache may keep in memory, the serialized node
        # bytes are moved directly into the LMDB backing store on load without being deserialized, and the graph
        # structure is built without materializing CFGNode objects.
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        AngrDB(proj, nullpool=True).dump(db_file)

        # force the fast path by using tiny CFG node/edge cache limits
        with (
            mock.patch.object(angr.Project, "get_cfg_node_cache_limit", return_value=5),
            mock.patch.object(angr.Project, "get_cfg_edge_cache_limit", return_value=5),
        ):
            new_proj = AngrDB(nullpool=True).load(db_file)

        new_cfg = new_proj.kb.cfgs["CFGFast"]
        assert new_cfg.graph.spilled_count > 0

        assert new_cfg.graph.number_of_nodes() == cfg.model.graph.number_of_nodes()
        assert new_cfg.graph.number_of_edges() == cfg.model.graph.number_of_edges()

        # on-demand access must fully deserialize each node, and node content must round-trip
        def _node_rec(n):
            return (
                n.addr,
                n.size,
                n.block_id,
                n.name,
                n.function_address,
                n.no_ret,
                n.thumb,
                n.is_syscall,
                n.simprocedure_name,
                n.byte_string,
                tuple(n.instruction_addrs),
            )

        assert sorted(_node_rec(n) for n in new_cfg.graph.nodes()) == sorted(
            _node_rec(n) for n in cfg.model.graph.nodes()
        )

        # edge content (including edge data) must round-trip
        def _edge_recs(model):
            return sorted(
                (src.addr, src.size, dst.addr, dst.size, data.get("jumpkind"), data.get("ins_addr"))
                for src, dst, data in model.graph.edges(data=True)
            )

        assert _edge_recs(new_cfg) == _edge_recs(cfg.model)

        # get_any_node must work and return nodes with the correct function addresses
        for func in proj.kb.functions.values():
            for block_addr in func.block_addrs_set:
                node = new_cfg.get_any_node(block_addr)
                old_node = cfg.model.get_any_node(block_addr)
                if old_node is not None:
                    assert node is not None
                    assert node.function_address == old_node.function_address

    def test_angrdb_open_multiple_times(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        _: angr.analyses.CFGFast = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)
        proj.kb.comments[proj.entry] = "Entry point"

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        db = AngrDB(proj, nullpool=True)
        db.dump(db_file)

        # attempt 0
        db0 = AngrDB(nullpool=True)
        proj0 = db0.load(db_file)

        # attempt 1
        db1 = AngrDB(nullpool=True)
        proj1 = db1.load(db_file)

        # attempt 2
        db2 = AngrDB(nullpool=True)
        proj2 = db2.load(db_file)

        # attempt 3
        db3 = AngrDB(nullpool=True)
        proj3 = db3.load(db_file)

        # compare functions
        for func in proj.kb.functions.values():
            for p in [proj0, proj1, proj2, proj3]:
                new_func = p.kb.functions[func.addr]

                assert func.addr == new_func.addr
                assert func.normalized == new_func.normalized

                assert len(func.transition_graph.nodes()) == len(new_func.transition_graph.nodes())
                assert {x.addr for x in func.transition_graph.nodes()} == {
                    x.addr for x in new_func.transition_graph.nodes()
                }
                assert len(func.transition_graph.edges()) == len(new_func.transition_graph.edges())

    def test_angrdb_save_multiple_times(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        _: angr.analyses.CFGFast = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)
        proj.kb.comments[proj.entry] = "Entry point"

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        # attempt 0
        db = AngrDB(proj, nullpool=True)
        db.dump(db_file)

        # attempt 1
        proj0 = AngrDB(nullpool=True).load(db_file)
        assert proj0.kb.comments[proj.entry] == "Entry point"
        proj0.kb.comments[proj.entry] = "Comment 0"
        AngrDB(proj0).dump(db_file)

        # attempt 2
        proj1 = AngrDB(nullpool=True).load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 0"
        proj1.kb.comments[proj.entry] = "Comment 1"
        AngrDB(proj1).dump(db_file)

        # attempt 3
        proj1 = AngrDB(nullpool=True).load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 1"
        proj1.kb.comments[proj.entry] = "Comment 22222222222222222222222"
        AngrDB(proj1).dump(db_file)

        # attempt 4
        proj1 = AngrDB(nullpool=True).load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 22222222222222222222222"

    def test_angrdb_save_without_binary_existence(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "proj.adb")

            with tempfile.TemporaryDirectory() as td0:
                tmp_path = os.path.join(td0, os.path.basename(bin_path))
                shutil.copy(bin_path, tmp_path)
                proj = angr.Project(tmp_path, auto_load_libs=False)

                AngrDB(proj, nullpool=True).dump(db_file)

                del proj
                os.remove(tmp_path)

            # now that the binary file no longer exists, we should be able to open the angr DB and save it without
            # raising exceptions.
            proj = AngrDB(nullpool=True).load(db_file)
            os.remove(db_file)

            db_file_new = os.path.join(td, "proj_new.adb")
            AngrDB(proj, nullpool=True).dump(db_file_new)

            # we should be able to load it back!
            proj_new = AngrDB(nullpool=True).load(db_file_new)
            assert os.path.basename(proj_new.loader.main_object.binary) == "fauxware"

    def test_angrdb_cart_file(self):
        bin_path = os.path.join(test_location, "x86_64", "1after909.cart")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "proj.adb")

            with tempfile.TemporaryDirectory() as td0:
                tmp_path = os.path.join(td0, os.path.basename(bin_path))
                shutil.copy(bin_path, tmp_path)
                proj = angr.Project(
                    tmp_path,
                    auto_load_libs=False,
                    main_opts={"arc4_key": b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
                )
                assert proj.loader._main_binary_path.endswith("1after909.cart")

                # let's build a CFG and then save it as well
                assert len(proj.kb.functions) == 0
                proj.analyses.CFG(normalize=True)
                func_count = len(proj.kb.functions)
                assert func_count > 0

                assert isinstance(proj.loader.all_objects[0], cle.backends.CARTFile)
                assert "arc4_key" in proj.loader.all_objects[0].load_args
                assert proj.loader._main_binary_path.endswith("1after909.cart")
                assert proj.loader.main_object.binary is None

                AngrDB(proj, nullpool=True).dump(db_file)

                del proj
                os.remove(tmp_path)

            # now that the binary file no longer exists, we should be able to open the angr DB and save it without
            # raising exceptions.
            proj = AngrDB(nullpool=True).load(db_file)
            assert proj.loader._main_binary_path.endswith("1after909.cart")
            assert proj.loader.main_object.binary is None
            assert len(proj.kb.functions) == func_count
            os.remove(db_file)

            db_file_new = os.path.join(td, "proj_new.adb")
            AngrDB(proj, nullpool=True).dump(db_file_new)

            # we should be able to load it back!
            proj_new = AngrDB(nullpool=True).load(db_file_new)
            assert proj.loader._main_binary_path.endswith("1after909.cart")
            assert proj_new.loader.main_object.binary is None
            assert len(proj.kb.functions) == func_count

    def test_angrdb_decompilation_display_format(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "proj.adb")

            with tempfile.TemporaryDirectory() as td0:
                tmp_path = os.path.join(td0, os.path.basename(bin_path))
                shutil.copy(bin_path, tmp_path)
                proj = angr.Project(tmp_path, auto_load_libs=False)
                proj.analyses.CFG(normalize=True)
                proj.analyses.CompleteCallingConventions()

                # decompile the main function
                main_func = proj.kb.functions["main"]
                dec = proj.analyses.Decompiler(main_func)
                assert dec.codegen is not None and dec.codegen.text is not None
                print_decompilation_result(dec)
                assert dec.codegen.text.count("0x8") == 0

                # find the CConstant whose value is 8
                target_consts = []
                for _, elem in dec.codegen.map_pos_to_node.items():
                    if isinstance(elem.obj, CConstant) and elem.obj.value == 8:
                        target_consts.append(elem.obj)

                assert len(target_consts) == 2
                assert target_consts[0]._ident < target_consts[1]._ident

                # change the display format of the first one to hex
                target_consts[0].fmt_hex = True

                # now if we decompile it again, we should see the change reflected
                dec_1 = proj.analyses.Decompiler(main_func)
                assert dec_1.codegen is not None and dec_1.codegen.text is not None
                print_decompilation_result(dec_1)
                assert dec_1.codegen.text.count("0x8") == 1

                # it should be part of the structured code cache
                assert proj.kb.decompilations

                AngrDB(proj, nullpool=True).dump(db_file)

                del proj
                os.remove(tmp_path)

            # now that the binary file no longer exists, we should be able to open the angr DB and save it without
            # raising exceptions.

            proj = AngrDB(nullpool=True).load(db_file)
            os.remove(db_file)

            db_file_new = os.path.join(td, "proj_new.adb")
            AngrDB(proj, nullpool=True).dump(db_file_new)

            # we should be able to load it back!
            proj_new = AngrDB(nullpool=True).load(db_file_new)
            assert os.path.basename(proj_new.loader.main_object.binary) == "fauxware"

            # decompile the function again
            dec_2 = proj_new.analyses.Decompiler(proj_new.kb.functions["main"])
            assert dec_2.codegen is not None and dec_2.codegen.text is not None
            print_decompilation_result(dec_2)
            assert dec_2.codegen.text.count("0x8") == 1

    def test_angrdb_decompilation_load_variables(self):
        # https://github.com/angr/angr/issues/5990

        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        with tempfile.TemporaryDirectory() as td:
            out_db = os.path.join(td, "out.sqlite")

            proj = angr.Project(bin_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(
                normalize=True,
                resolve_indirect_jumps=True,
                detect_tail_calls=True,
            )
            dec = proj.analyses.Decompiler("main", variable_kb=proj.kb, cfg=cfg.model, regen_clinic=False)
            assert dec.codegen is not None and dec.codegen.text is not None

            adb = AngrDB(proj, nullpool=True)
            adb.dump(out_db, extra_info={"binary_path": bin_path})

            _proj = AngrDB(nullpool=True).load(out_db)

    def test_angrdb_blob_loader_options_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            blob_path = os.path.join(td, "sample.bin")
            db_file = os.path.join(td, "sample.adb")

            with open(blob_path, "wb") as f:
                f.write(b"\x01\x02\x03\x04")

            proj = angr.Project(
                blob_path,
                auto_load_libs=False,
                main_opts={"backend": "blob", "arch": "ARMHF"},
            )

            loaded = self._roundtrip_angrdb(proj, db_file)
            self._assert_loader_state(loaded, cle.backends.Blob, "ARMHF")

    def test_angrdb_blob_loader_options_roundtrip_with_arch_object(self):
        with tempfile.TemporaryDirectory() as td:
            blob_path = os.path.join(td, "sample.bin")
            db_file = os.path.join(td, "sample.adb")
            db_file_2 = os.path.join(td, "sample_2.adb")

            with open(blob_path, "wb") as f:
                f.write(b"\x01\x02\x03\x04")

            proj = angr.Project(
                blob_path,
                auto_load_libs=False,
                main_opts={"backend": "blob", "arch": archinfo.arch_from_id("ARMHF")},
            )

            loaded = self._roundtrip_angrdb(proj, db_file)
            self._assert_loader_state(loaded, cle.backends.Blob, "ARMHF")

            loaded_2 = self._roundtrip_angrdb(loaded, db_file_2)
            self._assert_loader_state(loaded_2, cle.backends.Blob, "ARMHF")

    def test_angrdb_ihex_loader_options_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            hex_path = os.path.join(td, "sample.ihex")
            db_file = os.path.join(td, "sample.adb")

            with open(hex_path, "wb") as f:
                f.write(b":0400000001020304F2\n:00000001FF\n")

            proj = angr.Project(
                hex_path,
                auto_load_libs=False,
                main_opts={"backend": "hex", "arch": "ARMHF"},
            )

            loaded = self._roundtrip_angrdb(proj, db_file)
            self._assert_loader_state(loaded, cle.backends.Hex, "ARMHF")

    def test_angrdb_ihex_loader_options_roundtrip_with_arch_object(self):
        with tempfile.TemporaryDirectory() as td:
            hex_path = os.path.join(td, "sample.ihex")
            db_file = os.path.join(td, "sample.adb")
            db_file_2 = os.path.join(td, "sample_2.adb")

            with open(hex_path, "wb") as f:
                f.write(b":0400000001020304F2\n:00000001FF\n")

            proj = angr.Project(
                hex_path,
                auto_load_libs=False,
                main_opts={"backend": "hex", "arch": archinfo.arch_from_id("ARMHF")},
            )

            loaded = self._roundtrip_angrdb(proj, db_file)
            self._assert_loader_state(loaded, cle.backends.Hex, "ARMHF")

            loaded_2 = self._roundtrip_angrdb(loaded, db_file_2)
            self._assert_loader_state(loaded_2, cle.backends.Hex, "ARMHF")

    def test_angrdb_loader_multi_object(self):
        """Verify that a Loader with multiple objects can be dumped and loaded correctly."""
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        lib_path = os.path.join(test_location, "x86_64", "libc.so.6")
        proj = angr.Project(bin_path, preload_libs=[lib_path], auto_load_libs=False)

        objects = proj.loader.all_elf_objects

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            proj2 = AngrDB(nullpool=True).load(db_file)

        objects2 = proj2.loader.all_elf_objects

        assert len(objects) == len(objects2), f"number of objects mismatch: {len(objects)} vs {len(objects2)}"

        for o1, o2 in zip(objects, objects2):
            name1 = os.path.basename(o1.binary) if o1.binary else None
            name2 = os.path.basename(o2.binary) if o2.binary else None
            assert name1 == name2, f"object binary name mismatch: {name1} vs {name2}"
            assert o1.min_addr == o2.min_addr
            assert o1.max_addr == o2.max_addr


if __name__ == "__main__":
    unittest.main()
