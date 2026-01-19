#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import os
import tempfile
import shutil
import unittest

import cle

import angr
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.angrdb import AngrDB

from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDb(unittest.TestCase):
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

        assert len(new_proj.kb.cfgs["CFGFast"].nodes()) == len(cfg.model.nodes())
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


if __name__ == "__main__":
    unittest.main()
