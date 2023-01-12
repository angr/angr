# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestDb(unittest.TestCase):
    def test_angrdb_fauxware(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg: angr.analyses.CFGFast = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)
        proj.kb.comments[proj.entry] = "Entry point"

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        db = AngrDB(proj)
        db.dump(db_file)

        db1 = AngrDB()
        new_proj = db1.load(db_file)

        assert len(new_proj.kb.cfgs["CFGFast"].nodes()) == len(cfg.model.nodes())
        assert len(new_proj.kb.functions) == len(proj.kb.functions)

        # compare each function
        for func in proj.kb.functions.values():
            new_func = new_proj.kb.functions[func.addr]

            assert func.addr == new_func.addr
            assert func.normalized == new_func.normalized

            assert len(func.transition_graph.nodes()) == len(new_func.transition_graph.nodes())
            assert set(map(lambda x: x.addr, func.transition_graph.nodes())) == set(
                map(lambda x: x.addr, new_func.transition_graph.nodes())
            )
            assert len(func.transition_graph.edges()) == len(new_func.transition_graph.edges())

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

        db = AngrDB(proj)
        db.dump(db_file)

        # attempt 0
        db0 = AngrDB()
        proj0 = db0.load(db_file)

        # attempt 1
        db1 = AngrDB()
        proj1 = db1.load(db_file)

        # attempt 2
        db2 = AngrDB()
        proj2 = db2.load(db_file)

        # attempt 3
        db3 = AngrDB()
        proj3 = db3.load(db_file)

        # compare functions
        for func in proj.kb.functions.values():
            for p in [proj0, proj1, proj2, proj3]:
                new_func = p.kb.functions[func.addr]

                assert func.addr == new_func.addr
                assert func.normalized == new_func.normalized

                assert len(func.transition_graph.nodes()) == len(new_func.transition_graph.nodes())
                assert set(map(lambda x: x.addr, func.transition_graph.nodes())) == set(
                    map(lambda x: x.addr, new_func.transition_graph.nodes())
                )
                assert len(func.transition_graph.edges()) == len(new_func.transition_graph.edges())

    def test_angrdb_save_multiple_times(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        _: angr.analyses.CFGFast = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)
        proj.kb.comments[proj.entry] = "Entry point"

        dtemp = tempfile.mkdtemp()
        db_file = os.path.join(dtemp, "fauxware.adb")

        # attempt 0
        db = AngrDB(proj)
        db.dump(db_file)

        # attempt 1
        proj0 = AngrDB().load(db_file)
        assert proj0.kb.comments[proj.entry] == "Entry point"
        proj0.kb.comments[proj.entry] = "Comment 0"
        AngrDB(proj0).dump(db_file)

        # attempt 2
        proj1 = AngrDB().load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 0"
        proj1.kb.comments[proj.entry] = "Comment 1"
        AngrDB(proj1).dump(db_file)

        # attempt 3
        proj1 = AngrDB().load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 1"
        proj1.kb.comments[proj.entry] = "Comment 22222222222222222222222"
        AngrDB(proj1).dump(db_file)

        # attempt 4
        proj1 = AngrDB().load(db_file)
        assert proj1.kb.comments[proj.entry] == "Comment 22222222222222222222222"


if __name__ == "__main__":
    unittest.main()
