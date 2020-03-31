
import os
import tempfile

import angr
from angr.angrdb import AngrDB

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_angrdb_fauxware():
    bin_path = os.path.join(test_location, "x86_64", "fauxware")

    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)  # type: angr.analyses.CFGFast

    dtemp = tempfile.mkdtemp()
    db_file = os.path.join(dtemp, "fauxware.adb")

    db = AngrDB(proj)
    db.dump(db_file)

    db1 = AngrDB()
    new_proj = db1.load(db_file)

    assert len(new_proj.kb.cfgs['CFGFast'].nodes()) == len(cfg.model.nodes())
    assert len(new_proj.kb.functions) == len(proj.kb.functions)

    # compare each function
    for func in proj.kb.functions.values():
        new_func = new_proj.kb.functions[func.addr]

        assert func.addr == new_func.addr
        assert func.normalized == new_func.normalized

        assert len(func.transition_graph.nodes()) == len(new_func.transition_graph.nodes())
        assert len(func.transition_graph.edges()) == len(new_func.transition_graph.edges())

    # compare CFG
    new_cfg = new_proj.kb.cfgs['CFGFast']
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


if __name__ == "__main__":
    test_angrdb_fauxware()
