
import os

import nose.tools

import angr
from angr.analyses.code_location import CodeLocation
from angr.knowledge_plugins.xrefs import XRef, XRefType

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_lwip_udpecho_bm():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    cfg = p.analyses.CFG(collect_data_references=True)

    func = cfg.functions[0x23c9]
    state = p.factory.blank_state()
    prop = p.analyses.Propagator(func=func, base_state=state)
    _ = p.analyses.XRefs(func=func, replacements=prop.replacements)

    timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23d4)  # the constant in the constant pool
    timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1fff36f4)  # the value in .bss

    nose.tools.assert_equal(len(timenow_cp_xrefs), 1)
    nose.tools.assert_equal(next(iter(timenow_cp_xrefs)),
                            XRef(XRefType.Read, CodeLocation(0x23c9, stmt_idx=10, ins_addr=0x23c9), 0x23d4)
                            )

    nose.tools.assert_equal(len(timenow_xrefs), 2)


if __name__ == "__main__":
    test_lwip_udpecho_bm()
