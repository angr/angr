
import os

import nose.tools

import angr
from angr.knowledge_plugins.xrefs import XRef, XRefType

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_lwip_udpecho_bm():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True)

    func = cfg.functions[0x23c9]
    state = p.factory.blank_state()
    prop = p.analyses.Propagator(func=func, base_state=state)
    _ = p.analyses.XRefs(func=func, replacements=prop.replacements)

    timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23d4)  # the constant in the constant pool
    timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1fff36f4)  # the value in .bss

    nose.tools.assert_equal(len(timenow_cp_xrefs), 1)
    nose.tools.assert_equal(next(iter(timenow_cp_xrefs)),
                            XRef(ins_addr=0x23c9, dst=0x23d4, xref_type=XRefType.Read)
                            )

    nose.tools.assert_equal(len(timenow_xrefs), 2)


def test_lwip_udpecho_bm_the_better_way():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    cfg = p.analyses.CFG(cross_references=True)  # pylint:disable=unused-variable

    timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23d4)  # the constant in the constant pool
    timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1fff36f4)  # the value in .bss

    nose.tools.assert_equal(len(timenow_cp_xrefs), 1)
    nose.tools.assert_equal(next(iter(timenow_cp_xrefs)),
                            XRef(ins_addr=0x23c9, dst=0x23d4, xref_type=XRefType.Read)
                            )
    # time_init, sys_now, time_isr == 3
    nose.tools.assert_equal(len(timenow_xrefs), 3)


if __name__ == "__main__":
    test_lwip_udpecho_bm()
