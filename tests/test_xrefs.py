import os


import angr
from angr.knowledge_plugins.xrefs import XRef, XRefType

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_lwip_udpecho_bm():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True)

    func = cfg.functions[0x23C9]
    state = p.factory.blank_state()
    prop = p.analyses.Propagator(func=func, base_state=state)
    _ = p.analyses.XRefs(func=func, replacements=prop.replacements)

    timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23D4)  # the constant in the constant pool
    timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1FFF36F4)  # the value in .bss

    assert len(timenow_cp_xrefs) == 1
    assert next(iter(timenow_cp_xrefs)) == XRef(ins_addr=0x23C9, dst=0x23D4, xref_type=XRefType.Read)

    assert len(timenow_xrefs) == 3
    assert [x for x in timenow_xrefs if x.type == XRefType.Offset][0] == XRef(
        ins_addr=0x23C9, dst=0x1FFF36F4, xref_type=XRefType.Offset
    )
    assert [x for x in timenow_xrefs if x.type == XRefType.Read][0] == XRef(
        ins_addr=0x23CB, dst=0x1FFF36F4, xref_type=XRefType.Read
    )
    assert [x for x in timenow_xrefs if x.type == XRefType.Write][0] == XRef(
        ins_addr=0x23CF, dst=0x1FFF36F4, xref_type=XRefType.Write
    )


def test_lwip_udpecho_bm_the_better_way():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    p.analyses.CFG(cross_references=True)

    timenow_cp_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x23D4)  # the constant in the constant pool
    timenow_xrefs = p.kb.xrefs.get_xrefs_by_dst(0x1FFF36F4)  # the value in .bss

    assert len(timenow_cp_xrefs) == 1
    assert next(iter(timenow_cp_xrefs)) == XRef(ins_addr=0x23C9, dst=0x23D4, xref_type=XRefType.Read)
    # sys_now (2), time_isr (3) == 5
    assert len(timenow_xrefs) == 5


def test_p2im_drone_with_inits():
    bin_path = os.path.join(test_location, "armel", "p2im_drone.elf")
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFG(data_references=True)

    func = cfg.functions["Peripherals_Init"]
    state = proj.factory.blank_state()
    prop = proj.analyses.Propagator(func=func, base_state=state)

    init_finder = proj.analyses.InitializationFinder(func=func, replacements=prop.replacements)
    overlay_state = init_finder.overlay_state

    cfg.do_full_xrefs(overlay_state=overlay_state)

    h12c1_inst_xrefs = proj.kb.xrefs.get_xrefs_by_dst(0x20001500)
    assert len(h12c1_inst_xrefs) == 5


if __name__ == "__main__":
    test_lwip_udpecho_bm()
    test_lwip_udpecho_bm_the_better_way()
    test_p2im_drone_with_inits()
