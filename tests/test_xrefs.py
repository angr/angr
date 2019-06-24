
import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_lwip_udpecho_bm():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    p = angr.Project(bin_path, auto_load_libs=False)
    cfg = p.analyses.CFG(collect_data_references=True)

    func = cfg.functions[0x23c9]
    state = p.factory.blank_state()
    prop = p.analyses.Propagator(func=func, base_state=state)
    xrefs = p.analyses.XRefs(func=func, replacements=prop.replacements)


if __name__ == "__main__":
    test_lwip_udpecho_bm()
