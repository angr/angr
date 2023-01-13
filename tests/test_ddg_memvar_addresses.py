# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))
arches = {"i386", "x86_64"}


class TestDdgMemvarAddresses(unittest.TestCase):
    def test_ddg_memvar_addresses(self):
        for arch in arches:
            self.run_ddg_memvar_addresses(arch)

    def run_ddg_memvar_addresses(self, arch):
        test_file = os.path.join(test_location, arch, "simple_data_dependence")
        proj = angr.Project(test_file, auto_load_libs=False)
        cfg = proj.analyses.CFGEmulated(
            context_sensitivity_level=2,
            keep_state=True,
            state_add_options=angr.sim_options.refs,
        )
        ddg = proj.analyses.DDG(cfg)

        for node in ddg._data_graph.nodes():
            if isinstance(node.variable, angr.sim_variable.SimMemoryVariable):
                assert (
                    0 <= node.variable.addr < (1 << proj.arch.bits)
                ), f"Program variable {node.variable} has an invalid address: {node.variable.addr}"


if __name__ == "__main__":
    unittest.main()
