# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))
arches = {"x86_64"}


class TestDdgGlobalVarDependencies(unittest.TestCase):
    def test_ddg_global_var_dependencies(self):
        for arch in arches:
            self.run_ddg_global_var_dependencies(arch)

    def run_ddg_global_var_dependencies(self, arch):
        test_file = os.path.join(test_location, arch, "ddg_global_var_dependencies")
        proj = angr.Project(test_file, auto_load_libs=False)
        cfg = proj.analyses.CFGEmulated(
            context_sensitivity_level=2,
            keep_state=True,
            state_add_options=angr.sim_options.refs,
        )
        ddg = proj.analyses.DDG(cfg)
        main_func = cfg.functions.function(name="main")

        target_block_addr = main_func.ret_sites[0].addr
        target_block = proj.factory.block(addr=target_block_addr)
        tgt_stmt_idx, tgt_stmt = self.get_target_stmt(proj, target_block)
        assert tgt_stmt_idx is not None
        buf_addr = tgt_stmt.data.addr.con.value
        tgt_ddg_node = self.get_ddg_node(ddg, target_block_addr, tgt_stmt_idx)
        assert tgt_ddg_node is not None

        # Whether the target depends on the statement assigning 'b' to the global variable
        has_correct_dependency = False
        for pred in ddg.get_predecessors(tgt_ddg_node):
            pred_block = proj.factory.block(addr=pred.block_addr)
            stmt = pred_block.vex.statements[pred.stmt_idx]
            has_correct_dependency |= self.check_dependency(stmt, buf_addr, ord("b"))

            # If the target depends on the statement assigning 'a' to the global variable, it is underconstrained (
            # this assignment should be overwritten by the 'b' assignment)
            assert not self.check_dependency(
                stmt, buf_addr, ord("a")
            ), "Target statement has incorrect dependency (DDG is underconstrained)"
        assert has_correct_dependency, "Target statement does not have correct dependency (DDG is overconstrained)"

    def check_dependency(self, stmt, addr, const):
        # Check if we are storing a constant to a variable with constant address
        if stmt.tag == "Ist_Store" and stmt.addr.tag == "Iex_Const" and stmt.data.tag == "Iex_Const":
            # Check if we are storing the specified constant to the specified variable address
            if stmt.addr.con.value == addr and stmt.data.con.value == const:
                return True

        return False

    def get_ddg_node(self, ddg, block_addr, stmt_idx):
        for node in ddg.graph.nodes:
            if node.block_addr == block_addr and node.stmt_idx == stmt_idx:
                return node
        return None

    def get_target_stmt(self, proj, block):
        for i, stmt in enumerate(block.vex.statements):
            # We're looking for the instruction that loads a constant memory address into a temporary variable
            if stmt.tag == "Ist_WrTmp" and stmt.data.tag == "Iex_Load" and stmt.data.addr.tag == "Iex_Const":
                addr = stmt.data.addr.con.value
                section = proj.loader.main_object.find_section_containing(addr)
                # Confirm the memory address is in the uninitialized data section
                if section.name == ".bss":
                    return i, stmt
        return None, None


if __name__ == "__main__":
    unittest.main()
