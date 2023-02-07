import os
import logging
import unittest

import angr
from angr.sim_variable import SimStackVariable, SimRegisterVariable
from angr.knowledge_plugins.variables import VariableType


l = logging.getLogger("test_variablerecovery")


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


#
# Utility methods
#


class TestVariableRecovery(unittest.TestCase):
    def _compare_memory_variable(self, variable, variable_info):
        if variable_info["location"] == "stack":
            if not isinstance(variable, SimStackVariable):
                return False

            # base
            if "base" in variable_info:
                base = variable_info["base"]
                if variable.base != base:
                    return False

            # offset
            if "offset" in variable_info:
                offset = variable_info["offset"]
                if variable.offset != offset:
                    return False

            # size
            if "size" in variable_info:
                size = variable_info["size"]
                if variable.size != size:
                    return False

            return True

        else:
            if isinstance(variable, SimStackVariable):
                # it is not a variable on the stack
                return False

            raise NotImplementedError()

    def _compare_register_variable(self, variable, variable_info):  # pylint:disable=unused-argument
        if not isinstance(variable, SimRegisterVariable):
            return False

        if "reg" in variable_info:
            reg = variable_info["reg"]
            if variable.reg != reg:
                return False

        if "size" in variable_info:
            size = variable_info["size"]
            if variable.size != size:
                return False

        return True

    def _run_variable_recovery_analysis(self, func_name, groundtruth, is_fast):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        project = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = project.analyses.CFG(normalize=True)
        func = cfg.kb.functions[func_name]

        # Create a temporary KnowledgeBase instance
        tmp_kb = angr.KnowledgeBase(project)

        if is_fast:
            l.debug("Running VariableRecoveryFast on function %r.", func)
            vr = project.analyses.VariableRecoveryFast(func, kb=tmp_kb)
        else:
            l.debug("Running VariableRecovery on function %r.", func)
            vr = project.analyses.VariableRecovery(func, kb=tmp_kb)

        variable_manager = vr.variable_manager[func.addr]

        for insn_addr, variables in groundtruth["variables_by_instruction"].items():
            for var_info in variables:
                var_sort = var_info["sort"]
                vars_and_offset = variable_manager.find_variables_by_insn(insn_addr, var_sort)

                # enumerate vars and find the variable that we want
                if var_sort == VariableType.MEMORY:
                    the_var = next(
                        (var for var, _ in vars_and_offset if self._compare_memory_variable(var, var_info)),
                        None,
                    )
                elif var_sort == VariableType.REGISTER:
                    the_var = next(
                        (var for var, _ in vars_and_offset if self._compare_register_variable(var, var_info)),
                        None,
                    )
                else:
                    l.error("Unsupported variable sort %s.", var_sort)
                    assert False

                assert (
                    the_var is not None
                ), "The variable {} in groundtruth at instruction {:#x} cannot be found in variable manager.".format(
                    var_info,
                    insn_addr,
                )
                l.debug("Found variable %s at %#x.", the_var, insn_addr)

        for block_addr, variables in groundtruth["phi_variables_by_block"].items():
            phi_variables = variable_manager.get_phi_variables(block_addr)
            for var_info in variables:
                var_sort = var_info["sort"]

                # enumerate vars and find the variable that we want
                if var_sort == VariableType.MEMORY:
                    the_var = next(
                        (var for var in phi_variables if self._compare_memory_variable(var, var_info)),
                        None,
                    )
                elif var_sort == VariableType.REGISTER:
                    the_var = next(
                        (var for var in phi_variables if self._compare_register_variable(var, var_info)),
                        None,
                    )
                else:
                    l.error("Unsupported variable sort %s.", var_sort)
                    assert False

                assert (
                    the_var is not None
                ), "The phi variable {} in groundtruth at block {:#x} cannot be found in variable manager.".format(
                    var_info,
                    block_addr,
                )
                l.debug("Found phi variable %s at %#x.", the_var, block_addr)

    def test_variable_recovery_fauxware_authenticate_true(self):
        self._run_variable_recovery_analysis(
            "authenticate",
            {
                "variables_by_instruction": {
                    0x40066C: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 8,
                        },
                    ],
                    0x400670: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 8,
                        },
                    ],
                    0x400674: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x8,
                            "size": 1,
                        },
                    ],
                    0x40067F: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 8,
                        },
                    ],
                    0x400699: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 8,
                        },
                    ],
                    0x4006AF: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x4,
                            "size": 4,
                        },
                    ],
                    0x4006B2: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x10,
                            "size": 1,
                        },
                    ],
                },
                "phi_variables_by_block": {
                    0x4006EB: [
                        {"sort": VariableType.REGISTER, "reg": 16, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 32, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 64, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 72, "size": 8},
                    ]
                },
            },
            True,
        )

    def test_variable_recovery_fauxware_authenticate_false(self):
        self._run_variable_recovery_analysis(
            "authenticate",
            {
                "variables_by_instruction": {
                    0x40066C: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 8,
                        },
                    ],
                    0x400670: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 8,
                        },
                    ],
                    0x400674: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x8,
                            "size": 1,
                        },
                    ],
                    0x40067F: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 8,
                        },
                    ],
                    0x400699: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 8,
                        },
                    ],
                    0x4006AF: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x4,
                            "size": 4,
                        },
                    ],
                    0x4006B2: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x10,
                            "size": 1,
                        },
                    ],
                },
                "phi_variables_by_block": {
                    0x4006EB: [
                        {"sort": VariableType.REGISTER, "reg": 16, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 32, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 64, "size": 8},
                        {"sort": VariableType.REGISTER, "reg": 72, "size": 8},
                    ]
                },
            },
            False,
        )

    def test_variable_recovery_fauxware_main_true(self):
        self._run_variable_recovery_analysis(
            "main",
            {
                "variables_by_instruction": {
                    0x400725: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x34,
                            "size": 4,
                        },
                    ],
                    0x400728: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x40,
                            "size": 8,
                        },
                    ],
                    0x40072C: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x8,
                            "size": 1,
                        },
                    ],
                    0x400730: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 1,
                        },
                    ],
                    0x40073E: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x10,
                            "size": 1,
                        },
                    ],
                    0x400754: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x24,
                            "size": 1,
                        },
                    ],
                    0x400774: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 1,
                        },
                    ],
                },
                "phi_variables_by_block": {},
            },
            True,
        )

    def test_variable_recovery_fauxware_main_false(self):
        self._run_variable_recovery_analysis(
            "main",
            {
                "variables_by_instruction": {
                    0x400725: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x34,
                            "size": 4,
                        },
                    ],
                    0x400728: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x40,
                            "size": 8,
                        },
                    ],
                    0x40072C: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x8,
                            "size": 1,
                        },
                    ],
                    0x400730: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x18,
                            "size": 1,
                        },
                    ],
                    0x40073E: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x10,
                            "size": 1,
                        },
                    ],
                    0x400754: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x24,
                            "size": 1,
                        },
                    ],
                    0x400774: [
                        {
                            "sort": VariableType.MEMORY,
                            "location": "stack",
                            "base": "bp",
                            "offset": -0x20,
                            "size": 1,
                        },
                    ],
                },
                "phi_variables_by_block": {},
            },
            False,
        )


if __name__ == "__main__":
    l.setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.variable_recovery_fast").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.variable_recovery").setLevel(logging.DEBUG)

    unittest.main()
