
import sys
import os
import logging

import nose

import angr
from angr.sim_variable import SimStackVariable, SimRegisterVariable
from angr.knowledge_plugins.variables import VariableType


l = logging.getLogger('test_variablerecovery')


test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '..', '..', 'binaries', 'tests'
                                 )
                    )


#
# Utility methods
#

def _compare_memory_variable(variable, variable_info):

    if variable_info['location'] == 'stack':
        if not isinstance(variable, SimStackVariable):
            return False

        # base
        if 'base' in variable_info:
            base = variable_info['base']
            if variable.base != base:
                return False

        # offset
        if 'offset' in variable_info:
            offset = variable_info['offset']
            if variable.offset != offset:
                return False

        # size
        if 'size' in variable_info:
            size = variable_info['size']
            if variable.size != size:
                return False

        return True

    else:
        if isinstance(variable, SimStackVariable):
            # it is not a variable on the stack
            return False

        raise NotImplementedError()


def _compare_register_variable(variable, variable_info):  # pylint:disable=unused-argument

    if not isinstance(variable, SimRegisterVariable):
        return False

    if 'reg' in variable_info:
        reg = variable_info['reg']
        if variable.reg != reg:
            return False

    if 'size' in variable_info:
        size = variable_info['size']
        if variable.size != size:
            return False

    return True


def run_variable_recovery_analysis(project, func, groundtruth, is_fast):

    # Create a temporary KnowledgeBase instance
    tmp_kb = angr.KnowledgeBase(project)

    if is_fast:
        l.debug("Running VariableRecoveryFast on function %r.", func)
        vr = project.analyses.VariableRecoveryFast(func, kb=tmp_kb)
    else:
        l.debug("Running VariableRecovery on function %r.", func)
        vr = project.analyses.VariableRecovery(func, kb=tmp_kb)

    variable_manager = vr.variable_manager[func.addr]

    for insn_addr, variables in groundtruth['variables_by_instruction'].items():
        for var_info in variables:
            var_sort = var_info['sort']
            vars_and_offset = variable_manager.find_variables_by_insn(insn_addr, var_sort)

            # enumerate vars and find the variable that we want
            if var_sort == VariableType.MEMORY:
                the_var = next((var for var, _ in vars_and_offset if _compare_memory_variable(var, var_info)), None)
            elif var_sort == VariableType.REGISTER:
                the_var = next((var for var, _ in vars_and_offset if _compare_register_variable(var, var_info)), None)
            else:
                l.error('Unsupported variable sort %s.', var_sort)
                assert False

            nose.tools.assert_is_not_none(the_var, msg="The variable %s in groundtruth at instruction %#x cannot be "
                                                       "found in variable manager." % (var_info, insn_addr)
                                          )
            l.debug("Found variable %s at %#x.", the_var, insn_addr)

    for block_addr, variables in groundtruth['phi_variables_by_block'].items():
        phi_variables = variable_manager.get_phi_variables(block_addr)
        for var_info in variables:
            var_sort = var_info['sort']

            # enumerate vars and find the variable that we want
            if var_sort == VariableType.MEMORY:
                the_var = next((var for var in phi_variables if _compare_memory_variable(var, var_info)), None)
            elif var_sort == VariableType.REGISTER:
                the_var = next((var for var in phi_variables if _compare_register_variable(var, var_info)), None)
            else:
                l.error('Unsupported variable sort %s.', var_sort)
                assert False

            nose.tools.assert_is_not_none(the_var, msg="The phi variable %s in groundtruth at block %#x cannot be "
                                                       "found in variable manager." % (var_info, block_addr)
                                          )
            l.debug("Found phi variable %s at %#x.", the_var, block_addr)


def test_variable_recovery_fauxware():

    binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFG(normalize=True)

    groundtruth = {
        'authenticate': {
            'variables_by_instruction': {
                0x40066c: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x18, 'size': 8},
                ],
                0x400670: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x20, 'size': 8},
                ],
                0x400674: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x8, 'size': 1},
                ],
                0x40067f: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x20, 'size': 8},
                ],
                0x400699: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x18, 'size': 8},
                ],
                0x4006af: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x4, 'size': 4},
                ],
                0x4006b2: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x10, 'size': 1},
                ]
            },
            'phi_variables_by_block': {
                0x4006eb: [
                    {'sort': VariableType.REGISTER, 'reg': 16, 'size': 8},
                    {'sort': VariableType.REGISTER, 'reg': 32, 'size': 8},
                    {'sort': VariableType.REGISTER, 'reg': 64, 'size': 8},
                    {'sort': VariableType.REGISTER, 'reg': 72, 'size': 8},
                ]
            },
        },
        'main': {
            'variables_by_instruction': {
                0x400725: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x34, 'size': 4},
                ],
                0x400728: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x40, 'size': 8},
                ],
                0x40072c: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x8, 'size': 1},
                ],
                0x400730: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x18, 'size': 1},
                ],
                0x40073e: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x10, 'size': 1},
                ],
                0x400754: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x24, 'size': 1},
                ],
                0x400774: [
                    {'sort': VariableType.MEMORY, 'location': 'stack', 'base': 'bp', 'offset': -0x20, 'size': 1},
                ],
            },
            'phi_variables_by_block': {

            },
        }
    }

    for func_name, truth in groundtruth.items():
        yield run_variable_recovery_analysis, project, cfg.kb.functions[func_name], truth, True
        yield run_variable_recovery_analysis, project, cfg.kb.functions[func_name], truth, False


def main():

    g = globals()
    if len(sys.argv) > 1:
        func_name = "test_%s" % sys.argv[1]
        if func_name not in g:
            func_name = "test_variable_recovery_%s" % sys.argv[1]
        for testfunc_and_args in g[func_name]():
            testfunc, args = testfunc_and_args[0], testfunc_and_args[1:]
            testfunc(*args)
    else:
        for func_name, func in g.items():
            if func_name.startswith('test_') and hasattr(func, '__call__'):
                print(func_name)
                for testfunc_and_args in func():
                    testfunc, args = testfunc_and_args[0], testfunc_and_args[1:]
                    testfunc(*args)


if __name__ == '__main__':

    l.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.variable_recovery_fast').setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.variable_recovery').setLevel(logging.DEBUG)

    main()
