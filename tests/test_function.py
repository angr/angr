
import os

import nose.tools

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_function_serialization():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions['main']
    s = func_main.serialize()

    nose.tools.assert_is(type(s), bytes)
    nose.tools.assert_greater(len(s), 10)

    f = angr.knowledge_plugins.Function.parse(s)
    nose.tools.assert_equal(func_main.addr, f.addr)
    nose.tools.assert_equal(func_main.name, f.name)

def test_function_definition_application():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    cfg = p.analyses.CFG()
    func_main = cfg.kb.functions['main'] # type: angr.knowledge_plugins.Function


    func_main.apply_definition("int main(int argc, char** argv)")

    # Check prototype of function
    nose.tools.assert_equal(func_main.prototype.args,
                            [angr.sim_type.SimTypeInt().with_arch(p.arch), angr.sim_type.SimTypePointer(
                                angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar()).with_arch(p.arch)).with_arch(p.arch)])
    # Check that the default calling convention of the architecture was applied
    nose.tools.assert_true(isinstance(func_main.calling_convention, angr.calling_conventions.DefaultCC[p.arch.name]))

    func_main.apply_definition("int main(int argc, char** argv)")

def test_function_instruction_addr_from_any_addr():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions['main']

    nose.tools.assert_equal(func_main.addr_to_instruction_addr(0x400739), 0x400739)
    nose.tools.assert_equal(func_main.addr_to_instruction_addr(0x40073a), 0x400739)
    nose.tools.assert_equal(func_main.addr_to_instruction_addr(0x40073d), 0x400739)
    nose.tools.assert_equal(func_main.addr_to_instruction_addr(0x400742), 0x400742)
    nose.tools.assert_equal(func_main.addr_to_instruction_addr(0x400743), 0x400742)


if __name__ == "__main__":
    test_function_serialization()
    test_function_definition_application()
    test_function_instruction_addr_from_any_addr()
