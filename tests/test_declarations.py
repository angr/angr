
import os
import logging

import nose.tools

import angr
import angr.calling_conventions


def test_function_declaration():

    proj = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all'))

    func = angr.knowledge.Function(proj.kb.functions, 0x100000, name='strcmp')
    func.declaration = angr.SIM_DECLARATIONS['libc'][func.name]
    func.calling_convention = angr.calling_conventions.DEFAULT_CC[proj.arch.name](
        proj.arch,
        func_ty=func.declaration,
    )

    # import ipdb; ipdb.set_trace()


def test_find_declaration():
    proj = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)

    cfg = proj.analyses.CFG()

    func = proj.kb.functions.function(name='strcmp', plt=False)
    func.calling_convention = angr.calling_conventions.DEFAULT_CC[proj.arch.name](proj.arch)

    try:
        func.calling_convention.arg_locs()
        nose.tools.assert_true(False, msg="Calling SimCC.arg_locs() should fail when the function declaration is not provided.")
    except ValueError:
        # as expected
        pass

    func.find_declaration()

    arg_locs = func.calling_convention.arg_locs()  # now it won't fail

    nose.tools.assert_equal(len(arg_locs), 2)
    nose.tools.assert_equal(arg_locs[0].reg_name, 'rdi')
    nose.tools.assert_equal(arg_locs[1].reg_name, 'rsi')


def main():
    test_find_declaration()
    # test_function_declaration()

if __name__ == "__main__":
    main()
