
import os

import nose.tools

import angr
import angr.calling_conventions

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_function_prototype():

    proj = angr.Project(os.path.join(test_location, 'x86_64', 'all'))

    func = angr.knowledge_plugins.Function(proj.kb.functions, 0x100000, name='strcmp')
    func.prototype = angr.SIM_LIBRARIES['libc.so.6'].prototypes[func.name]
    func.calling_convention = angr.calling_conventions.DEFAULT_CC[proj.arch.name](
        proj.arch,
        func_ty=func.prototype,
    )

    # import ipdb; ipdb.set_trace()


def test_find_prototype():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'all'), auto_load_libs=False)

    cfg = proj.analyses.CFG()

    func = cfg.kb.functions.function(name='strcmp', plt=False)
    func.calling_convention = angr.calling_conventions.DEFAULT_CC[proj.arch.name](proj.arch)

    # Calling SimCC.arg_locs() should fail when the function prototype is not provided.
    nose.tools.assert_raises(ValueError, func.calling_convention.arg_locs)

    func.find_declaration()

    arg_locs = func.calling_convention.arg_locs()  # now it won't fail

    nose.tools.assert_equal(len(arg_locs), 2)
    nose.tools.assert_equal(arg_locs[0].reg_name, 'rdi')
    nose.tools.assert_equal(arg_locs[1].reg_name, 'rsi')


def main():
    test_find_prototype()
    test_function_prototype()

if __name__ == "__main__":
    main()
