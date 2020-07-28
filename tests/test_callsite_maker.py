import os

import angr
import ailment


def test_callsite_maker():

    project = angr.Project(os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)

    manager = ailment.Manager(arch=project.arch)

    # Generate a CFG
    cfg = project.analyses.CFG()

    new_cc_found = True
    while new_cc_found:
        new_cc_found = False
        for func in cfg.kb.functions.values():
            if func.calling_convention is None:
                # determine the calling convention of each function
                cc_analysis = project.analyses.CallingConvention(func)
                if cc_analysis.cc is not None:
                    func.calling_convention = cc_analysis.cc
                    new_cc_found = True

    main_func = cfg.kb.functions['main']

    for block in sorted(main_func.blocks, key=lambda x: x.addr):
        print(block.vex.pp())
        ail_block = ailment.IRSBConverter.convert(block.vex, manager)
        simp = project.analyses.AILBlockSimplifier(ail_block)

        csm = project.analyses.AILCallSiteMaker(simp.result_block)
        if csm.result_block:
            ail_block = csm.result_block
            simp = project.analyses.AILBlockSimplifier(ail_block)

        print(simp.result_block)



if __name__ == "__main__":
    test_callsite_maker()
