
import os

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_smoketest():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'linked_list'), auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    main_func = cfg.kb.functions['sum']

    vr = p.analyses.VariableRecoveryFast(main_func)
    p.analyses.CompleteCallingConventions()

    # import pprint
    tcons = vr.type_constraints
    # pprint.pprint(vr._outstates[0x4005b2].typevars._typevars)
    # pprint.pprint(tcons)

    _ = p.analyses.Typehoon(tcons)
    # pprint.pprint(t.simtypes_solution)

    # convert function blocks to AIL blocks
    # clinic = p.analyses.Clinic(main_func)

    #t = p.analyses.Typehoon(main_func) #, clinic)
    #print(t)


if __name__ == "__main__":
    test_smoketest()
