
import logging
import os

import nose.tools

import archinfo
import angr
from angr.calling_conventions import SimStackArg, SimRegArg, SimCCCdecl


test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..',
                             'binaries',
                             )

def run_fauxware(arch, function_and_cc_list):
    binary_path = os.path.join(test_location, 'tests', arch, 'fauxware')
    fauxware = angr.Project(binary_path, auto_load_libs=False)

    cfg = fauxware.analyses.CFG()

    for func_name, expected_cc in function_and_cc_list:
        authenticate = cfg.functions[func_name]
        variable_recovery = fauxware.analyses.VariableRecoveryFast(authenticate)

        cc_analysis = fauxware.analyses.CallingConvention(authenticate)
        cc = cc_analysis.cc

        nose.tools.assert_equal(cc, expected_cc)


def run_cgc(binary_name):
    binary_path = os.path.join(test_location, '..', 'binaries-private', 'cgc_qualifier_event', 'cgc', binary_name)
    project = angr.Project(binary_path)

    categorization = project.analyses.FunctionCategorizationAnalysis()

    tag_manager = categorization.function_tag_manager
    print "INPUT:", map(hex, tag_manager.input_functions())
    print "OUTPUT:", map(hex, tag_manager.output_functions())


def test_fauxware():

    args = {
        'i386': [
            ('authenticate', SimCCCdecl(
                archinfo.arch_from_id('i386'),
                args=[SimStackArg(4, 4), SimStackArg(8, 4)], sp_delta=4
                )
             ),
        ],
    }

    for arch, lst in args.iteritems():
        yield run_fauxware, arch, lst


def test_cgc():

    binaries = [
        '002ba801_01',
        '01cf6c01_01',
    ]

    for binary in binaries:
        yield run_cgc, binary


def run_all():
    logging.getLogger("angr.analyses.variable_recovery.variable_recovery_fast").setLevel(logging.DEBUG)

    for args in test_fauxware():
        func, args = args[0], args[1:]
        func(*args)

    #for args in test_cgc():
    #    func, args = args[0], args[1:]
    #    func(*args)


if __name__ == "__main__":
    run_all()
