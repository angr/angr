
import logging
import os

import nose.tools

import archinfo
import angr
from angr.calling_conventions import SimStackArg, SimRegArg, SimCCCdecl, SimCCSystemVAMD64


test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..',
                             'binaries',
                             )

def run_fauxware(arch, function_and_cc_list):
    binary_path = os.path.join(test_location, 'tests', arch, 'fauxware')
    fauxware = angr.Project(binary_path, auto_load_libs=False)

    cfg = fauxware.analyses.CFG()

    for func_name, expected_cc in function_and_cc_list:
        authenticate = cfg.functions[func_name]
        _ = fauxware.analyses.VariableRecoveryFast(authenticate)

        cc_analysis = fauxware.analyses.CallingConvention(authenticate, cfg=cfg, analyze_callsites=True)
        cc = cc_analysis.cc

        nose.tools.assert_equal(cc, expected_cc)


def run_cgc(binary_name):
    binary_path = os.path.join(test_location, '..', 'binaries-private', 'cgc_qualifier_event', 'cgc', binary_name)
    project = angr.Project(binary_path)

    categorization = project.analyses.FunctionCategorizationAnalysis()

    # tag_manager = categorization.function_tag_manager
    # print "INPUT:", map(hex, tag_manager.input_functions())
    # print "OUTPUT:", map(hex, tag_manager.output_functions())


def test_fauxware():

    amd64 = archinfo.arch_from_id('amd64')

    args = {
        'i386': [
            ('authenticate', SimCCCdecl(
                archinfo.arch_from_id('i386'),
                args=[SimStackArg(4, 4), SimStackArg(8, 4)], sp_delta=4, ret_val=SimRegArg('eax', 4),
                )
             ),
        ],
        'x86_64': [
            ('authenticate', SimCCSystemVAMD64(
                amd64,
                args=[SimRegArg('rdi', 8), SimRegArg('rsi', 8)],
                sp_delta=8,
                ret_val=SimRegArg('rax', 8),
                )
             ),
        ],
    }

    for arch, lst in args.items():
        yield run_fauxware, arch, lst


# def test_cgc():
def disabled_cgc():
    # Skip this test since we do not have the binaries-private repo cloned on Travis CI.

    binaries = [
        '002ba801_01',
        '01cf6c01_01',
    ]

    for binary in binaries:
        yield run_cgc, binary

#
# Full-binary calling convention analysis
#

def check_arg(arg, expected_str):

    if isinstance(arg, SimRegArg):
        arg_str = "r_%s" % (arg.reg_name)
    else:
        raise TypeError("Unsupported argument type %s." % type(arg))
    return arg_str == expected_str


def check_args(func_name, args, expected_arg_strs):

    nose.tools.assert_equal(len(args), len(expected_arg_strs), msg="Wrong number of arguments for function %s. "
                                                                   "Got %d, expect %d." % (
        func_name, len(args), len(expected_arg_strs)
    ))

    for idx, (arg, expected_arg_str) in enumerate(zip(args, expected_arg_strs)):
        r = check_arg(arg, expected_arg_str)
        nose.tools.assert_true(r, msg="Incorrect argument %d for function %s. Got %s, expect %s." % (
            idx, func_name, arg, expected_arg_str
        ))


def _a(funcs, func_name):
    return funcs[func_name].calling_convention.args


def test_x8664_dir_gcc_O0():

    binary_path = os.path.join(test_location, 'tests', 'x86_64', 'dir_gcc_-O0')
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

    cfg = proj.analyses.CFG()  # fill in the default kb

    proj.analyses.CompleteCallingConventions(recover_variables=True)

    funcs = cfg.kb.functions

    # check args
    expected_args = {
        'c_ispunct': ['r_rdi'],
        'file_failure': ['r_rdi', 'r_rsi', 'r_rdx'],
        'to_uchar': ['r_rdi'],
        'dot_or_dotdot': ['r_rdi'],
        'emit_mandatory_arg_note': [ ],
        'emit_size_note': [ ],
        'emit_ancillary_info': ['r_rdi'],
        'emit_try_help': [ ],
        'dev_ino_push': ['r_rdi', 'r_rsi'],
        'main': ['r_rdi', 'r_rsi'],
        'queue_directory': ['r_rdi', 'r_rsi', 'r_rdx'],
    }

    for func_name, args in expected_args.items():
        check_args(func_name, _a(funcs, func_name), args)


def test_armel_fauxware():
    binary_path = os.path.join(test_location, 'tests', 'armel', 'fauxware')
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

    cfg = proj.analyses.CFG()  # fill in the default kb

    proj.analyses.CompleteCallingConventions(recover_variables=True)

    funcs = cfg.kb.functions

    # check args
    expected_args = {
        'main': ['r_r0', 'r_r1'],
        'accepted': ['r_r0', 'r_r1', 'r_r2', 'r_r3'],
        'rejected': [ ],
        'authenticate': ['r_r0', 'r_r1'],
    }

    for func_name, args in expected_args.items():
        check_args(func_name, _a(funcs, func_name), args)


def test_x8664_void():
    binary_path = os.path.join(test_location, 'tests', 'x86_64', 'types', 'void')
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

    cfg = proj.analyses.CFG()

    proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model, analyze_callsites=True)

    funcs = cfg.kb.functions

    groundtruth = {
        'func_1': None,
        'func_2': None,
        'func_3': 'rax',
        'func_4': None,
        'func_5': None,
        'func_6': 'rax',
    }

    for func in funcs.values():
        if func.is_simprocedure or func.alignment:
            continue
        if func.calling_convention is None:
            continue
        if func.name in groundtruth:
            r = groundtruth[func.name]
            if r is None:
                assert func.calling_convention.ret_val is None
            else:
                assert isinstance(func.calling_convention.ret_val, SimRegArg)
                assert func.calling_convention.ret_val.reg_name == r


def run_all():
    for args in test_fauxware():
        func, args = args[0], args[1:]
        func(*args)

    #for args in test_cgc():
    #    func, args = args[0], args[1:]
    #    func(*args)


if __name__ == "__main__":
    # logging.getLogger("angr.analyses.variable_recovery.variable_recovery_fast").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.calling_convention").setLevel(logging.INFO)
    # run_all()
    test_x8664_void()
    # test_dir_gcc_O0()
