import nose
import angr
import claripy
import archinfo
from angr.sim_type import SimTypePointer, SimTypeFunction, SimTypeChar, SimTypeInt, parse_defns
from angr.errors import AngrCallableMultistateError

import logging
l = logging.getLogger("angr_tests")

import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

addresses_fauxware = {
    'armel': 0x8524,
    'armhf': 0x104c9,    # addr+1 to force thumb
    'i386': 0x8048524,
    'mips': 0x400710,
    'mipsel': 0x4006d0,
    'ppc': 0x1000054c,
    'ppc64': 0x10000698,
    'x86_64': 0x400664
}

addresses_manysum = {
    'armel': 0x1041c,
    'armhf': 0x103bd,
    'i386': 0x80483d8,
    'mips': 0x400704,
    'mipsel': 0x400704,
    'ppc': 0x10000418,
    'ppc64': 0x10000500,
    'x86_64': 0x4004ca
}

def run_fauxware(arch):
    addr = addresses_fauxware[arch]
    p = angr.Project(os.path.join(location, arch, 'fauxware'))
    charstar = SimTypePointer(SimTypeChar())
    prototype = SimTypeFunction((charstar, charstar), SimTypeInt(False))
    cc = p.factory.cc(func_ty=prototype)
    authenticate = p.factory.callable(addr, toc=0x10018E80 if arch == 'ppc64' else None, concrete_only=True, cc=cc)
    nose.tools.assert_equal(authenticate("asdf", "SOSNEAKY")._model_concrete.value, 1)
    nose.tools.assert_raises(AngrCallableMultistateError, authenticate, "asdf", "NOSNEAKY")


def run_callable_c_fauxware(arch):
    addr = addresses_fauxware[arch]
    p = angr.Project(os.path.join(location, arch, 'fauxware'))
    cc = p.factory.cc(func_ty="int f(char*, char*)")
    authenticate = p.factory.callable(addr, toc=0x10018E80 if arch == 'ppc64' else None, concrete_only=True, cc=cc)
    retval = authenticate.call_c('("asdf", "SOSNEAKY")')
    nose.tools.assert_equal(retval._model_concrete.value, 1)
    nose.tools.assert_raises(AngrCallableMultistateError, authenticate, "asdf", "NOSNEAKY")


def run_manysum(arch):
    addr = addresses_manysum[arch]
    p = angr.Project(os.path.join(location, arch, 'manysum'))
    inttype = SimTypeInt()
    prototype = SimTypeFunction([inttype]*11, inttype)
    cc = p.factory.cc(func_ty=prototype)
    sumlots = p.factory.callable(addr, cc=cc)
    result = sumlots(1,2,3,4,5,6,7,8,9,10,11)
    nose.tools.assert_false(result.symbolic)
    nose.tools.assert_equal(result._model_concrete.value, sum(range(12)))


def run_callable_c_manysum(arch):
    addr = addresses_manysum[arch]
    p = angr.Project(os.path.join(location, arch, 'manysum'))
    cc = p.factory.cc(func_ty="int f(int, int, int, int, int, int, int, int, int, int, int)")
    sumlots = p.factory.callable(addr, cc=cc)
    result = sumlots.call_c("(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)")
    nose.tools.assert_false(result.symbolic)
    nose.tools.assert_equal(result._model_concrete.value, sum(range(12)))

type_cache = None

def run_manyfloatsum(arch):
    global type_cache
    if type_cache is None:
        type_cache = parse_defns(open(os.path.join(location, '..', 'tests_src', 'manyfloatsum.c')).read())

    p = angr.Project(os.path.join(location, arch, 'manyfloatsum'))
    for function in ('sum_floats', 'sum_combo', 'sum_segregated', 'sum_doubles', 'sum_combo_doubles', 'sum_segregated_doubles'):
        cc = p.factory.cc(func_ty=type_cache[function])
        args = list(range(len(cc.func_ty.args)))
        answer = float(sum(args))
        addr = p.loader.main_object.get_symbol(function).rebased_addr
        my_callable = p.factory.callable(addr, cc=cc)
        result = my_callable(*args)
        nose.tools.assert_false(result.symbolic)
        result_concrete = result.args[0]
        nose.tools.assert_equal(answer, result_concrete)

def run_manyfloatsum_symbolic(arch):
    global type_cache
    if type_cache is None:
        type_cache = parse_defns(open(os.path.join(location, '..', 'tests_src', 'manyfloatsum.c')).read())

    p = angr.Project(os.path.join(location, arch, 'manyfloatsum'))
    function = 'sum_doubles'
    cc = p.factory.cc(func_ty=type_cache[function])
    args = [claripy.FPS('arg_%d' % i, claripy.FSORT_DOUBLE) for i in range(len(type_cache[function].args))]
    addr = p.loader.main_object.get_symbol(function).rebased_addr
    my_callable = p.factory.callable(addr, cc=cc)
    result = my_callable(*args)
    nose.tools.assert_true(result.symbolic)

    s = claripy.Solver()
    for arg in args:
        s.add(arg > claripy.FPV(1.0, claripy.FSORT_DOUBLE))
    s.add(result == claripy.FPV(27.7, claripy.FSORT_DOUBLE))

    args_conc = s.batch_eval(args, 1)[0]
    nose.tools.assert_equal(s.eval(result, 1)[0], 27.7)
    # not almost equal!! totally equal!!! z3 is magic, if kinda slow!!!!!
    for arg_conc in args_conc:
        nose.tools.assert_greater(arg_conc, 1.0)
    nose.tools.assert_equal(sum(args_conc), 27.7)


def test_fauxware():
    for arch in addresses_fauxware:
        yield run_fauxware, arch

def test_manysum():
    for arch in addresses_manysum:
        yield run_manysum, arch

def test_manyfloatsum():
    for arch in ('i386', 'x86_64'):
        yield run_manyfloatsum, arch

def test_manyfloatsum_symbolic():
    for arch in ('i386', 'x86_64'):
        yield run_manyfloatsum_symbolic, arch


def test_callable_c_fauxware():
    for arch in addresses_fauxware:
        yield run_callable_c_fauxware, arch


def test_callable_c_manyfloatsum():
    for arch in addresses_manysum:
        yield run_callable_c_manysum, arch

def test_setup_callsite():
    p = angr.load_shellcode(b'b', arch=archinfo.ArchX86())

    s = p.factory.call_state(0, "hello", stack_base=0x1234, alloc_base=0x5678, grow_like_stack=False)
    assert (s.regs.sp == 0x1234).is_true()
    assert (s.mem[0x1234 + 4].long.resolved == 0x5678).is_true()
    assert (s.memory.load(0x5678, 5) == b'hello').is_true()

    s = p.factory.call_state(0, "hello", stack_base=0x1234)
    assert (s.regs.sp == 0x1234).is_true()
    assert (s.mem[0x1234 + 4].long.resolved == 0x1234 + 8).is_true()
    assert (s.memory.load(0x1234 + 8, 5) == b'hello').is_true()



if __name__ == "__main__":
    print('testing manyfloatsum with symbolic arguments')
    for func, march in test_manyfloatsum_symbolic():
        print('* testing ' + march)
        func(march)
    print('testing manyfloatsum')
    for func, march in test_manyfloatsum():
        print('* testing ' + march)
        func(march)
    print('testing fauxware')
    for func, march in test_fauxware():
        print('* testing ' + march)
        func(march)
    print('testing fauxware with c-style strings')
    for func, march in test_callable_c_fauxware():
        func(march)
    print('testing manysum')
    for func, march in test_manysum():
        print('* testing ' + march)
        func(march)
    print('testing manyfloatsum with c_style strings')
    for func, march in test_callable_c_manyfloatsum():
        print('* testing ' + march)
        func(march)
