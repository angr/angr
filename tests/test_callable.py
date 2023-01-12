import angr
import claripy
import archinfo
import unittest
from angr.sim_type import SimTypePointer, SimTypeFunction, SimTypeChar, SimTypeInt, parse_defns
from angr.errors import AngrCallableMultistateError

import logging

l = logging.getLogger("angr_tests")

import os
from common import slow_test, bin_location as location

addresses_fauxware = {
    "armel": 0x8524,
    "armhf": 0x104C9,  # addr+1 to force thumb
    "i386": 0x8048524,
    "mips": 0x400710,
    "mipsel": 0x4006D0,
    "ppc": 0x1000054C,
    "ppc64": 0x10000698,
    "x86_64": 0x400664,
}

addresses_manysum = {
    "armel": 0x1041C,
    "armhf": 0x103BD,
    "i386": 0x80483D8,
    "mips": 0x400704,
    "mipsel": 0x400704,
    "ppc": 0x10000418,
    "ppc64": 0x10000500,
    "x86_64": 0x4004CA,
}

type_cache = None


class TestCallable(unittest.TestCase):
    def run_fauxware(self, arch):
        addr = addresses_fauxware[arch]
        p = angr.Project(os.path.join(location, "tests", arch, "fauxware"))
        charstar = SimTypePointer(SimTypeChar())
        prototype = SimTypeFunction((charstar, charstar), SimTypeInt(False))
        authenticate = p.factory.callable(
            addr, toc=0x10018E80 if arch == "ppc64" else None, concrete_only=True, prototype=prototype
        )
        assert authenticate("asdf", "SOSNEAKY")._model_concrete.value == 1
        self.assertRaises(AngrCallableMultistateError, authenticate, "asdf", "NOSNEAKY")

    def run_callable_c_fauxware(self, arch):
        addr = addresses_fauxware[arch]
        p = angr.Project(os.path.join(location, "tests", arch, "fauxware"))
        authenticate = p.factory.callable(
            addr, toc=0x10018E80 if arch == "ppc64" else None, concrete_only=True, prototype="int f(char*, char*)"
        )
        retval = authenticate.call_c('("asdf", "SOSNEAKY")')
        assert retval._model_concrete.value == 1

    def run_manysum(self, arch):
        addr = addresses_manysum[arch]
        p = angr.Project(os.path.join(location, "tests", arch, "manysum"))
        inttype = SimTypeInt()
        prototype = SimTypeFunction([inttype] * 11, inttype)
        sumlots = p.factory.callable(addr, prototype=prototype)
        result = sumlots(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
        assert not result.symbolic
        assert result._model_concrete.value == sum(range(12))

    def run_callable_c_manysum(self, arch):
        addr = addresses_manysum[arch]
        p = angr.Project(os.path.join(location, "tests", arch, "manysum"))
        sumlots = p.factory.callable(addr, prototype="int f(int, int, int, int, int, int, int, int, int, int, int)")
        result = sumlots.call_c("(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)")
        assert not result.symbolic
        assert result._model_concrete.value == sum(range(12))

    def run_manyfloatsum(self, arch):
        global type_cache
        if type_cache is None:
            with open(os.path.join(location, "tests_src", "manyfloatsum.c")) as fp:
                type_cache = parse_defns(fp.read())

        p = angr.Project(os.path.join(location, "tests", arch, "manyfloatsum"))
        for function in (
            "sum_floats",
            "sum_combo",
            "sum_segregated",
            "sum_doubles",
            "sum_combo_doubles",
            "sum_segregated_doubles",
        ):
            args = list(range(len(type_cache[function].args)))
            answer = float(sum(args))
            addr = p.loader.main_object.get_symbol(function).rebased_addr
            my_callable = p.factory.callable(addr, prototype=type_cache[function])
            result = my_callable(*args)
            assert not result.symbolic
            result_concrete = result.args[0]
            assert answer == result_concrete

    @slow_test
    def run_manyfloatsum_symbolic(self, arch):
        global type_cache
        if type_cache is None:
            with open(os.path.join(location, "tests_src", "manyfloatsum.c")) as fp:
                type_cache = parse_defns(fp.read())

        p = angr.Project(os.path.join(location, "tests", arch, "manyfloatsum"))
        function = "sum_doubles"
        args = [claripy.FPS("arg_%d" % i, claripy.FSORT_DOUBLE) for i in range(len(type_cache[function].args))]
        addr = p.loader.main_object.get_symbol(function).rebased_addr
        my_callable = p.factory.callable(addr, prototype=type_cache[function])
        result = my_callable(*args)
        assert result.symbolic

        s = claripy.Solver(timeout=15 * 60 * 1000)
        for arg in args:
            s.add(arg > claripy.FPV(1.0, claripy.FSORT_DOUBLE))
        s.add(result == claripy.FPV(27.7, claripy.FSORT_DOUBLE))

        args_conc = s.batch_eval(args, 1)[0]
        assert s.eval(result, 1)[0] == 27.7
        # not almost equal!! totally equal!!! z3 is magic, if kinda slow!!!!!
        for arg_conc in args_conc:
            assert arg_conc > 1.0
        assert sum(args_conc) == 27.7

    def test_fauxware_armel(self):
        self.run_fauxware("armel")

    def test_fauxware_armhf(self):
        self.run_fauxware("armhf")

    def test_fauxware_i386(self):
        self.run_fauxware("i386")

    def test_fauxware_mips(self):
        self.run_fauxware("mips")

    def test_fauxware_mipsel(self):
        self.run_fauxware("mipsel")

    def test_fauxware_ppc(self):
        self.run_fauxware("ppc")

    def test_fauxware_ppc64(self):
        self.run_fauxware("ppc64")

    def test_fauxware_x86_64(self):
        self.run_fauxware("x86_64")

    def test_manysum_armel(self):
        self.run_manysum("armel")

    def test_manysum_armhf(self):
        self.run_manysum("armhf")

    def test_manysum_i386(self):
        self.run_manysum("i386")

    def test_manysum_mips(self):
        self.run_manysum("mips")

    def test_manysum_mipsel(self):
        self.run_manysum("mipsel")

    def test_manysum_ppc(self):
        self.run_manysum("ppc")

    def test_manysum_ppc64(self):
        self.run_manysum("ppc64")

    def test_manysum_x86_64(self):
        self.run_manysum("x86_64")

    def test_manyfloatsum_i386(self):
        self.run_manyfloatsum("i386")

    def test_manyfloatsum_x86_64(self):
        self.run_manyfloatsum("x86_64")

    @slow_test
    def test_manyfloatsum_symbolic_i386(self):
        # doesn't have to be slow but it might be
        # https://github.com/Z3Prover/z3/issues/2584
        self.run_manyfloatsum_symbolic("i386")

    @slow_test
    def test_manyfloatsum_symbolic_x86_64(self):
        # doesn't have to be slow but it might be
        # https://github.com/Z3Prover/z3/issues/2584
        self.run_manyfloatsum_symbolic("x86_64")

    def test_callable_c_fauxware_armel(self):
        self.run_callable_c_fauxware("armel")

    def test_callable_c_fauxware_armhf(self):
        self.run_callable_c_fauxware("armhf")

    def test_callable_c_fauxware_i386(self):
        self.run_callable_c_fauxware("i386")

    def test_callable_c_fauxware_mips(self):
        self.run_callable_c_fauxware("mips")

    def test_callable_c_fauxware_mipsel(self):
        self.run_callable_c_fauxware("mipsel")

    def test_callable_c_fauxware_ppc(self):
        self.run_callable_c_fauxware("ppc")

    def test_callable_c_fauxware_ppc64(self):
        self.run_callable_c_fauxware("ppc64")

    def test_callable_c_fauxware_x86_64(self):
        self.run_callable_c_fauxware("x86_64")

    def test_callable_c_manyfloatsum_armel(self):
        self.run_callable_c_manysum("armel")

    def test_callable_c_manyfloatsum_armhf(self):
        self.run_callable_c_manysum("armhf")

    def test_callable_c_manyfloatsum_i386(self):
        self.run_callable_c_manysum("i386")

    def test_callable_c_manyfloatsum_mips(self):
        self.run_callable_c_manysum("mips")

    def test_callable_c_manyfloatsum_mipsel(self):
        self.run_callable_c_manysum("mipsel")

    def test_callable_c_manyfloatsum_ppc(self):
        self.run_callable_c_manysum("ppc")

    def test_callable_c_manyfloatsum_ppc64(self):
        self.run_callable_c_manysum("ppc64")

    def test_callable_c_manyfloatsum_x86_64(self):
        self.run_callable_c_manysum("x86_64")

    def test_setup_callsite(self):
        p = angr.load_shellcode(b"b", arch=archinfo.ArchX86())

        s = p.factory.call_state(
            0, "hello", prototype="void x(char*)", stack_base=0x1234, alloc_base=0x5678, grow_like_stack=False
        )
        assert (s.regs.sp == 0x1234).is_true()
        assert (s.mem[0x1234 + 4].long.resolved == 0x5678).is_true()
        assert (s.memory.load(0x5678, 5) == b"hello").is_true()

        s = p.factory.call_state(0, "hello", prototype="void x(char*)", stack_base=0x1234)
        assert (s.regs.sp == 0x1234).is_true()
        assert (s.mem[0x1234 + 4].long.resolved == 0x1234 + 8).is_true()
        assert (s.memory.load(0x1234 + 8, 5) == b"hello").is_true()


if __name__ == "__main__":
    unittest.main()
