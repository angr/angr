
import random

from ....sim_type import SimTypeFunction, SimTypeInt
from ..func import Func, TestData
from ..custom_callable import IdentifierCallable


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class memcpy(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(memcpy, self).__init__() #pylint disable=useless-super-delegation
        self.memmove_safe = False

    def get_name(self): #pylint disable=no-self-use
        if self.memmove_safe:
            return "memmove"
        return "memcpy"

    def num_args(self):
        return 3

    def args(self):
        return ["dst", "src", "len"]

    def can_call_other_funcs(self): #pylint disable=no-self-use
        return False

    def gen_input_output_pair(self):
        # TODO we don't check the return val
        copy_len = random.randint(1,40)
        buf = rand_str(copy_len)
        result_buf = rand_str(copy_len+5)
        test_input = [result_buf, buf, copy_len]
        test_output = [buf + result_buf[-5:], buf, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):

        result_buf = "A" * 6
        in_buf = "a\x00bbbc"

        test_input = [result_buf, in_buf, 6]
        test_output = [in_buf, in_buf, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        result = runner.test(func, test)
        if not result:
            return False

        s = runner.get_base_call_state(func, test)
        s.memory.store(0x2000, "ABC\x00\x00\x00\x00\x00")
        inttype = SimTypeInt(runner.project.arch.bits, False)
        func_ty = SimTypeFunction([inttype] * 3, inttype)
        cc = runner.project.factory.cc(func_ty=func_ty)
        call = IdentifierCallable(runner.project, func.startpoint.addr, concrete_only=True,
                        cc=cc, base_state=s, max_steps=20)
        _ = call(*[0x2003, 0x2000, 5])
        result_state = call.result_state
        self.memmove_safe = bool(result_state.solver.eval(result_state.memory.load(0x2000, 8), cast_to=bytes) == "ABCABC\x00\x00")

        s = runner.get_base_call_state(func, test)
        s.memory.store(0x2000, "\x00\x00\x00\x00\x00CBA")
        inttype = SimTypeInt(runner.project.arch.bits, False)
        func_ty = SimTypeFunction([inttype] * 3, inttype)
        cc = runner.project.factory.cc(func_ty=func_ty)
        call = IdentifierCallable(runner.project, func.startpoint.addr, concrete_only=True,
                        cc=cc, base_state=s, max_steps=20)
        _ = call(*[0x2000, 0x2003, 5])
        result_state = call.result_state
        if result_state.solver.eval(result_state.memory.load(0x2000, 8), cast_to=bytes) == "\x00\x00CBACBA":
            self.memmove_safe = True and self.memmove_safe
        else:
            self.memmove_safe = False

        return True
