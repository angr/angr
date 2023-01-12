import logging
import unittest


from angr.state_plugins.callstack import CallStack

l = logging.getLogger("angr.tests.test_callstack")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallstack(unittest.TestCase):
    def test_empty_stack(self):
        cs = CallStack()

        # Initial setting: just assume the control flow starts from 0x300000
        cs = cs.call(None, 0x300000, None, 0xFFFFFFF0)

        # Calling 0x401000 from 0x400000. When it returns, it should return to 0x400004.
        # The stack pointer after entering the new function should be 0xffffff00
        # Note: this means on platforms like x86 and AMD64 where CALL instruction actually pushes the ret address on to
        # the stack and modifies the stack pointer, the user should adjust stack pointer accordingly (minus 4 or 8, for
        # example) before passing to CallStack.call(). CallStack has no way to know what the architecture it is used on.
        cs = cs.call(0x400000, 0x401000, 0x400004, 0xFFFFFF00)

        cs = cs.call(0x401008, 0x402000, 0x40100C, 0xFFFFFE80)

        assert cs.current_function_address == 0x402000
        assert cs.current_stack_pointer == 0xFFFFFE80

        # Return to 0x40100c
        cs = cs.ret(0x40100C)

        assert cs.current_function_address == 0x401000
        assert cs.current_stack_pointer == 0xFFFFFF00

        cs = cs.ret(0x400004)

        assert cs.current_function_address == 0x300000
        assert cs.current_stack_pointer == 0xFFFFFFF0

        # We return one more time to see what happens
        # Ideally nothing should be popped out
        cs = cs.ret(0x200000)

        assert cs.current_function_address == 0x300000
        assert cs.current_stack_pointer == 0xFFFFFFF0

        # Final return!
        cs = cs.ret(None)

        assert cs.current_function_address == 0
        assert cs.current_stack_pointer == 0


if __name__ == "__main__":
    unittest.main()
