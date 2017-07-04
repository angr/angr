
import logging

import nose

from angr.state_plugins.callstack import CallStack

l = logging.getLogger('angr.tests.test_callstack')

def test_empty_stack():
    cs = CallStack()

    # Initial setting: just assume the control flow starts from 0x300000
    cs = cs.call(None, 0x300000, None, 0xfffffff0)

    # Calling 0x401000 from 0x400000. When it returns, it should return to 0x400004.
    # The stack pointer after entering the new function should be 0xffffff00
    # Note: this means on platforms like x86 and AMD64 where CALL instruction actually pushes the ret address on to
    # the stack and modifies the stack pointer, the user should adjust stack pointer accordingly (minus 4 or 8, for
    # example) before passing to CallStack.call(). CallStack has no way to know what the architecture it is used on.
    cs = cs.call(0x400000, 0x401000, 0x400004, 0xffffff00)

    cs = cs.call(0x401008, 0x402000, 0x40100c, 0xfffffe80)

    nose.tools.assert_equal(cs.current_function_address, 0x402000)
    nose.tools.assert_equal(cs.current_stack_pointer, 0xfffffe80)

    # Return to 0x40100c
    cs = cs.ret(0x40100c)

    nose.tools.assert_equal(cs.current_function_address, 0x401000)
    nose.tools.assert_equal(cs.current_stack_pointer, 0xffffff00)

    cs = cs.ret(0x400004)

    nose.tools.assert_equal(cs.current_function_address, 0x300000)
    nose.tools.assert_equal(cs.current_stack_pointer, 0xfffffff0)

    # We return one more time to see what happens
    # Ideally nothing should be popped out
    cs = cs.ret(0x200000)

    nose.tools.assert_equal(cs.current_function_address, 0x300000)
    nose.tools.assert_equal(cs.current_stack_pointer, 0xfffffff0)

    # Final return!
    cs = cs.ret(None)

    nose.tools.assert_equal(cs.current_function_address, 0)
    nose.tools.assert_equal(cs.current_stack_pointer, 0)

if __name__ == "__main__":
    test_empty_stack()
