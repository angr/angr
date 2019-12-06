import nose
import os
import sys
import angr
import subprocess

import logging
l = logging.getLogger('angr.tests.test_ctype_locale')

test_location = os.path.dirname(os.path.abspath(__file__))

def test_ctype_b_loc():
    '''
    test_ctype_locale.test_ctype_b_loc

    const unsigned short * * __ctype_b_loc (void);

    Description

    The __ctype_b_loc() function shall return a pointer into an array of
    characters in the current locale that contains characteristics for each
    character in the current character set. The array shall contain a total
    of 384 characters, and can be indexed with any signed or unsigned char
    (i.e. with an index value between -128 and 255). If the application is
    multithreaded, the array shall be local to the current thread.

    This interface is not in the source standard; it is only in the binary
    standard.
    '''
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    # Just load a binary so that we can do the initialization steps from
    # libc_start_main
    bin_path = os.path.join(test_location, '..', '..', 'binaries', 'tests', 'x86_64', 'ctype_b_loc')

    ctype_b_loc = lambda state, arguments: angr.SIM_PROCEDURES['glibc']['__ctype_b_loc']().execute(state, arguments=arguments)

    b = angr.Project(bin_path)
    p = b.factory.full_init_state()
    pg = b.factory.simulation_manager(p)

    # Find main located at 0x400596 to let libc_start_main do its thing
    main = pg.explore(find=0x400596)

    state = main.found[0]
    b_loc_array_ptr = ctype_b_loc(state, []).ret_expr
    table_ptr = state.memory.load(b_loc_array_ptr, state.arch.bytes, endness=state.arch.memory_endness)

    result = b''
    for i in range(-128, 256):
        result += b"%d->0x%x\n" % (i, state.mem[table_ptr + i*2].short.unsigned.concrete)

    # Check output of compiled C program that uses ctype_b_loc()
    output = subprocess.check_output(bin_path, shell=True)
    nose.tools.assert_equal(result, output)


def test_ctype_tolower_loc():
    '''
    test_ctype_locale.test_ctype_tolower_loc

    int32_t * * __ctype_tolower_loc(void);

    Description:
    The __ctype_tolower_loc() function shall return a pointer into an array of
    characters in the current locale that contains lower case equivalents for
    each character in the current character set. The array shall contain a total
    of 384 characters, and can be indexed with any signed or unsigned char (i.e.
    with an index value between -128 and 255). If the application is
    multithreaded, the array shall be local to the current thread.

    This interface is not in the source standard; it is only in the binary
    standard.

    Return Value:
    The __ctype_tolower_loc() function shall return a pointer to the array of
    characters to be used for the ctype() family of functions (see <ctype.h>).
    '''
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    # Just load a binary so that we can do the initialization steps from
    # libc_start_main
    bin_path = os.path.join(test_location, '..', '..', 'binaries', 'tests', 'x86_64', 'ctype_tolower_loc')

    ctype_tolower_loc = lambda state, arguments: angr.SIM_PROCEDURES['glibc']['__ctype_tolower_loc']().execute(state, arguments=arguments)

    b = angr.Project(bin_path)
    p = b.factory.full_init_state()
    pg = b.factory.simulation_manager(p)

    # Find main located at 0x400596 to let libc_start_main do its thing
    main = pg.explore(find=0x400596)

    state = main.found[0]
    tolower_loc_array_ptr = ctype_tolower_loc(state, []).ret_expr
    table_ptr = state.memory.load(tolower_loc_array_ptr, state.arch.bytes, endness=state.arch.memory_endness)

    result = b''
    for i in range(-128, 256):
        result += b"%d->0x%x\n" % (i, state.mem[table_ptr + i*4].int.unsigned.concrete)

    # Check output of compiled C program that uses ctype_tolower_loc()
    output = subprocess.check_output(bin_path, shell=True)
    nose.tools.assert_equal(result, output)


def test_ctype_toupper_loc():
    '''
    test_ctype_locale.test_ctype_toupper_loc

    int32_t * * __ctype_toupper_loc(void);

    Description:
    The __ctype_toupper_loc() function shall return a pointer into an array of
    characters in the current locale that contains upper case equivalents for
    each character in the current character set. The array shall contain a total
    of 384 characters, and can be indexed with any signed or unsigned char (i.e.
    with an index value between -128 and 255). If the application is
    multithreaded, the array shall be local to the current thread.

    This interface is not in the source standard; it is only in the binary
    standard.

    Return Value:
    The __ctype_toupper_loc() function shall return a pointer to the array of
    characters to be used for the ctype() family of functions (see <ctype.h>).
    '''
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    # Just load a binary so that we can do the initialization steps from
    # libc_start_main
    bin_path = os.path.join(test_location, '..', '..', 'binaries', 'tests', 'x86_64', 'ctype_toupper_loc')

    ctype_toupper_loc = lambda state, arguments: angr.SIM_PROCEDURES['glibc']['__ctype_toupper_loc']().execute(state, arguments=arguments)

    b = angr.Project(bin_path)
    p = b.factory.full_init_state()
    pg = b.factory.simulation_manager(p)

    # Find main located at 0x400596 to let libc_start_main do its thing
    main = pg.explore(find=0x400596)

    state = main.found[0]
    toupper_loc_array_ptr = ctype_toupper_loc(state, []).ret_expr
    table_ptr = state.memory.load(toupper_loc_array_ptr, state.arch.bytes, endness=state.arch.memory_endness)

    result = b''
    for i in range(-128, 256):
        result += b"%d->0x%x\n" % (i, state.mem[table_ptr + i*4].int.unsigned.concrete)

    # Check output of compiled C program that uses ctype_toupper_loc()
    output = subprocess.check_output(bin_path, shell=True)
    nose.tools.assert_equal(result, output)


if __name__ == '__main__':
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
