import angr
from IPython import embed

import logging
l = logging.getLogger("angr.tests.unicorn")
l.setLevel('DEBUG')
logging.getLogger('simuvex.plugins.unicorn').setLevel('DEBUG')
logging.getLogger('simuvex.s_unicorn').setLevel('INFO')
# logging.getLogger('angr.factory').setLevel('DEBUG')

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private/'))


from simuvex import s_options as so



REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'd']

def dump_reg(s):
    # for k in dir(s.regs):
    for k in REGS:
        l.info('$%s = %r', k, getattr(s.regs, k))

def test_unicorn():
    p = angr.Project(os.path.join(test_location, './cgc_qualifier_event/cgc/99c22c01_01'))

    s_unicorn = p.factory.entry_state(add_options={so.UNICORN, so.UNICORN_FAST}) # unicorn
    s_angr = p.factory.entry_state() # pure angr
    # s_unicorn.options.add(so.UNICORN_DISABLE_NATIVE)

    # make sure all the registers are concrete
    for k in dir(s_unicorn.regs):
        r = getattr(s_unicorn.regs, k)
        if r.symbolic:
            setattr(s_unicorn.regs, k, 0)
    dump_reg(s_unicorn)

    pg_unicorn = p.factory.path_group(s_unicorn)
    pg_angr = p.factory.path_group(s_angr)

    # input = 'x\n\0\0\0\0'
    inp = 'L\x0alaehdamfeg\x0a10\x2f28\x2f2014\x0a-2147483647:-2147483647:-2147483647\x0ajfifloiblk\x0a126\x0a63\x0a47\x0a31\x0a3141\x0a719\x0a'

    stdin = s_unicorn.posix.get_file(0)
    stdin.write(inp, len(inp))
    stdin.seek(0)

    stdin = s_angr.posix.get_file(0)
    stdin.write(inp, len(inp))
    stdin.seek(0)

    #pg_unicorn.active[0].state.options.remove(so.UNICORN_FAST)

    # run explore
    # pg_unicorn.explore()
    # pg_angr.explore()

    embed()

def test_counter():
    p = angr.Project(os.path.join(test_location, '../binaries/tests/i386/counter'))
    s_unicorn = p.factory.full_init_state(add_options={so.UNICORN, so.UNICORN_FAST}) # unicorn
    pg_unicorn = p.factory.path_group(s_unicorn)

    dump_reg(s_unicorn)
    for k in dir(s_unicorn.regs):
        r = getattr(s_unicorn.regs, k)
        if r.symbolic:
            setattr(s_unicorn.regs, k, 0)

    pg_unicorn.explore()
    print pg_unicorn.errored[0]
    print pg_unicorn.errored[0].retry()

if __name__ == '__main__':
    test_counter()
    #test_unicorn()
