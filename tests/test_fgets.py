import nose
import logging

import angr

TARGET_APP = "../../binaries/tests/x86_64/fgets"

l = logging.getLogger('angr.tests.libc.fgets')

p = angr.Project("{}".format(TARGET_APP))

find_normal = p.loader.find_symbol('find_normal').rebased_addr
find_exact = p.loader.find_symbol('find_exact').rebased_addr
find_eof = p.loader.find_symbol('find_eof').rebased_addr
find_impossible = p.loader.find_symbol('find_impossible').rebased_addr

def _testfind(addr, failmsg):
    e = p.factory.entry_state()
    e.options.add(angr.sim_options.SHORT_READS)
    e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    s = p.factory.simgr(e)
    r = s.explore(find=addr)
    nose.tools.ok_(len(r.found) > 0, failmsg)
    with open("./out.txt", "a") as outfile:
        print(r.found[0].posix.dumps(0), file=outfile)
    return r.found[0].posix.dumps(0)

def _testnotfind(addr, failmsg):
    e = p.factory.entry_state()
    e.options.add(angr.sim_options.SHORT_READS)
    e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    s = p.factory.simgr(e)
    r= s.explore(find=addr)
    nose.tools.ok_(len(r.found) == 0, failmsg)

def test_normal():
    answer = _testfind(find_normal, "Normal Failure!")
    nose.tools.ok_(answer == b'normal\n')

def test_exact():
    _testfind(find_exact, "Exact Failure!")

def test_eof():
    _testfind(find_eof, "EOF Failure!")

def test_impossible():
    _testnotfind(find_impossible, "Impossible Failure!")
