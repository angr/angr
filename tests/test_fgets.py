import logging
import os

import angr

TARGET_APP = os.path.join(os.path.dirname(os.path.realpath(str(__file__))),
    "../../binaries/tests/x86_64/fgets")

l = logging.getLogger('angr.tests.libc.fgets')

p = angr.Project("{}".format(TARGET_APP), auto_load_libs=False)

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
    assert len(r.found) > 0, failmsg
    return r.found[0].posix.dumps(0)

def _testnotfind(addr, failmsg):
    e = p.factory.entry_state()
    e.options.add(angr.sim_options.SHORT_READS)
    e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    s = p.factory.simgr(e)
    r= s.explore(find=addr)
    assert len(r.found) == 0, failmsg


def test_normal():
    answer = _testfind(find_normal, "Normal Failure!")
    assert answer == b'normal\n'

def test_exact():
    answer = _testfind(find_exact, "Exact Failure!")
    assert answer.endswith(b'0123456789')

def test_impossible():
    _testnotfind(find_impossible, "Impossible Failure!")
