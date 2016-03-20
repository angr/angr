import angr
import simuvex
import claripy

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

def broken_unicorn():
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
    print pg_angr, pg_unicorn

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
    #embed()

def run_longinit(arch):
    p = angr.Project(os.path.join(test_location, '../binaries/tests/' + arch + '/longinit'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.path_group(s_unicorn)
    pg.explore()
    s = pg.deadended[0].state
    first = s.posix.files[0].content.load(0, 9)
    second = s.posix.files[0].content.load(9, 9)
    s.add_constraints(first == s.se.BVV('A'*9))
    s.add_constraints(second == s.se.BVV('B'*9))
    assert s.posix.dumps(1) == "You entered AAAAAAAAA and BBBBBBBBB!\n"

def test_longinit_i386():
    run_longinit('i386')
def test_longinit_x86_64():
    run_longinit('x86_64')

def broken_fauxware():
    p = angr.Project(os.path.join(test_location, '../binaries/tests/i386/fauxware'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.path_group(s_unicorn)

    pg.explore()
    import IPython; IPython.embed()

def broken_palindrome():
    b = angr.Project(os.path.join(test_location, "cgc_scored_event_2/cgc/0b32aa01_01"))
    s_unicorn = b.factory.entry_state(add_options={so.UNICORN, so.UNICORN_FAST}, remove_options={so.LAZY_SOLVES}) # unicorn
    pg = b.factory.path_group(s_unicorn)
    angr.path_group.l.setLevel("DEBUG")
    pg.step(300)

def _compare_paths(pu, pn):
    l.debug("Comparing...")
    assert pu.addr == pn.addr
    sn = pn.state
    su = pu.state
    joint_solver = claripy.FullFrontend(claripy.backends.z3)

    # make sure the canonicalized constraints are the same
    n_map, n_counter, n_canon_constraint = claripy.And(*sn.se.constraints).canonicalize()
    u_map, u_counter, u_canon_constraint = claripy.And(*su.se.constraints).canonicalize()
    joint_solver.add((n_canon_constraint, u_canon_constraint))
    assert n_canon_constraint is u_canon_constraint

    # get the differences in registers and memory
    mem_diff = sn.memory.changed_bytes(su.memory)
    reg_diff = sn.registers.changed_bytes(su.registers) - set(range(40, 52)) #ignore cc psuedoregisters

    # make sure the differences in registers and memory are actually just renamed
    # versions of the same ASTs
    for diffs,(um,nm) in (
        (mem_diff, (su.memory, sn.memory)),
        (reg_diff, (su.registers, sn.registers))
    ):
        for i in diffs:
            bn = nm.load(i, 1)
            bu = um.load(i, 1)

            bnc = bn.canonicalize(var_map=n_map, counter=n_counter)[-1]
            buc = bu.canonicalize(var_map=u_map, counter=u_counter)[-1]

            assert bnc is buc

    # make sure the flags are the same
    #print "Native flags:", simuvex.vex.ccall._get_flags(sn)
    #print "Unicorn flags:", simuvex.vex.ccall._get_flags(su)
    n_flags = simuvex.vex.ccall._get_flags(sn)[0].canonicalize(var_map=n_map, counter=n_counter)[-1]
    u_flags = simuvex.vex.ccall._get_flags(su)[0].canonicalize(var_map=u_map, counter=u_counter)[-1]
    assert n_flags is u_flags
    l.debug("Done comparing!")

def run_similarity(binpath, depth, b=None, state=None):
    if b is None:
        b = angr.Project(os.path.join(test_location, binpath))

    if state is None:
        s_unicorn = b.factory.entry_state(add_options=so.unicorn, remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING}) # unicorn
        s_normal = b.factory.entry_state(add_options={so.INITIALIZE_ZERO_REGISTERS}, remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING}) # normal
    else:
        assert so.INITIALIZE_ZERO_REGISTERS in state.options

        s_normal = state.copy()
        s_normal.options.discard(so.LAZY_SOLVES)
        s_normal.options.discard(so.TRACK_MEMORY_MAPPING)

        s_unicorn = state.copy()
        s_unicorn.options.update(so.unicorn)
        s_unicorn.options.discard(so.LAZY_SOLVES)
        s_unicorn.options.discard(so.TRACK_MEMORY_MAPPING)

    p_unicorn = b.factory.path(s_unicorn)
    p_normal = b.factory.path(s_normal)
    pg = b.factory.path_group(p_unicorn)
    pg.stash(to_stash='unicorn')
    pg.active.append(p_normal)
    pg.stash(to_stash='normal')
    pg.stash(to_stash='stashed_normal')
    pg.stash(to_stash='stashed_unicorn')

    #pg_history = [ ]

    while pg.normal[0].length < depth:
        assert len(pg.unicorn) == 1
        assert len(pg.normal) == 1
        assert pg.unicorn[0].weighted_length == pg.normal[0].weighted_length
        assert len(pg.deadended) == 0
        assert len(pg.errored) == 0
        #_compare_paths(pg.unicorn[0], pg.normal[0])

        #pg_history.append(pg.copy())
        pg_prev = pg.copy() #pylint:disable=unused-variable
        pg.step(stash='unicorn')
        assert len(pg.errored) == 0

        if len(pg.unicorn) == 0:
            assert len(pg.deadended) == 1
            assert not isinstance(pg.deadended[0]._run, simuvex.SimUnicorn)
            pg.step(stash='normal')
            assert len(pg.normal) == 0
            assert len(pg.deadended) == 2
            pg.drop(stash='deadended')
            assert len(pg.deadended) == 0
        else:
            if isinstance(pg.unicorn[0].previous_run, simuvex.SimUnicorn):
                n = pg.unicorn[0].previous_run.state.unicorn.steps
                pg.step(stash='normal', n=n)
            else:
                pg.step(stash='normal')

            assert len(pg.errored) == 0
            pg.unicorn.sort(key=lambda p: p.addr)
            pg.normal.sort(key=lambda p: p.addr)

            #print "PG:", pg
            #print "PG paths:", pg.unicorn, pg.normal

            # make sure the path groups are in the same place
            assert len(pg.normal) == len(pg.unicorn)
            assert pg.mp_unicorn.addr.mp_items == pg.mp_normal.addr.mp_items

        # make sure the paths are the same
        pg.stashed_unicorn[:] = pg.stashed_unicorn[::-1]
        pg.stashed_normal[:] = pg.stashed_normal[::-1]
        pg.move('stashed_unicorn', 'unicorn')
        pg.move('stashed_normal', 'normal')

        for pu,pn in zip(pg.unicorn, pg.normal):
            _compare_paths(pu, pn)

        if len(pg.normal) > 1:
            pg.split(from_stash='normal', limit=1, to_stash='stashed_normal')
            pg.split(from_stash='unicorn', limit=1, to_stash='stashed_unicorn')

def test_similarity_01cf6c01(): run_similarity("cgc_qualifier_event/cgc/01cf6c01_01", 5170)
def timesout_similarity_38256a01(): run_similarity("cgc_qualifier_event/cgc/38256a01_01", 125)
def timesout_similarity_5821ad01(): run_similarity("cgc_qualifier_event/cgc/5821ad01_01", 125)
def test_similarity_5c921501(): run_similarity("cgc_qualifier_event/cgc/5c921501_01", 250)
def test_similarity_63cf1501(): run_similarity("cgc_qualifier_event/cgc/63cf1501_01", 125)
def timesout_similarity_6787bf01(): run_similarity("cgc_qualifier_event/cgc/6787bf01_01", 125)
def test_similarity_7185fe01(): run_similarity("cgc_qualifier_event/cgc/7185fe01_01", 500)
def timesout_similarity_ab957801(): run_similarity("cgc_qualifier_event/cgc/ab957801_01", 125)
def test_similarity_acedf301(): run_similarity("cgc_qualifier_event/cgc/acedf301_01", 600)
def test_similarity_d009e601(): run_similarity("cgc_qualifier_event/cgc/d009e601_01", 600)
def test_similarity_d4411101(): run_similarity("cgc_qualifier_event/cgc/d4411101_01", 500)
def test_similarity_eae6fa01(): run_similarity("cgc_qualifier_event/cgc/eae6fa01_01", 250)
def test_similarity_ee545a01(): run_similarity("cgc_qualifier_event/cgc/ee545a01_01", 1000)
def timesout_similarity_f5adc401(): run_similarity("cgc_qualifier_event/cgc/f5adc401_01", 250)

if __name__ == '__main__':
    #test_palindrome()
    #test_fauxware()
    #test_longinit()
    #test_unicorn()
    #test_similarity_01cf6c01()
    #test_similarity_7185fe01()
    import sys
    globals()['test_' + sys.argv[1]]()
