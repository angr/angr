# pylint:disable=no-self-use,missing-class-docstring
import os
from unittest import TestCase, main

import claripy
import angr
from angr import options as o


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestSelfModifyingCOde(TestCase):
    def test_self_modifying_code(self):
        p = angr.Project(os.path.join(test_location, "cgc", "stuff"), auto_load_libs=False, selfmodifying_code=True)
        pg = p.factory.simulation_manager(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS}))

        # small issue: the program is bugged and uses illegal stack allocation patterns, bypassing the red page
        # hack around this here
        for offs in range(0, 0x6000, 0x1000):
            pg.one_active.memory.load(pg.one_active.regs.sp - offs, size=1)

        pg.run(until=lambda lpg: len(lpg.active) != 1)
        retval = pg.one_deadended.regs.ebx
        assert claripy.is_true(retval == 65)

        pgu = p.factory.simulation_manager(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS} | o.unicorn))
        for offs in range(0, 0x6000, 0x1000):
            pgu.one_active.memory.load(pgu.one_active.regs.sp - offs, size=1)
        pgu.run(until=lambda lpg: len(lpg.active) != 1)
        retval = pgu.one_deadended.regs.ebx
        assert claripy.is_true(retval == 65)

        # the two histories are not the same because angr does not add relifted block addresses (caused by raising
        # SimReliftExceptions during execution) to the history. whether this is a good design decision or not is a
        # question for another day. for now, we resort to a weaker check.
        #
        # assert pg.one_deadended.history.bbl_addrs.hardcopy == pgu.one_deadended.history.bbl_addrs.hardcopy
        i, j = 0, 0
        pg_bbl_addrs = pg.one_deadended.history.bbl_addrs.hardcopy
        u_bbl_addrs = pgu.one_deadended.history.bbl_addrs.hardcopy
        while i < len(pg_bbl_addrs) and j < len(u_bbl_addrs):
            if pg_bbl_addrs[i] == u_bbl_addrs[j]:
                i += 1
                j += 1
            elif pg_bbl_addrs[i] != u_bbl_addrs[j] and pg_bbl_addrs[i - 1] < u_bbl_addrs[j] < pg_bbl_addrs[i]:
                # this is the missing relifted block address in angr's history. skip it
                j += 1
            else:
                raise Exception("History mismatch")
        assert i == len(pg_bbl_addrs)
        assert j == len(u_bbl_addrs)

        # also ensure that block.pp() does not raise any exceptions
        p.factory.block(0xBAAA7B42, backup_state=pg.one_deadended).pp()


if __name__ == "__main__":
    main()
