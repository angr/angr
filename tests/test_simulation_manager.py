import os
import logging
import unittest

import angr

l = logging.getLogger("angr_tests.managers")

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

addresses_fauxware = {
    "armel": 0x8524,
    "armhf": 0x104C9,  # addr+1 to force thumb
    #'i386': 0x8048524, # commenting out because of the freaking stack check
    "mips": 0x400710,
    "mipsel": 0x4006D0,
    "ppc": 0x1000054C,
    "ppc64": 0x10000698,
    "x86_64": 0x400664,
}


class TestSimulationManager(unittest.TestCase):
    def _run_fauxware(self, arch, threads):
        p = angr.Project(os.path.join(location, arch, "fauxware"), load_options={"auto_load_libs": False})

        pg = p.factory.simulation_manager(threads=threads)
        assert len(pg.active) == 1
        assert pg.active[0].history.depth == 0

        # step until the backdoor split occurs
        pg2 = pg.step(until=lambda lpg: len(lpg.active) > 1, step_func=lambda lpg: lpg.prune())
        assert len(pg2.active) == 2
        assert any(b"SOSNEAKY" in s for s in pg2.mp_active.posix.dumps(0).mp_items)
        assert not all(b"SOSNEAKY" in s for s in pg2.mp_active.posix.dumps(0).mp_items)

        # separate out the backdoor and normal paths
        pg3 = pg2.stash(lambda path: b"SOSNEAKY" in path.posix.dumps(0), to_stash="backdoor").move("active", "auth")
        assert len(pg3.active) == 0
        assert len(pg3.backdoor) == 1
        assert len(pg3.auth) == 1

        # step the backdoor path until it returns to main
        pg4 = pg3.step(until=lambda lpg: lpg.backdoor[0].history.jumpkinds[-1] == "Ijk_Ret", stash="backdoor")
        main_addr = pg4.backdoor[0].addr

        assert len(pg4.active) == 0
        assert len(pg4.backdoor) == 1
        assert len(pg4.auth) == 1

        # now step the real path until the real authentication paths return to the same place
        pg5 = pg4.explore(find=main_addr, num_find=2, stash="auth").move("found", "auth")

        assert len(pg5.active) == 0
        assert len(pg5.backdoor) == 1
        assert len(pg5.auth) == 2

        # now unstash everything
        pg6 = pg5.unstash(from_stash="backdoor").unstash(from_stash="auth")
        assert len(pg6.active) == 3
        assert len(pg6.backdoor) == 0
        assert len(pg6.auth) == 0

        assert len(set(pg6.mp_active.addr.mp_items)) == 1

        # now merge them!
        pg7 = pg6.merge()
        assert len(pg7.active) == 2
        assert len(pg7.backdoor) == 0
        assert len(pg7.auth) == 0

        # test selecting paths to step
        pg8 = p.factory.simulation_manager()
        pg8.step(until=lambda lpg: len(lpg.active) > 1, step_func=lambda lpg: lpg.prune().drop(stash="pruned"))
        st1, st2 = pg8.active
        pg8.step(selector_func=lambda p: p is st1, step_func=lambda lpg: lpg.prune().drop(stash="pruned"))
        assert st2 is pg8.active[1]
        assert st1 is not pg8.active[0]

        total_active = len(pg8.active)

        # test special stashes
        assert len(pg8.stashes["stashed"]) == 0
        pg8.stash(filter_func=lambda p: p is pg8.active[1], to_stash="asdf")
        assert len(pg8.stashes["stashed"]) == 0
        assert len(pg8.asdf) == 1
        assert len(pg8.active) == total_active - 1
        pg8.stash(from_stash=pg8.ALL, to_stash="fdsa")
        assert len(pg8.asdf) == 0
        assert len(pg8.active) == 0
        assert len(pg8.fdsa) == total_active
        pg8.stash(from_stash=pg8.ALL, to_stash=pg8.DROP)
        assert all(len(s) == 0 for s in pg8.stashes.values())

    def test_fauxware_armel(self):
        self._run_fauxware("armel", None)

    def test_fauxware_armhf(self):
        self._run_fauxware("armhf", None)

    def test_fauxware_mips(self):
        self._run_fauxware("mips", None)

    def test_fauxware_mipsel(self):
        self._run_fauxware("mipsel", None)

    def test_fauxware_ppc(self):
        self._run_fauxware("ppc", None)

    def test_fauxware_ppc64(self):
        self._run_fauxware("ppc64", None)

    def test_fauxware_x86_64(self):
        self._run_fauxware("x86_64", None)

    def test_find_to_middle(self):
        # Test the ability of PathGroup to execute until an instruction in the middle of a basic block
        p = angr.Project(os.path.join(location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

        pg = p.factory.simulation_manager()
        pg.explore(find=(0x4006EE,))

        assert len(pg.found) == 1
        assert pg.found[0].addr == 0x4006EE

    def test_explore_with_cfg(self):
        p = angr.Project(os.path.join(location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

        cfg = p.analyses.CFGEmulated()

        pg = p.factory.simulation_manager()
        pg.use_technique(angr.exploration_techniques.Explorer(find=0x4006ED, cfg=cfg, num_find=3))
        pg.run()

        assert len(pg.active) == 0
        assert len(pg.avoid) == 1
        assert len(pg.found) == 2
        assert pg.found[0].addr == 0x4006ED
        assert pg.found[1].addr == 0x4006ED
        assert pg.avoid[0].addr == 0x4007C9


if __name__ == "__main__":
    unittest.main()
