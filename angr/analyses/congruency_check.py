import logging

import claripy

from . import Analysis

l = logging.getLogger(name=__name__)
#l.setLevel(logging.DEBUG)


class CongruencyCheck(Analysis):
    """
    This is an analysis to ensure that angr executes things identically with different execution backends (i.e., unicorn vs vex).
    """

    def __init__(self, throw=False):
        """
        Initializes a CongruencyCheck analysis.

        :param throw: whether to raise an exception if an incongruency is found.
        """
        self._throw = throw
        self.simgr = None
        self.prev_pg = None

    def set_state_options(self, left_add_options=None, left_remove_options=None, right_add_options=None, right_remove_options=None):
        """
        Checks that the specified state options result in the same states over the next `depth` states.
        """
        s_right = self.project.factory.full_init_state(
            add_options=right_add_options, remove_options=right_remove_options,
            args=[],
        )
        s_left = self.project.factory.full_init_state(
            add_options=left_add_options, remove_options=left_remove_options,
            args=[],
        )

        return self.set_states(s_left, s_right)

    def set_states(self, left_state, right_state):
        """
        Checks that the specified paths stay the same over the next `depth` states.
        """

        simgr = self.project.factory.simulation_manager(right_state)
        simgr.stash(to_stash='right')
        simgr.active.append(left_state)
        simgr.stash(to_stash='left')
        simgr.stash(to_stash='stashed_left')
        simgr.stash(to_stash='stashed_right')

        return self.set_simgr(simgr)

    def set_simgr(self, simgr):
        self.simgr = simgr
        return self

    @staticmethod
    def _sync_steps(simgr, max_steps=None):
        l.debug("Sync-stepping pathgroup...")
        l.debug(
            "... left width: %s, right width: %s",
            simgr.left[0].history.block_count if len(simgr.left) > 0 else None,
            simgr.right[0].history.block_count if len(simgr.right) > 0 else None,
        )

        if len(simgr.errored) != 0 and (len(simgr.left) == 0 or len(simgr.right) == 0):
            l.debug("... looks like a path errored")
            return simgr
        if len(simgr.left) == 0 and len(simgr.right) != 0:
            l.debug("... left is deadended; stepping right %s times", max_steps)
            npg = simgr.run(stash='right', n=max_steps)
        elif len(simgr.right) == 0 and len(simgr.left) != 0:
            l.debug("... right is deadended; stepping left %s times", max_steps)
            npg = simgr.run(stash='left', n=max_steps)
        elif len(simgr.right) == 0 and len(simgr.left) == 0:
            l.debug("... both deadended.")
            return simgr
        elif simgr.left[0].history.block_count == simgr.right[0].history.block_count:
            l.debug("... synced")
            return simgr
        elif simgr.left[0].history.block_count < simgr.right[0].history.block_count:
            l.debug("... right is ahead; stepping left %s times",
                    simgr.right[0].history.block_count - simgr.left[0].history.block_count)
            npg = simgr.run(
                stash='left',
                until=lambda lpg: lpg.left[0].history.block_count >= simgr.right[0].history.block_count,
                n=max_steps
            )
        elif simgr.right[0].history.block_count < simgr.left[0].history.block_count:
            l.debug("... left is ahead; stepping right %s times",
                    simgr.left[0].history.block_count - simgr.right[0].history.block_count)
            npg = simgr.run(
                stash='right',
                until=lambda lpg: lpg.right[0].history.block_count >= simgr.left[0].history.block_count,
                n=max_steps
            )

        return CongruencyCheck._sync_steps(npg)

    def _validate_incongruency(self):
        """
        Checks that a detected incongruency is not caused by translation backends having a different
        idea of what constitutes a basic block.
        """

        ot = self._throw

        try:
            self._throw = False
            l.debug("Validating incongruency.")

            if ("UNICORN" in self.simgr.right[0].options) ^ ("UNICORN" in self.simgr.left[0].options):
                if "UNICORN" in self.simgr.right[0].options:
                    unicorn_stash = 'right'
                    normal_stash = 'left'
                else:
                    unicorn_stash = 'left'
                    normal_stash = 'right'

                unicorn_path = self.simgr.stashes[unicorn_stash][0]
                normal_path = self.simgr.stashes[normal_stash][0]

                if unicorn_path.arch.name in ("X86", "AMD64"):
                    # unicorn "falls behind" on loop and rep instructions, since
                    # it sees them as ending a basic block. Here, we will
                    # step the unicorn until it's caught up
                    npg = self.project.factory.simulation_manager(unicorn_path)
                    npg.explore(find=lambda p: p.addr == normal_path.addr, n=200)
                    if len(npg.found) == 0:
                        l.debug("Validator failed to sync paths.")
                        return True

                    new_unicorn = npg.found[0]
                    delta = new_unicorn.history.block_count - normal_path.history.block_count
                    normal_path.history.recent_block_count += delta
                    new_normal = normal_path
                elif unicorn_path.arch.name == "MIPS32":
                    # unicorn gets ahead here, because VEX falls behind for unknown reasons
                    # for example, this block:
                    #
                    # 0x1016f20:      lui     $gp, 0x17
                    # 0x1016f24:      addiu   $gp, $gp, -0x35c0
                    # 0x1016f28:      addu    $gp, $gp, $t9
                    # 0x1016f2c:      addiu   $sp, $sp, -0x28
                    # 0x1016f30:      sw      $ra, 0x24($sp)
                    # 0x1016f34:      sw      $s0, 0x20($sp)
                    # 0x1016f38:      sw      $gp, 0x10($sp)
                    # 0x1016f3c:      lw      $v0, -0x6cf0($gp)
                    # 0x1016f40:      move    $at, $at
                    npg = self.project.factory.simulation_manager(normal_path)
                    npg.explore(find=lambda p: p.addr == unicorn_path.addr, n=200)
                    if len(npg.found) == 0:
                        l.debug("Validator failed to sync paths.")
                        return True

                    new_normal = npg.found[0]
                    delta = new_normal.history.block_count - unicorn_path.history.block_count
                    unicorn_path.history.recent_block_count += delta
                    new_unicorn = unicorn_path
                else:
                    l.debug("Dunno!")
                    return True

                if self.compare_paths(new_unicorn, new_normal):
                    l.debug("Divergence accounted for by unicorn.")
                    self.simgr.stashes[unicorn_stash][0] = new_unicorn
                    self.simgr.stashes[normal_stash][0] = new_normal
                    return False
                else:
                    l.warning("Divergence unaccounted for by unicorn.")
                    return True
            else:
                # no idea
                l.warning("Divergence unaccounted for.")
                return True
        finally:
            self._throw = ot

    def _report_incongruency(self, *args):
        l.warning(*args)
        if self._throw:
            raise AngrIncongruencyError(*args)

    def run(self, depth=None):
        """
        Checks that the paths in the specified path group stay the same over the next
        `depth` bytes.

        The path group should have a "left" and a "right" stash, each with a single
        path.
        """
        #pg_history = [ ]
        if len(self.simgr.right) != 1 or len(self.simgr.left) != 1:
            self._report_incongruency("Single path in pg.left and pg.right required.")
            return False

        if "UNICORN" in self.simgr.one_right.options and depth is not None:
            self.simgr.one_right.unicorn.max_steps = depth

        if "UNICORN" in self.simgr.one_left.options and depth is not None:
            self.simgr.one_left.unicorn.max_steps = depth

        l.debug("Performing initial path comparison.")
        if not self.compare_paths(self.simgr.left[0], self.simgr.right[0]):
            self._report_incongruency("Initial path comparison check failed.")
            return False

        while len(self.simgr.left) > 0 and len(self.simgr.right) > 0:
            if depth is not None:
                self._update_progress(100. * float(self.simgr.one_left.history.block_count) / depth)

            if len(self.simgr.deadended) != 0:
                self._report_incongruency("Unexpected deadended paths before step.")
                return False
            if len(self.simgr.right) == 0 and len(self.simgr.left) == 0:
                l.debug("All done!")
                return True
            if len(self.simgr.right) != 1 or len(self.simgr.left) != 1:
                self._report_incongruency("Different numbers of paths in left and right stash..")
                return False

            # do a step
            l.debug(
                "Stepping right path with weighted length %d/%d",
                self.simgr.right[0].history.block_count,
                depth
            )
            self.prev_pg = self.simgr.copy() #pylint:disable=unused-variable
            self.simgr.step(stash='right')
            CongruencyCheck._sync_steps(self.simgr)

            if len(self.simgr.errored) != 0:
                self._report_incongruency("Unexpected errored paths.")
                return False

            try:
                if not self.compare_path_group(self.simgr) and self._validate_incongruency():
                    self._report_incongruency("Path group comparison failed.")
                    return False
            except AngrIncongruencyError:
                if self._validate_incongruency():
                    raise

            if depth is not None:
                self.simgr.drop(stash='left', filter_func=lambda p: p.history.block_count >= depth)
                self.simgr.drop(stash='right', filter_func=lambda p: p.history.block_count >= depth)

            self.simgr.right.sort(key=lambda p: p.addr)
            self.simgr.left.sort(key=lambda p: p.addr)
            self.simgr.stashed_right[:] = self.simgr.stashed_right[::-1]
            self.simgr.stashed_left[:] = self.simgr.stashed_left[::-1]
            self.simgr.move('stashed_right', 'right')
            self.simgr.move('stashed_left', 'left')

            if len(self.simgr.left) > 1:
                self.simgr.split(from_stash='left', limit=1, to_stash='stashed_left')
                self.simgr.split(from_stash='right', limit=1, to_stash='stashed_right')

    def compare_path_group(self, pg):
        if len(pg.left) != len(pg.right):
            self._report_incongruency("Number of left and right paths differ.")
            return False
        if len(pg.deadended) % 2 != 0:
            self._report_incongruency("Odd number of deadended paths after step.")
            return False
        pg.drop(stash='deadended')

        if len(pg.left) == 0 and len(pg.right) == 0:
            return True

        # make sure the paths are the same
        for pl,pr in zip(sorted(pg.left, key=lambda p: p.addr), sorted(pg.right, key=lambda p: p.addr)):
            if not self.compare_paths(pl, pr):
                self._report_incongruency("Differing paths.")
                return False

        return True

    def compare_states(self, sl, sr):
        """
        Compares two states for similarity.
        """
        joint_solver = claripy.Solver()

        # make sure the canonicalized constraints are the same
        n_map, n_counter, n_canon_constraint = claripy.And(*sr.solver.constraints).canonicalize() #pylint:disable=no-member
        u_map, u_counter, u_canon_constraint = claripy.And(*sl.solver.constraints).canonicalize() #pylint:disable=no-member
        if n_canon_constraint is not u_canon_constraint:
            # https://github.com/Z3Prover/z3/issues/2359
            # don't try to simplify unless we really need to, as it can introduce serious nondeterminism
            n_canoner_constraint = sr.solver.simplify(n_canon_constraint)
            u_canoner_constraint = sl.solver.simplify(u_canon_constraint)
        else:
            n_canoner_constraint = u_canoner_constraint = n_canon_constraint
        joint_solver.add((n_canoner_constraint, u_canoner_constraint))
        if n_canoner_constraint is not u_canoner_constraint:
            # extra check: are these two constraints equivalent?
            tmp_solver = claripy.Solver()
            a = tmp_solver.satisfiable(extra_constraints=(n_canoner_constraint == u_canoner_constraint,))
            b = tmp_solver.satisfiable(extra_constraints=(n_canoner_constraint != u_canoner_constraint,))

            if not (a is True and b is False):
                self._report_incongruency("Different constraints!")
                return False

        # get the differences in registers and memory
        mem_diff = sr.memory.changed_bytes(sl.memory)
        reg_diff = sr.registers.changed_bytes(sl.registers)

        # this is only for unicorn
        if "UNICORN" in sl.options or "UNICORN" in sr.options:
            if sl.arch.name == "X86":
                reg_diff -= set(range(40, 52)) #ignore cc psuedoregisters
                reg_diff -= set(range(320, 324)) #some other VEX weirdness
                reg_diff -= set(range(340, 344)) #ip_at_syscall
            elif sl.arch.name == "AMD64":
                reg_diff -= set(range(144, 168)) #ignore cc psuedoregisters

        # make sure the differences in registers and memory are actually just renamed
        # versions of the same ASTs
        for diffs,(um,nm) in (
            (reg_diff, (sl.registers, sr.registers)),
            (mem_diff, (sl.memory, sr.memory)),
        ):
            for i in diffs:
                bn = nm.load(i, 1)
                bu = um.load(i, 1)

                bnc = bn.canonicalize(var_map=n_map, counter=n_counter)[-1]
                buc = bu.canonicalize(var_map=u_map, counter=u_counter)[-1]

                if bnc is not buc:
                    self._report_incongruency("Different memory or registers (index %d, values %r and %r)!", i, bn, bu)
                    return False

        # make sure the flags are the same
        if sl.arch.name in ("AMD64", "X86", "ARM", "ARMEL", "ARMHF", "AARCH64"):
            # pylint: disable=unused-variable
            n_bkp = sr.regs.cc_op, sr.regs.cc_dep1, sr.regs.cc_dep2, sr.regs.cc_ndep
            u_bkp = sl.regs.cc_op, sl.regs.cc_dep1, sl.regs.cc_dep2, sl.regs.cc_ndep
            if sl.arch.name in ('AMD64', 'X86'):
                n_flags = sr.regs.eflags.canonicalize(var_map=n_map, counter=n_counter)[-1]
                u_flags = sl.regs.eflags.canonicalize(var_map=u_map, counter=u_counter)[-1]
            else:
                n_flags = sr.regs.flags.canonicalize(var_map=n_map, counter=n_counter)[-1]
                u_flags = sl.regs.flags.canonicalize(var_map=u_map, counter=u_counter)[-1]
            if n_flags is not u_flags and sl.solver.simplify(n_flags) is not sr.solver.simplify(u_flags):
                self._report_incongruency("Different flags!")
                return False

        return True

    def compare_paths(self, pl, pr):
        l.debug("Comparing paths...")
        if not self.compare_states(pl, pr):
            self._report_incongruency("Failed state similarity check!")
            return False

        if pr.history.block_count != pl.history.block_count:
            self._report_incongruency("Different weights!")
            return False

        if pl.addr != pr.addr:
            self._report_incongruency("Different addresses!")
            return False

        return True

from ..errors import AngrIncongruencyError
from angr.analyses import AnalysesHub
AnalysesHub.register_default('CongruencyCheck', CongruencyCheck)
