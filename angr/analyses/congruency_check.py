import logging

import claripy
import simuvex
from ..analysis import Analysis, register_analysis

l = logging.getLogger('angr.analyses.congruency_check')
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
		self.pg = None
		self.prev_pg = None

	def set_state_options(self, left_add_options=None, left_remove_options=None, right_add_options=None, right_remove_options=None):
		"""
		Checks that the specified state options result in the same states over the next `depth` states.
		"""
		s_right = self.project.factory.full_init_state(
			add_options=right_add_options, remove_options=right_remove_options
		)
		s_left = self.project.factory.full_init_state(
			add_options=left_add_options, remove_options=left_remove_options
		)

		return self.set_states(s_left, s_right)

	def set_states(self, left_state, right_state):
		"""
		Checks that the specified states stay the same over the next `depth` states.
		"""
		p_right = self.project.factory.path(right_state)
		p_left = self.project.factory.path(left_state)

		return self.set_paths(p_left, p_right)

	def set_paths(self, left_path, right_path):
		"""
		Checks that the specified paths stay the same over the next `depth` states.
		"""
		pg = self.project.factory.path_group(right_path)
		pg.stash(to_stash='right')
		pg.active.append(left_path)
		pg.stash(to_stash='left')
		pg.stash(to_stash='stashed_left')
		pg.stash(to_stash='stashed_right')

		return self.set_path_group(pg)

	def set_path_group(self, pg):
		self.pg = pg
		return self

	@staticmethod
	def _sync_steps(pg, max_steps=None):
		l.debug("Sync-stepping pathgroup...")
		l.debug(
			"... left width: %s, right width: %s",
			pg.left[0].weighted_length if len(pg.left) > 0 else None,
			pg.right[0].weighted_length if len(pg.right) > 0 else None,
		)

		if len(pg.errored) != 0 and (len(pg.left) == 0 or len(pg.right) == 0):
			l.debug("... looks like a path errored")
			return pg
		if len(pg.left) == 0 and len(pg.right) != 0:
			l.debug("... left is deadended; stepping right %s times", max_steps)
			npg = pg.step(stash='right', n=max_steps)
		elif len(pg.right) == 0 and len(pg.left) != 0:
			l.debug("... right is deadended; stepping left %s times", max_steps)
			npg = pg.step(stash='left', n=max_steps)
		elif len(pg.right) == 0 and len(pg.left) == 0:
			l.debug("... both deadended.")
			return pg
		elif pg.left[0].weighted_length == pg.right[0].weighted_length:
			l.debug("... synced")
			return pg
		elif pg.left[0].weighted_length < pg.right[0].weighted_length:
			l.debug("... right is ahead; stepping left up to %s times", max_steps)
			npg = pg.step(
				stash='left',
				until=lambda lpg: lpg.left[0].weighted_length >= pg.right[0].weighted_length,
				n=max_steps
			)
		elif pg.right[0].weighted_length < pg.left[0].weighted_length:
			l.debug("... left is ahead; stepping right up to %s times", max_steps)
			npg = pg.step(
				stash='right',
				until=lambda lpg: lpg.right[0].weighted_length >= pg.left[0].weighted_length,
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

			if ("UNICORN" in self.pg.right[0].state.options) ^ ("UNICORN" in self.pg.left[0].state.options):
				if "UNICORN" in self.pg.right[0].state.options:
					unicorn_stash = 'right'
					normal_stash = 'left'
				else:
					unicorn_stash = 'left'
					normal_stash = 'right'

				unicorn_path = self.pg.stashes[unicorn_stash][0]
				normal_path = self.pg.stashes[normal_stash][0]

				if unicorn_path.state.arch.name in ("X86", "AMD64"):
					# unicorn "falls behind" on loop and rep instructions, since
					# it sees them as ending a basic block. Here, we will
					# step the unicorn until it's caught up
					npg = self.project.factory.path_group(unicorn_path)
					npg.explore(find=lambda p: p.addr == normal_path.addr, n=200)
					if len(npg.found) == 0:
						l.debug("Validator failed to sync paths.")
						return True

					new_unicorn = npg.found[0]
					delta = new_unicorn.weighted_length - normal_path.weighted_length
					normal_path.extra_length += delta
					new_normal = normal_path
				elif unicorn_path.state.arch.name == "MIPS32":
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
					npg = self.project.factory.path_group(normal_path)
					npg.explore(find=lambda p: p.addr == unicorn_path.addr, n=200)
					if len(npg.found) == 0:
						l.debug("Validator failed to sync paths.")
						return True

					new_normal = npg.found[0]
					delta = new_normal.weighted_length - unicorn_path.weighted_length
					unicorn_path.extra_length += delta
					new_unicorn = unicorn_path
				else:
					l.debug("Dunno!")
					return True

				if self.compare_paths(new_unicorn, new_normal):
					l.debug("Divergence accounted for by unicorn.")
					self.pg.stashes[unicorn_stash][0] = new_unicorn
					self.pg.stashes[normal_stash][0] = new_normal
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
		if len(self.pg.right) != 1 or len(self.pg.left) != 1:
			self._report_incongruency("Single path in pg.left and pg.right required.")
			return False

		if "UNICORN" in self.pg.one_right.state.options and depth is not None:
			self.pg.one_right.state.unicorn.max_steps = depth

		if "UNICORN" in self.pg.one_left.state.options and depth is not None:
			self.pg.one_left.state.unicorn.max_steps = depth

		l.debug("Performing initial path comparison.")
		if not self.compare_paths(self.pg.left[0], self.pg.right[0]):
			self._report_incongruency("Initial path comparison check failed.")
			return False

		while len(self.pg.left) > 0 and len(self.pg.right) > 0:
			if depth is not None:
				self._update_progress(100. * float(self.pg.one_left.weighted_length) / depth)

			if len(self.pg.deadended) != 0:
				self._report_incongruency("Unexpected deadended paths before step.")
				return False
			if len(self.pg.right) == 0 and len(self.pg.left) == 0:
				l.debug("All done!")
				return True
			if len(self.pg.right) != 1 or len(self.pg.left) != 1:
				self._report_incongruency("Different numbers of paths in left and right stash..")
				return False

			# do a step
			l.debug(
				"Stepping right path with weighted length %d/%s",
				self.pg.right[0].weighted_length,
				depth
			)
			self.prev_pg = self.pg.copy() #pylint:disable=unused-variable
			self.pg.step(stash='right')
			CongruencyCheck._sync_steps(self.pg)

			if len(self.pg.errored) != 0:
				self._report_incongruency("Unexpected errored paths.")
				return False

			try:
				if not self.compare_path_group(self.pg) and self._validate_incongruency():
					self._report_incongruency("Path group comparison failed.")
					return False
			except AngrIncongruencyError:
				if self._validate_incongruency():
					raise

			if depth is not None:
				self.pg.drop(stash='left', filter_func=lambda p: p.weighted_length >= depth)
				self.pg.drop(stash='right', filter_func=lambda p: p.weighted_length >= depth)

			self.pg.right.sort(key=lambda p: p.addr)
			self.pg.left.sort(key=lambda p: p.addr)
			self.pg.stashed_right[:] = self.pg.stashed_right[::-1]
			self.pg.stashed_left[:] = self.pg.stashed_left[::-1]
			self.pg.move('stashed_right', 'right')
			self.pg.move('stashed_left', 'left')

			if len(self.pg.left) > 1:
				self.pg.split(from_stash='left', limit=1, to_stash='stashed_left')
				self.pg.split(from_stash='right', limit=1, to_stash='stashed_right')

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
		n_map, n_counter, n_canon_constraint = claripy.And(*sr.se.constraints).canonicalize() #pylint:disable=no-member
		u_map, u_counter, u_canon_constraint = claripy.And(*sl.se.constraints).canonicalize() #pylint:disable=no-member
		n_canoner_constraint = sr.se.simplify(n_canon_constraint)
		u_canoner_constraint = sl.se.simplify(u_canon_constraint)
		joint_solver.add((n_canoner_constraint, u_canoner_constraint))
		if n_canoner_constraint is not u_canoner_constraint:
			self._report_incongruency("Different constraints!")
			return False

		# get the differences in registers and memory
		mem_diff = sr.memory.changed_bytes(sl.memory)
		reg_diff = sr.registers.changed_bytes(sl.registers)

		# this is only for unicorn
		if "UNICORN" in sl.options | sr.options:
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
		if sl.arch.name in ("AMD64", "X86", "ARM", "AARCH64"):
			n_flags = simuvex.vex.ccall._get_flags(sr)[0].canonicalize(var_map=n_map, counter=n_counter)[-1]
			u_flags = simuvex.vex.ccall._get_flags(sl)[0].canonicalize(var_map=u_map, counter=u_counter)[-1]
			if n_flags is not u_flags and sl.se.simplify(n_flags) is not sr.se.simplify(u_flags):
				self._report_incongruency("Different flags!")
				return False

		return True

	def compare_paths(self, pl, pr):
		l.debug("Comparing paths...")
		if not self.compare_states(pl.state, pr.state):
			self._report_incongruency("Failed state similarity check!")
			return False

		if pr.weighted_length != pl.weighted_length:
			self._report_incongruency("Different weights!")
			return False

		if pl.addr != pr.addr:
			self._report_incongruency("Different addresses!")
			return False

		return True

from ..errors import AngrIncongruencyError
register_analysis(CongruencyCheck, 'CongruencyCheck')
