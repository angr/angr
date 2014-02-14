from collections import defaultdict
from simuvex.s_ref import RefTypes, SimMemRead, SimMemWrite
from simuvex import SimIRSB, SimProcedure
import logging

l = logging.getLogger("angr.ddg")

class DDG(object):
	def __init__(self, cfg, entry_point):
		self._cfg = cfg
		self._entry_point = entry_point

		self._ddg = defaultdict(dict)

	def debug_print(self):
		print self._ddg

	def construct(self):
		run_stack = [ ]
		# Added the first container into the stack
		initial_container = AddrToRefContainer(self._cfg.get_irsb((None, None, self._entry_point)), { })
		run_stack.append(initial_container)
		analyzed_runs = set()
		while len(run_stack) > 0:
			container = run_stack.pop()
			run = container.run
			if run in analyzed_runs:
				continue
			analyzed_runs.add(run)
			if isinstance(run, SimIRSB):
				irsb = run
				l.debug("Running %s", irsb)
				# Simulate the execution of this irsb.
				# For MemWriteRef, fill the addr_to_ref dict with every single concretizable
				# memory address, and ignore those symbolic ones
				# For MemReadRef, get its related MemoryWriteRef from our dict
				# TODO: Is it possible to trace memory operations even if the memory is not
				# concretizable itself?
				statements = irsb.statements
				for i in range(len(statements)):
					stmt = statements[i]
					refs = stmt.refs
					if len(refs) > 0:
						real_ref = refs[len(refs) - 1]
						if type(real_ref) == SimMemWrite:
							addr = real_ref.addr
							if not addr.is_symbolic():
								concrete_addr = addr.any()
								container.addr_to_ref[concrete_addr] = (irsb, i)
							else:
								# We ignore them for now
								pass
					for ref in refs:
						if type(ref) == SimMemRead:
							addr = ref.addr
							if not addr.is_symbolic():
								concrete_addr = addr.any()
								if concrete_addr in container.addr_to_ref:
									self._ddg[irsb][i] = container.addr_to_ref[concrete_addr]
								else:
									# raise Exception("wtf...")
									pass
			elif isinstance(run, SimProcedure):
				sim_proc = run
				l.debug("Running %s", sim_proc)
				refs = sim_proc.refs()
				for ref in refs[SimMemRead]:
					addr = ref.addr
					if not addr.is_symbolic():
						concrete_addr = addr.any()
						if concrete_addr in container.addr_to_ref:
							self._ddg[sim_proc][-1] = container.addr_to_ref[concrete_addr]
				for ref in refs[SimMemWrite]:
					addr = ref.addr
					if not addr.is_symbolic():
						concrete_addr = addr.any()
						container.addr_to_ref[concrete_addr] = (sim_proc, -1)

			# Get successors of the current irsb,
			successors = self._cfg.get_successors(run)
			# ... and add them to our stack with a shallow copy of the addr_to_ref dict
			for successor in successors:
				new_container = AddrToRefContainer(successor, container.addr_to_ref.copy())
				run_stack.append(new_container)

class AddrToRefContainer(object):
	def __init__(self, run, addr_to_ref):
		self.run = run
		self.addr_to_ref = addr_to_ref
