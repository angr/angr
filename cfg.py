import sys
from collections import defaultdict

import networkx

import logging
import simuvex
import angr
from .translate import translate_bytes

l = logging.getLogger(name = "sliceit.s_cfg")
l.setLevel(logging.DEBUG)

class Stack(object):
	def __init__(self, stack=None):
		if stack is None:
			self._stack = []
		else:
			self._stack = stack

	def stack_suffix(self):
		length = len(self._stack)
		if length == 0:
			return (None, None)
		elif length == 1:
			return (None, self._stack[length - 1])
		return (self._stack[length - 2], self._stack[length - 1])

	def call(self, callsite_addr, addr):
		self._stack.append(callsite_addr)
		self._stack.append(addr)

	def ret(self):
		if len(self._stack) > 0:
			self._stack.pop()
			self._stack.pop()

	def copy(self):
		return Stack(self._stack[::])

class SimExitWrapper(object):
	def __init__(self, ex, stack=None):
		self._exit = ex
		if stack == None:
			self._stack = Stack()
		else:
			self._stack = stack

	def sim_exit(self):
		return self._exit

	def stack(self):
		return self._stack

	def stack_copy(self):
		return self._stack.copy()

	def stack_suffix(self):
		return self._stack.stack_suffix()

class CFG(object):
	def __init__(self):
		self.cfg = networkx.DiGraph()
		self.bbl_dict = None

	# Construct the CFG from an angr. binary object
	def construct(self, binary, project):
		# Re-create the DiGraph
		self.cfg = networkx.DiGraph()

		# Traverse all the IRSBs, and put them to a dict
		# It's actually a multi-dict, as each SIRSB might have different states on different call predicates
		self.bbl_dict = {}
		entry_point = binary.entry()
		l.debug("Entry point = 0x%x", entry_point)

		# Crawl the binary, create CFG and fill all the refs inside project!
		l.debug("Pulling all memory")
		project.mem.pull()
		project.perm.pull()

		loaded_state = project.initial_state()
		entry_point_exit = simuvex.SimExit(addr=entry_point, state=loaded_state.copy_after(), jumpkind="Ijk_boring")
		exit_wrapper = SimExitWrapper(entry_point_exit)
		remaining_exits = [exit_wrapper]
		traced_sim_blocks = defaultdict(set)
		traced_sim_blocks[exit_wrapper.stack_suffix()].add(entry_point_exit.concretize())

		# A dict to log edges bddetween each basic block
		exit_targets = defaultdict(list)
		# Iteratively analyze every exit
		while len(remaining_exits) > 0:
			current_exit_wrapper = remaining_exits.pop()
			current_exit = current_exit_wrapper.sim_exit()
			stack_suffix = current_exit_wrapper.stack_suffix()
			addr = current_exit.concretize()
			initial_state = current_exit.state
			jumpkind = current_exit.jumpkind

			try:
				sim_run = project.sim_run(addr, initial_state, mode="static")
			except simuvex.s_irsb.SimIRSBError:
				# It's a tragedy that we came across some instructions that VEX does not support
				# Let's make a fake IRSB with a simple ret instruction inside
				# l.warning("Error while creating SimRun at 0x%x, " % addr + \
				# 	"we'll create a pseudo nop IRSB instead.")
				# fake_irsb = initial_state.arch.get_nop_irsb(addr)
				# sim_run = simuvex.SimIRSB(initial_state, fake_irsb, mode="static")
				#
				# I'll create a terminating stub there
				sim_run = simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](initial_state, addr=addr, mode="static", options=None)
			except angr.errors.AngrException as ex:
				l.error("AngrException %s when creating SimRun at 0x%x" % (ex, addr))
				# We might be on a wrong branch, and is likely to encounter the "No bytes
				# in memory xxx" exception
				# Just ignore it
				continue

			tmp_exits = sim_run.exits()

			# Adding the new sim_run to our dict
			self.bbl_dict[stack_suffix + (addr,)] = sim_run

			# TODO: Fill the mem/code references!

			# If there is a call exit, we shouldn't put the default exit (which is
			# artificial) into the CFG. The exits will be Ijk_Call and Ijk_Ret, and
			# Ijk_Call always goes first
			is_call_exit = False
			for ex in tmp_exits:
				try:
					new_addr = ex.concretize()
				except simuvex.s_value.ConcretizingException:
					# It cannot be concretized currently. Maybe we could handle it later,
					# maybe it just cannot be concretized
					continue
				new_initial_state = ex.state.copy_after()
				new_jumpkind = ex.jumpkind

				if new_jumpkind == "Ijk_Call":
					is_call_exit = True

				# Get the new stack of target block
				if new_jumpkind == "Ijk_Call":
					new_stack = current_exit_wrapper.stack_copy()
					new_stack.call(addr, new_addr)
				elif new_jumpkind == "Ijk_Ret" and not is_call_exit:
					new_stack = current_exit_wrapper.stack_copy()
					new_stack.ret()
				else:
					new_stack = current_exit_wrapper.stack()
				new_stack_suffix = new_stack.stack_suffix()

				if new_addr not in traced_sim_blocks[new_stack_suffix]:
					traced_sim_blocks[stack_suffix].add(new_addr)
					new_exit = simuvex.SimExit(addr=new_addr, state=new_initial_state, jumpkind=ex.jumpkind)
					new_exit_wrapper = SimExitWrapper(new_exit, new_stack)
					remaining_exits.append(new_exit_wrapper)

				if not is_call_exit:
					exit_targets[stack_suffix + (addr,)].append(new_stack_suffix + (new_addr,))
				elif new_jumpkind == "Ijk_Call":
					exit_targets[stack_suffix + (addr,)].append(new_stack_suffix + (new_addr,))

			# debugging!
			l.debug("Basic block [0x%08x]" % addr)
			for exit in tmp_exits:
				try:
					l.debug("|      target: %x", exit.concretize())
				except:
					l.debug("|      target cannot be concretized.")

		# Adding edges
		for tpl, targets in exit_targets.items():
			basic_block = self.bbl_dict[tpl] # Cannot fail :)
			for ex in targets:
				if ex in self.bbl_dict:
					self.cfg.add_edge(basic_block, self.bbl_dict[ex])
				else:
					import ipdb
					ipdb.set_trace()
					if ex[0] is None:
						s = "([None -> None] 0x%08x)" % (ex[2])
					elif ex[1] is None:
						s = "([None -> 0x%x] 0x%08x)" % (ex[1], ex[2])
					else:
						s = "([0x%x -> 0x%x] 0x%08x)" % (ex[0], ex[1], ex[2])
					l.warning("Key %s does not exist." % s)


	def _get_block_addr(self, b):
		if isinstance(b, simuvex.SimIRSB):
			return b.first_imark.addr
		elif isinstance(b, simuvex.SimProcedure):
			return b.addr
		else:
			raise Exception("Unsupported block type %s" % type(b))

	def output(self):
		print "Edges:"
		for edge in self.cfg.edges():
			x = edge[0]
			y = edge[1]
			print "(%x -> %x)" % (self._get_block_addr(x), self._get_block_addr(y))

	# TODO: Mark as deprecated
	def get_bbl_dict(self):
		return self.bbl_dict

	def get_predecessors(self, basic_block):
		return self.cfg.predecessors(basic_block)

	def get_successors(self, basic_block):
		return self.cfg.successors(basic_block)

	def get_irsb(self, addr):
		# TODO: Support getting irsb at arbitary address
		if addr in self.bbl_dict.keys():
			return self.bbl_dict[addr]
		else:
			return None
