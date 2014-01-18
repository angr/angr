from collections import defaultdict
import networkx
from simuvex.s_ref import RefTypes, SimRegWrite, SimRegRead, SimTmpWrite, SimTmpRead, SimMemRef, SimMemRead, SimMemWrite, SimCodeRef
from simuvex import SimIRSB, SimProcedure
import logging

l = logging.getLogger(name="angr.sliceinfo")

class SliceInfo(object):
	def __init__(self, binary, project, cfg, cdg):
		self._binary = binary
		self._project = project
		self._cfg = cfg
		self._cdg = cdg

		self.final_run_set = None

	# With a given parameter, we try to generate a dependency graph of
	# it.
	def construct(self, irsb, stmt_id):
		l.debug("construct sliceinfo from entrypoint 0x%08x" % (self._binary.entry()))
		graph = networkx.DiGraph()

		# Backward-trace from the specified statement
		# Worklist algorithm:
		# A tuple (irsb, stmt_id, taints) is put in the worklist. If
		# it is changed, we'll redo the analysis of that IRSB

		refs = filter(lambda r: r.stmt_idx == stmt_id, irsb.refs()[SimRegWrite])
		if len(refs) != 1:
			raise Exception("Invalid references. len(refs) == %d." % len(refs))
		# TODO: Make it more elegant
		data_dep_set = set()
		data_dep_set.add(refs[0].data)
		start = TaintSource(irsb, stmt_id, data_dep_set, set(refs[0].data_reg_deps), set(refs[0].data_tmp_deps))
		worklist = set()
		worklist.add(start)
		processed_ts = set()
		run2TaintSource = defaultdict(list)
		self.final_run_set = set()
		while len(worklist) > 0:
			ts = worklist.pop()
			self.final_run_set.add(ts.run)

			run2TaintSource[ts.run].append(ts)
			data_taint_set = ts.data_taints.copy()
			reg_taint_set = ts.reg_taints.copy()
			tmp_taint_set = ts.tmp_taints.copy()
			if type(ts.run) == SimIRSB:
				irsb = ts.run
				irsb.irsb.pp()
				# Traverse the the current irsb, and taint everything related
				stmt_start_id = ts.stmt_id
				if stmt_start_id == -1:
					stmt_start_id = len(irsb.statements)
				statement_ids = range(stmt_start_id)
				statement_ids.reverse()
				for stmt_id in statement_ids:
					refs = irsb.statements[stmt_id].refs
					l.debug(str(stmt_id) + " : %s" % refs)
					for ref in refs:
						if type(ref) == SimRegWrite:
							if ref.offset in reg_taint_set:
								# Remove this taint
								reg_taint_set.remove(ref.offset)
								# Taint all its dependencies
								for reg_dep in ref.data_reg_deps:
									if reg_dep != 168:
										reg_taint_set.add(reg_dep)
								for tmp_dep in ref.data_tmp_deps:
									tmp_taint_set.add(tmp_dep)
						elif type(ref) == SimTmpWrite:
							if ref.tmp in tmp_taint_set:
								# Remove this taint
								tmp_taint_set.remove(ref.tmp)
								# Taint all its dependencies
								for reg_dep in ref.data_reg_deps:
									if reg_dep != 168:
										reg_taint_set.add(reg_dep)
								for tmp_dep in ref.data_tmp_deps:
									tmp_taint_set.add(tmp_dep)
						elif type(ref) == SimRegRead:
							l.debug("Ignoring SimRegRead")
						elif type(ref) == SimTmpRead:
							l.debug("Ignoring SimTmpRead")
						elif type(ref) == SimMemRef:
							l.debug("Ignoring SimMemRef")
						elif type(ref) == SimMemRead:
							l.debug("Ignoring SimMemRead for now...")
						elif type(ref) == SimMemWrite:
							l.debug("Ignoring SimMemWrite for now...")
						elif type(ref) == SimCodeRef:
							l.debug("Ignoring SimCodeRef")
						else:
							raise Exception("%s is not supported." % type(ref))
			elif isinstance(ts.run, SimProcedure):
				sim_proc = ts.run
				refs_dict = sim_proc.refs()
				refs = []
				for k, v in refs_dict.items():
					refs.extend(v)
				for ref in refs:
					if type(ref) == SimRegWrite:
						if ref.offset in reg_taint_set:
							# Remove this taint
							reg_taint_set.remove(ref.offset)
							# Taint all its dependencies
							for reg_dep in ref.data_reg_deps:
								if reg_dep != 168:
									reg_taint_set.add(reg_dep)
							for tmp_dep in ref.data_tmp_deps:
								tmp_taint_set.add(tmp_dep)
					elif type(ref) == SimTmpWrite:
						if ref.tmp in tmp_taint_set:
							# Remove this taint
							tmp_taint_set.remove(ref.tmp)
							# Taint all its dependencies
							for reg_dep in ref.data_reg_deps:
								if reg_dep != 168:
									reg_taint_set.add(reg_dep)
							for tmp_dep in ref.data_tmp_deps:
								tmp_taint_set.add(tmp_dep)
					elif type(ref) == SimRegRead:
						l.debug("Ignoring SimRegRead")
					elif type(ref) == SimTmpRead:
						l.debug("Ignoring SimTmpRead")
					elif type(ref) == SimMemRef:
						l.debug("Ignoring SimMemRef")
					elif type(ref) == SimMemRead:
						l.debug("Ignoring SimMemRead for now...")
					elif type(ref) == SimMemWrite:
						l.debug("Ignoring SimMemWrite for now...")
					elif type(ref) == SimCodeRef:
						l.debug("Ignoring SimCodeRef")
					else:
						raise Exception("%s is not supported." % type(ref))
			else:
				raise Exception("Unsupported SimRun type %s" % type(ts.run))

			l.debug(tmp_taint_set)
			l.debug(reg_taint_set)
			l.debug(data_taint_set)
			symbolic_data_taint_set = set()
			for d in data_taint_set:
				if d.is_symbolic():
					symbolic_data_taint_set.add(d)

			# TODO: Put it into our graph!

			processed_ts.add(TaintSource(ts.run, -1, symbolic_data_taint_set, reg_taint_set, tmp_taint_set))
			# Get its predecessors from our CFG
			if len(symbolic_data_taint_set) > 0 or len(reg_taint_set) > 0:
				predecessors = self._cfg.get_predecessors(ts.run)
				for p in predecessors:
					l.debug("%s Got new predecessor %s" % (ts.run, p))
					existing_tses = filter(lambda r : r.run == p, processed_ts)
					if len(existing_tses) > 0:
						existing_ts = existing_tses[0]
						if existing_ts.reg_taints != reg_taint_set or existing_ts.data_taints != data_taint_set:
							# Remove the existing one
							processed_ts.remove(existing_ts)
						else:
							l.debug("Ignore predecessor %s" % p)
							continue
					new_ts = TaintSource(p, -1, symbolic_data_taint_set, reg_taint_set, tmp_taint_set)
					worklist.add(new_ts)
			# Let's also search on control dependency graph
			cdg_predecessors = self._cdg.get_predecessors(ts.run)
			for p in cdg_predecessors:
				existing_tses = filter(lambda r : r.run == p, processed_ts)
				if len(existing_tses) > 0:
					existing_ts = existing_tses[0]
					if existing_ts.reg_taints != reg_taint_set or existing_ts.data_taints != data_taint_set:
						# Remove the existing one
						processed_ts.remove(existing_ts)
					else:
						l.debug("Ignore predecessor %s" % p)
						continue
				new_ts = TaintSource(p, -1, set(), set(), set())
				worklist.add(new_ts)

			raw_input("Press any key to continue...")

class TaintSource(object):
	# taints: a set of all tainted stuff after this basic block
	def __init__(self, run, stmt_id, data_taints, reg_taints, tmp_taints):
		self.run = run
		self.stmt_id = stmt_id
		self.data_taints = data_taints
		self.reg_taints = reg_taints
		self.tmp_taints = tmp_taints

	def equalsTo(self, obj):
		return (self.irsb == obj.irsb) and (self.stmt_id == obj.stmt_id) and (self.taints == obj.taints)
