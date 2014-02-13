from collections import defaultdict
import networkx
from simuvex.s_ref import RefTypes, SimRegWrite, SimRegRead, SimTmpWrite, SimTmpRead, SimMemRef, SimMemRead, SimMemWrite, SimCodeRef
from simuvex import SimIRSB, SimProcedure
import simuvex
import logging

l = logging.getLogger(name="angr.sliceinfo")

class SliceInfo(object):
	def __init__(self, binary, project, cfg, cdg, ddg):
		self._binary = binary
		self._project = project
		self._cfg = cfg
		self._cdg = cdg
		self._ddg = ddg

		self.runs_in_slice = None
		self.run_statements = None

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
		start = TaintSource(irsb, stmt_id, data_dep_set, set(refs[0].data_reg_deps), set(refs[0].data_tmp_deps), kid=None)
		worklist = set()
		worklist.add(start)
		processed_ts = set()
		run2TaintSource = defaultdict(list)
		self.runs_in_slice = networkx.DiGraph()
		# We are using a list here, and later on we reconstruct lists and write it to 
		# self.run_statements
		run_statements = defaultdict(set)
		while len(worklist) > 0:
			ts = worklist.pop()
			if ts.kid != None:
				self.runs_in_slice.add_edge(ts.run, ts.kid.run)
			run2TaintSource[ts.run].append(ts)
			data_taint_set = ts.data_taints.copy()
			reg_taint_set = ts.reg_taints.copy()
			tmp_taint_set = ts.tmp_taints.copy()
			if type(ts.run) == SimIRSB:
				irsb = ts.run
				print "====> Pick a new run at 0x%08x" % ts.run.addr
				# irsb.irsb.pp()
				arch_name = ts.run.state.arch.name
				reg_taint_set.add(simuvex.Architectures[arch_name].ip_offset)
				# Traverse the the current irsb, and taint everything related
				stmt_start_id = ts.stmt_id
				if stmt_start_id == -1:
					stmt_start_id = len(irsb.statements) - 1
				statement_ids = range(stmt_start_id + 1)
				statement_ids.reverse()
				# Taint the default exit first
				for ref in irsb.next_expr.refs:
					if type(ref) == SimTmpRead:
						tmp_taint_set.add(ref.tmp)
				# We also taint the stack pointer, so we could keep the stack balanced
				reg_taint_set.add(simuvex.Architectures[arch_name].sp_offset)
				for stmt_id in statement_ids:
					# l.debug(reg_taint_set)
					refs = irsb.statements[stmt_id].refs
					# l.debug(str(stmt_id) + " : %s" % refs)
					# irsb.statements[stmt_id].stmt.pp()
					for ref in refs:
						if type(ref) == SimRegWrite:
							if ref.offset in reg_taint_set:
								run_statements[irsb].add(stmt_id)
								if ref.offset != simuvex.Architectures[arch_name].ip_offset:
									# Remove this taint
									reg_taint_set.remove(ref.offset)
								# Taint all its dependencies
								for reg_dep in ref.data_reg_deps:
									reg_taint_set.add(reg_dep)
								for tmp_dep in ref.data_tmp_deps:
									tmp_taint_set.add(tmp_dep)
						elif type(ref) == SimTmpWrite:
							if ref.tmp in tmp_taint_set:
								run_statements[irsb].add(stmt_id)
								# Remove this taint
								tmp_taint_set.remove(ref.tmp)
								# Taint all its dependencies
								for reg_dep in ref.data_reg_deps:
									reg_taint_set.add(reg_dep)
								for tmp_dep in ref.data_tmp_deps:
									tmp_taint_set.add(tmp_dep)
						elif type(ref) == SimRegRead:
							# l.debug("Ignoring SimRegRead")
							pass
						elif type(ref) == SimTmpRead:
							# l.debug("Ignoring SimTmpRead")
							pass
						elif type(ref) == SimMemRef:
							# l.debug("Ignoring SimMemRef")
							pass
						elif type(ref) == SimMemRead:
							if irsb in self._ddg._ddg and stmt_id in self._ddg._ddg[irsb]:
								dependent_run, dependent_stmt_id = self._ddg._ddg[irsb][stmt_id]
								if type(dependent_run) == SimIRSB:
									# It's incorrect to do this:
									# 'run_statements[dependent_run].add(dependent_stmt_id)'
									# We should add a dependency to that SimRun object, and reanalyze
									# it by putting it to our worklist once more
									data_set = set()
									data_set.add(dependent_stmt_id)
									new_ts = TaintSource(p, -1, data_set, set(), set())
									worklist.add(new_ts)
								else:
									raise Exception("NotImplemented.")
						elif type(ref) == SimMemWrite:
							if stmt_id in data_taint_set:
								data_taint_set.remove(stmt_id)
								run_statements[irsb].add(stmt_id)
								for d in ref.data_reg_deps:
									reg_taint_set.add(d)
								for d in ref.addr_reg_deps:
									reg_taint_set.add(d)
								for d in ref.data_tmp_deps:
									tmp_taint_set.add(d)
								for d in ref.addr_tmp_deps:
									tmp_taint_set.add(d)
								# TODO: How do we handle other data dependencies here? Or if there is any?
						elif type(ref) == SimCodeRef:
							# l.debug("Ignoring SimCodeRef")
							pass
						else:
							raise Exception("%s is not supported." % type(ref))
			elif isinstance(ts.run, SimProcedure):
				sim_proc = ts.run
				refs_dict = sim_proc.refs()
				l.debug("SimProcedure Refs:")
				l.debug(refs_dict)
				refs = []
				for k, v in refs_dict.items():
					refs.extend(v)
				for ref in refs:
					if type(ref) == SimRegWrite:
						if ref.offset in reg_taint_set:
							if ref.offset != simuvex.Architectures[arch_name].ip_offset:
								# Remove this taint
								reg_taint_set.remove(ref.offset)
							# Taint all its dependencies
							for reg_dep in ref.data_reg_deps:
								reg_taint_set.add(reg_dep)
							for tmp_dep in ref.data_tmp_deps:
								tmp_taint_set.add(tmp_dep)
					elif type(ref) == SimTmpWrite:
						if ref.tmp in tmp_taint_set:
							# Remove this taint
							tmp_taint_set.remove(ref.tmp)
							# Taint all its dependencies
							for reg_dep in ref.data_reg_deps:
								reg_taint_set.add(reg_dep)
							for tmp_dep in ref.data_tmp_deps:
								tmp_taint_set.add(tmp_dep)
					elif type(ref) == SimRegRead:
						# Adding new ref!
						reg_taint_set.add(ref.offset)
					elif type(ref) == SimTmpRead:
						l.debug("Ignoring SimTmpRead")
					elif type(ref) == SimMemRef:
						l.debug("Ignoring SimMemRef")
					elif type(ref) == SimMemRead:
						if sim_proc in self._ddg._ddg:
							dependent_run, dependent_stmt_id = self._ddg._ddg[sim_proc][-1]
							if type(dependent_run) == SimIRSB:
								data_set = set()
								data_set.add(dependent_stmt_id)
								new_ts = TaintSource(p, -1, data_set, set(), set())
								worklist.add(new_ts)
							else:
								raise Exception("Not implemented.")
					elif type(ref) == SimMemWrite:
						if stmt_id in data_taint_set:
							data_taint_set.remove(stmt_id)
							run_statements[irsb].add(stmt_id)
							for d in ref.data_reg_deps:
								reg_taint_set.add(d)
							for d in ref.addr_reg_deps:
								reg_taint_set.add(d)
							for d in ref.data_tmp_deps:
								tmp_taint_set.add(d)
							for d in ref.addr_tmp_deps:
								tmp_taint_set.add(d)
							# TODO: How do we handle other data dependencies here? Or if there is any?
					elif type(ref) == SimCodeRef:
						l.debug("Ignoring SimCodeRef")
					else:
						raise Exception("%s is not supported." % type(ref))
			else:
				raise Exception("Unsupported SimRun type %s" % type(ts.run))

			l.debug("[%d]%s", len(tmp_taint_set), tmp_taint_set)
			l.debug("[%d]%s", len(reg_taint_set), reg_taint_set)
			l.debug("[%d]%s", len(data_taint_set), data_taint_set)
			l.debug("Worklist size: %d", len(worklist))
			# symbolic_data_taint_set = set()
			# for d in data_taint_set:
			# 	if d.is_symbolic():
			# 		symbolic_data_taint_set.add(d)

			# TODO: Put it into our graph!

			processed_ts.add(TaintSource(ts.run, -1, data_taint_set, reg_taint_set, tmp_taint_set, kid=ts))
			# Get its predecessors from our CFG
			if len(data_taint_set) > 0 or len(reg_taint_set) > 0:
				predecessors = self._cfg.get_predecessors(ts.run)
				for p in predecessors:
					l.debug("%s Got new predecessor %s" % (ts.run, p))
					existing_tses = filter(lambda r : r.run == p, processed_ts)
					if len(existing_tses) > 0:
						existing_ts = existing_tses[0]
						if existing_ts.reg_taints != reg_taint_set or existing_ts.data_taints != data_taint_set:
							# Remove the existing one
							processed_ts.remove(existing_ts)
							# Merge the old taint sets into new taint sets
							reg_taint_set |= existing_ts.reg_taints
							data_taint_set |= existing_ts.data_taints
						else:
							l.debug("Ignore predecessor %s" % p)
							continue
					# Remove existing runs inside worklist
					old_ts_list = filter(lambda r : r.run == p, worklist)
					for old_ts in old_ts_list:
						worklist.remove(old_ts)
						l.debug("Removing %s from worklist" % old_ts.run)
					# Add the new run
					new_ts = TaintSource(p, -1, data_taint_set, reg_taint_set, tmp_taint_set, kid=ts)
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
						# Merge the old taint sets into new taint sets
						reg_taint_set |= existing_ts.reg_taints
						data_taint_set |= existing_ts.data_taints
					else:
						l.debug("Ignore predecessor %s" % p)
						continue
				# Search for the last branching exit, just like
				#     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
				# , and then taint the temp variable inside if predicate
				new_tmp_taints = set()
				statement_ids = range(len(p.statements))
				statement_ids.reverse()
				cmp_stmt_id = 0
				for stmt_id in statement_ids:
					refs = p.statements[stmt_id].refs
					# Ugly implementation here
					has_code_ref = False
					for r in refs:
						if isinstance(r, SimCodeRef):
							has_code_ref = True
					if has_code_ref:
						tmp_ref = refs[0]
						new_tmp_taints.add(tmp_ref.tmp)
						cmp_stmt_id = stmt_id
						break

				l.debug("%s Got new control-dependency predecessor %s" % (ts.run, p))
				# Remove existing runs inside worklist
				new_data_taint_set = set()
				new_reg_taint_set = set()
				old_ts_list = filter(lambda r : r.run == p, worklist)
				for old_ts in old_ts_list:
					new_data_taint_set |= old_ts.data_taints
					new_reg_taint_set |= old_ts.reg_taints
					worklist.remove(old_ts)
					l.debug("Removing %s from worklist" % old_ts.run)
				run_statements[p].add(cmp_stmt_id)
				new_ts = TaintSource(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taints, kid=ts)
				worklist.add(new_ts)

			# raw_input("Press any key to continue...")
		
		# Reconstruct the run_statements
		self.run_statements = defaultdict(list)
		for run, s in run_statements.items():
			self.run_statements[run] = list(s)

class TaintSource(object):
	# taints: a set of all tainted stuff after this basic block
	def __init__(self, run, stmt_id, data_taints, reg_taints, tmp_taints, kid=None):
		self.run = run
		self.stmt_id = stmt_id
		self.data_taints = data_taints
		self.reg_taints = reg_taints
		self.tmp_taints = tmp_taints
		self.kid = kid

	def equalsTo(self, obj):
		return (self.irsb == obj.irsb) and (self.stmt_id == obj.stmt_id) and (self.taints == obj.taints)
