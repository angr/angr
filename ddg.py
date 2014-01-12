from collections import defaultdict
import networkx
from simuvex.s_ref import RefTypes, SimRegWrite, SimRegRead

# Data dependence graph
# We track dependencies between registers, stack vabiralbes and global
# memory.

class DDG(object):
	def __init__(self, binary, project, cfg):
		self._binary = binary
		self._project = project
		self._cfg = cfg

	# With a given parameter, we try to generate a dependency graph of
	# it.
	# reg_offset - the offset of register
	def construct(self, irsb, stmt_id):
		graph = networkx.DiGraph()

		# Backtrace from the specified statement
		# Worklist algorithm:
		# A tuple (irsb, stmt_id, taints) is put in the worklist. If
		# it is changed, we'll redo the analysis of that IRSB

		refs = filter(lambda r: r.stmt_idx == stmt_id, irsb.refs()[SimRegWrite])
		if len(refs) != 1:
			raise Exception("Invalid references. len(refs) == %d." % len(refs))
		start = TaintSource(irsb, stmt_id, refs)
		worklist = set()
		worklist.add(start)
		irsb2TaintSource = defaultdict(list)
		while len(worklist) > 0:
			ts = worklist.pop()

			irsb2TaintSource[ts.irsb].append(ts)
			new_taints = ts.taints[ : ]
			# TODO: Clean new_refs
			for r in new_taints:
				print r
			# TODO: Put it into our graph!
			# Get its predecessors from our CFG
			predecessors = self._cfg.get_predecessors(irsb)
			for p in predecessors:
				new_ts = TaintSource(p, len(p.statements) - 1, new_taints)
				if new_ts not in irsb2TaintSource[new_ts.irsb]:
					worklist.add(new_ts)

class TaintSource(object):
	# taints: a set of all tainted stuff after this basic block
	def __init__(self, irsb, stmt_id, taints):
		self.irsb = irsb
		self.stmt_id = stmt_id
		self.taints = taints

	def equalsTo(self, obj):
		return (self.irsb == obj.irsb) and (self.stmt_id == obj.stmt_id) and (self.taints == obj.taints)
