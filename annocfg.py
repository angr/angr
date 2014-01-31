import simuvex
from collections import defaultdict

class AnnotatedCFG(object):
	# cfg : class CFG
	def __init__(self, project, cfg):
		# TODO: Maybe we should recreate the CFG with every single node recreated?
		self._cfg = cfg.cfg
		self._project = project

		self._run_statement_whitelist = defaultdict(list)
		self._exit_taken = defaultdict(list)
		self._addr_to_run = {}
		self._addr_to_last_stmt_id = {}

		for run in self._cfg.nodes():
			self._addr_to_run[self.get_addr(run)] = run

	def get_addr(self, run):
		if isinstance(run, simuvex.SimIRSB):
			return run.first_imark.addr
		elif isinstance(run, simuvex.SimProcedure):
			pseudo_addr = self._project.get_pseudo_addr_for_sim_procedure(run)
			return pseudo_addr
		else:
			raise Exception()

	def add_statements_to_whitelist(self, run, stmt_ids):
		addr = self.get_addr(run)
		self._run_statement_whitelist[addr].extend(stmt_ids)
		self._run_statement_whitelist[addr] = sorted(self._run_statement_whitelist[addr])

	def add_exit_to_whitelist(self, run_from, run_to):
		addr_from = self.get_addr(run_from)
		addr_to = self.get_addr(run_to)
		self._exit_taken[addr_from].append(addr_to)

	def set_last_stmt(self, run, stmt_id):
		addr = self.get_addr(run)
		self._addr_to_last_stmt_id[run] = stmt_id

	def should_take_exit(self, addr_from, addr_to):
		if addr_from in self._exit_taken:
			return addr_to in self._exit_taken[addr_from]

		return False

	def should_execute_statement(self, addr, stmt_id):
		if addr in self._run_statement_whitelist:
			return stmt_id in self._run_statement_whitelist[addr]
		return False

	def get_run(self, addr):
		if addr in self._addr_to_run:
			return self._addr_to_run[addr]
		return None

	def get_whitelisted_statements(self, addr):
		if addr in self._run_statement_whitelist:
			return self._run_statement_whitelist[addr]
		return []

	def last_last_statement_index(self, addr):
		if addr in self._addr_to_last_stmt_id:
			return self._addr_to_last_stmt_id[addr]
		return None

	def debug_print(self):
		print "SimRuns:"
		for addr, run in self._addr_to_run.items():
			print "0x%08x => %s" % (addr, run)
		print "statements: "
		for addr, stmts in self._run_statement_whitelist.items():
			print "Address 0x%08x:" % addr
			print stmts
			for stmt_id in stmts:
				print "%d," % stmt_id,
			print ""
