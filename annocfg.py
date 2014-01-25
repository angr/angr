
class AnnotatedCFG(object):
	def __init__(self):
		pass

	def should_take_exit(self, addr_from, addr_to):
		return False

	def should_execute_statement(self, addr):
		return False

	def get_run(self, addr):
		return None

	def get_whitelisted_statement(self, addr):
		return []
