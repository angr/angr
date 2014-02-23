import copy
import simuvex # pylint: disable=F0401
import collections

import logging
l = logging.getLogger('simuvex.procedures.syscalls')

max_fds = 8192

class SimStateSystem(simuvex.SimStatePlugin):
	#__slots__ = [ 'maximum_symbolic_syscalls', 'files', 'max_length' ]

	def __init__(self, initialize=True, files=None):
		simuvex.SimStatePlugin.__init__(self)
		self.maximum_symbolic_syscalls = 255
		self.files = { } if files is None else files
		self.max_length = 2 ** 16

		if initialize:
			l.debug("Initializing files...")
			self.open("stdin", "r") # stdin
			self.open("stdout", "w") # stdout
			self.open("stderr", "w") # stderr
		else:
			l.debug("Not initializing files...")

	def open(self, name, mode):
		# TODO: speed this up
		for fd in xrange(0, 8192):
			if fd not in self.files:
				self.files[fd] = simuvex.SimFile(fd, name, mode)
				return fd

	def read_value(self, fd, length, pos=None):
		return self.state.expr_value(self.read(fd, length, pos=pos))

	def read(self, fd, length, pos=None):
		# TODO: error handling
		# TODO: symbolic support
		fd = self.state.make_concrete_int(fd)
		expr, constraints = self.files[fd].read(length, pos)
		self.state.add_constraints(*constraints)
		return expr

	def write(self, fd, content, length, pos=None):
		# TODO: error handling
		# TODO: symbolic support
		fd = self.state.make_concrete_int(fd)
		length = self.state.make_concrete_int(length)
		return self.files[fd].write(content, length, pos)

	def close(self, fd):
		# TODO: error handling
		# TODO: symbolic support?
		fd = self.state.make_concrete_int(fd)
		del self.files[fd]

	def seek(self, fd, seek):
		# TODO: symbolic support?
		fd = self.state.make_concrete_int(fd)
		self.files[fd].seek(seek)

	def copy(self):
		files = { fd:f.copy() for fd,f in self.files.iteritems() }
		return SimStateSystem(initialize=False, files=files)

	def merge(self, others, merge_flag, flag_values):
		if len(set(frozenset(o.files.keys()) for o in [ self ] + others)) != 1:
			raise simuvex.SimMergeError("Unable to merge SimStateSystem with different sets of open files.")

		for fd in self.files:
			constraints = self.files[fd].merge([ o.files[fd] for o in others ], merge_flag, flag_values)
			self.state.add_constraints(*constraints)

		return [ ]

	def dumps(self, fd):
		concretized_bytes = { i: self.read_value(fd, 1, pos=i).any() for i in self.files[fd].content.mem.keys() }
		all_bytes = collections.defaultdict(lambda: 0x41)
		all_bytes.update(concretized_bytes)
		return "".join([ chr(all_bytes[i]) for i in all_bytes ])
		
	def dump(self, fd, filename):
		open(filename, "w").write(self.dumps(fd))

	def get_file(self, fd):
		if fd not in self.files:
			return [ ]
		return self.files[fd]

simuvex.SimStatePlugin.register_default('posix', SimStateSystem)
