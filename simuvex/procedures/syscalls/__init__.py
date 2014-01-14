import simuvex # pylint: disable=F0401
import copy

max_fds = 8192

class SimStateSystem(simuvex.SimStatePlugin):
	def __init__(self, initialize=True, files=None):
		simuvex.SimStatePlugin.__init__(self)
		self.files = { } if files is None else files
                self.max_length = 2 ** 16

		if initialize:
			self.open("stdin", "r") # stdin
			self.open("stdout", "w") # stdout
			self.open("stderr", "w") # stderr

	def open(self, name, mode):
		# TODO: speed this up
		for fd in xrange(0, 8192):
			if fd not in self.files:
				self.files[fd] = simuvex.SimFile(fd, name, mode)
				return fd

	def read(self, fd, length):
		# TODO: error handling
		# TODO: symbolic support
		return self.files[fd].read(length)

	def write(self, fd, content, length):
		# TODO: error handling
		# TODO: symbolic support
		return self.files[fd].write(content, length)

	def close(self, fd):
		# TODO: error handling
		# TODO: symbolic support?
		del self.files[fd]

	def seek(self, fd, seek):
		# TODO: symbolic support?
		self.files[fd].seek(seek)

	def copy(self):
		files = { fd:file.copy() for fd,file in self.files }
		return SimStateSystem(False, files)

	def merge(self, other, merge_flag, flag_us_value):
		if self.files.keys() != other.files.keys():
			raise simuvex.SimMergeError("Unable to merge SimStateSystem with different sets of open files.")

		for fd in self.files:
			self.files[fd].merge(other.files[fd], merge_flag, flag_us_value)

simuvex.SimStatePlugin.register_default('posix', SimStateSystem)
