import simuvex
import copy

max_fds = 8192

class SimStateSystem(simuvex.SimStatePlugin):
	def __init__(self, initialize=True, fd=None, fd_seek=None, fd_mode=None, fd_name=None):
		simuvex.SimStatePlugin.__init__(self)
		self.fd = { } if fd is None else fd
		self.fd_seek = { } if fd_seek is None else fd_seek
		self.fd_mode = { } if fd_mode is None else fd_mode
		self.fd_name = { } if fd_name is None else fd_name

		if initialize:
			self.open("stdin", "r") # stdin
			self.open("stdout", "w") # stdout
			self.open("stderr", "w") # stderr

	def open(self, name, mode):
		# TODO: handle symbolic names, special cases for stdin/out/err

		# TODO: read content for existing files

		# TODO: speed this up
		for i in xrange(0, 8192):
			if i not in self.fd:
				new_file = simuvex.SimMemory()
				self.fd[i] = new_file
				self.fd_seek[i] = 0
				self.fd_mode[i] = mode
				self.fd_name[i] = name
				return i

	def read(self, fd, length):
		# TODO: error handling
		# TODO: symbolic support

		data = self.fd[fd].load(self.fd_seek[fd], length)
		self.fd_seek[fd] += length
		return data

	def write(self, fd, content, length):
		# TODO: error handling
		# TODO: symbolic support

		self.fd[fd].store(self.fd_seek[fd], content)
		self.fd_seek[fd] += length
		return length

	def close(self, fd):
		# TODO: error handling
		# TODO: symbolic support?

		del self.fd[fd]
		del self.fd_seek[fd]
		del self.fd_mode[fd]
		del self.fd_name[fd]

	def seek(self, fd, seek):
		# TODO: symbolic support?

		self.fd_seek[fd] = seek

	def copy(self):
		fd_copy = { f:m.copy() for f,m in self.fd }
		fd_seek_copy = copy.copy(self.fd_seek)
		fd_mode_copy = copy.copy(self.fd_mode)
		return SimStateSystem(False, fd_copy, fd_seek_copy, fd_mode_copy)

simuvex.SimStatePlugin.register_default('posix', SimStateSystem)
