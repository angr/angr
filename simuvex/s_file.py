from .s_memory import SimMemory
from .s_exception import SimMergeError

import logging
l = logging.getLogger("simuvex.s_file")

# TODO: symbolic file positions

class SimFile:
	# Creates a SimFile
	def __init__(self, fd, name, mode, content=None):
		self.fd = fd
		self.pos = 0
		self.name = name
		self.mode = mode
		self.content = SimMemory() if content is None else content

		# TODO: handle symbolic names, special cases for stdin/out/err
		# TODO: read content for existing files

	# Reads some data from the current position of the file.
	def read(self, length):
		# TODO: error handling
		# TODO: symbolic length?

		data = self.content.load(self.pos, length)
		self.pos += length
		return data

	# Writes some data to the current position of the file.
	def write(self, content, length):
		# TODO: error handling
		# TODO: symbolic length?

		self.content.store(self.pos, content)
		self.pos += length
		return length

	# Seeks to a position in the file.
	def seek(self, where):
		self.pos = where

	# Copies the SimFile object.
	def copy(self):
		c = SimFile(self.fd, self.name, self.mode, self.content.copy())
		c.pos = self.pos
		return c

	# Merges the SimFile object with another one.
	def merge(self, other, merge_flag, flag_us_value):
		if self.fd != other.fd:
			raise SimMergeError("files have different FDs")

		if self.pos != other.pos:
			raise SimMergeError("merging file positions is not yet supported (TODO)")

		if self.name != other.name:
			raise SimMergeError("merging file names is not yet supported (TODO)")

		if self.mode != other.mode:
			raise SimMergeError("merging modes is not yet supported (TODO)")

		self.content.merge(other, merge_flag, flag_us_value)
