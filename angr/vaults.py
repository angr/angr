import collections
import contextlib
import tempfile
import weakref
import logging
import claripy
import pickle
import shelve
import uuid
import os
import io

l = logging.getLogger("angr.vault")

class VaultPickler(pickle.Pickler):
	def __init__(self, vault, file, *args, assigned_objects=(), **kwargs):
		"""
		A persistence-aware pickler.
		It will check for persistence of any objects except for those with IDs in 'assigned_objects'.
		"""

		super().__init__(file, *args, **kwargs)
		self.vault = vault
		self.assigned_objects = assigned_objects

	def persistent_id(self, obj):
		return self.vault._persistent_store(obj, self)

class VaultUnpickler(pickle.Unpickler):
	def __init__(self, vault, file, *args, **kwargs):
		super().__init__(file, *args, **kwargs)
		self.vault = vault

	def persistent_load(self, pid):
		return self.vault.load(pid)

class Vault(collections.MutableMapping):
	"""
	The vault is a serializer for angr.
	"""

	#
	# These MUST be overriden.
	#

	def pickler_context(self, id): #pylint:disable=redefined-builtin
		"""
		Retrieves a pickler with the provided id, for pickling streams of objects.
		"""
		raise NotImplementedError()

	def unpickler_context(self, id): #pylint:disable=redefined-builtin
		"""
		Retrieves an unpickler with the provided id, for unpickling streams of objects.
		"""
		raise NotImplementedError()

	def keys(self):
		"""
		Should return the IDs stored by the vault.
		"""
		raise NotImplementedError()

	#
	# Persistance managers
	#

	def __init__(self):
		self._object_cache = weakref.WeakValueDictionary()

	@staticmethod
	def _get_persistent_id(o):
		"""
		Determines a persistent ID for an object.
		Does NOT do stores.
		"""
		if isinstance(o, claripy.ast.Base):
			return "AST-" + str(hash(o))
		elif isinstance(o, SimState):
			return "STATE-" + str(hash(o))
		return None

	def _persistent_store(self, o, p): #pylint:disable=redefined-builtin
		"""
		This function should return a persistent ID for deduplication purposes.
		If it does so, it should handle the storage of the object!

		@param o: the object
		"""

		pid = self._get_persistent_id(o)
		if pid is None:
			return None
		l.debug("Persistent store: %s", o)
		l.debug("... pid: %s", pid)
		if pid in p.assigned_objects:
			l.debug("... in assigned objects")
			return None
		if self.is_stored(pid):
			l.debug("... already stored")
			return pid
		l.debug("... not stored")

		return self.store(o, id=pid)

	#
	# Other stuff
	#

	def is_stored(self, id): #pylint:disable=redefined-builtin
		"""
		Checks if the provided id is already in the vault.
		"""
		try:
			with self.unpickler_context(id) as p:
				p.load()
				return True
		except (AngrVaultError, EOFError):
			return False

	def load(self, id): #pylint:disable=redefined-builtin
		"""
		Retrieves one object from the pickler with the provided id.

		@param id: an ID to use
		"""
		l.debug("LOAD: %s", id)
		try:
			l.debug("... trying cached")
			return self._object_cache[id]
		except KeyError:
			l.debug("... cached failed")
			with self.unpickler_context(id) as u:
				return u.load()

	@staticmethod
	def _get_id(o):
		"""
		Generates an id for an object.
		"""
		return o.__class__.__name__ + '-' + str(uuid.uuid1())

	def store(self, o, id=None): #pylint:disable=redefined-builtin
		"""
		Stores an object and returns its ID.

		@param o: the object
		@param id: an ID to use
		"""
		actual_id = id or self._get_persistent_id(o) or self._get_id(o)
		l.debug("STORE: %s %s", o, actual_id)
		with self.pickler_context(actual_id) as p:
			p.dump(o)
		self._object_cache[actual_id] = o
		return actual_id

	def dumps(self, o):
		"""
		Returns a serialized string representing the object, post-deduplication.

		@param o: the object
		"""
		f = io.BytesIO()
		VaultPickler(self, f).dump(o)
		f.seek(0)
		return f.read()

	def loads(self, s):
		"""
		Deserializes a string representation of the object.

		@param s: the string
		"""
		f = io.BytesIO(s)
		return VaultUnpickler(self, f).load()

	#
	# For MutableMapping.
	#

	def __setitem__(self, k, v):
		self.store(v, id=k)

	def __getitem__(self, k):
		return self.load(k)

	def __delitem__(self, k):
		raise AngrVaultError("We currently don't support deletion from the vault.")

	def __iter__(self):
		return iter(self.keys())

	def __len__(self):
		return len(self.keys())

class VaultDict(Vault):
	"""
	A Vault that uses a directory for storage.
	"""
	def __init__(self, d=None):
		super().__init__()
		self._dict = { } if d is None else d

	@contextlib.contextmanager
	def pickler_context(self, id): #pylint:disable=redefined-builtin
		f = io.BytesIO()
		yield VaultPickler(self, f, assigned_objects=(id))
		f.seek(0)
		self._dict[id] = f.read()

	@contextlib.contextmanager
	def unpickler_context(self, id): #pylint:disable=redefined-builtin
		try:
			f = io.BytesIO(self._dict[id])
			yield VaultUnpickler(self, f)
		except KeyError as e:
			raise AngrVaultError from e

	def keys(self):
		return self._dict.keys()

class VaultDir(Vault):
	"""
	A Vault that uses a directory for storage.
	"""
	def __init__(self, d=None):
		super().__init__()
		self._dir = tempfile.mkdtemp() if d is None else d
		with contextlib.suppress(FileExistsError):
			os.makedirs(self._dir)

	@contextlib.contextmanager
	def pickler_context(self, id): #pylint:disable=redefined-builtin
		with open(os.path.join(self._dir, id), "wb") as o:
			yield VaultPickler(self, o, assigned_objects=(id))

	@contextlib.contextmanager
	def unpickler_context(self, id): #pylint:disable=redefined-builtin
		try:
			with open(os.path.join(self._dir, id), "rb") as o:
				yield VaultUnpickler(self, o)
		except FileNotFoundError as e:
			raise AngrVaultError from e

	def keys(self):
		return os.listdir(self._dir)

class VaultShelf(VaultDict):
	"""
	A Vault that uses a shelve.Shelf for storage.
	"""
	def __init__(self, path=None):
		self._path = tempfile.mktemp() if path is None else path
		s = shelve.open(self._path)
		super().__init__(s)

from .errors import AngrVaultError
from .sim_state import SimState
