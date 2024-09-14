from __future__ import annotations
import os
import logging
from collections import namedtuple

from .plugin import SimStatePlugin
from ..storage.file import SimFile
from ..errors import SimMergeError
from ..misc.ux import once

l = logging.getLogger(name=__name__)

Stat = namedtuple(
    "Stat",
    (
        "st_dev",
        "st_ino",
        "st_nlink",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_rdev",
        "st_size",
        "st_blksize",
        "st_blocks",
        "st_atime",
        "st_atimensec",
        "st_mtime",
        "st_mtimensec",
        "st_ctime",
        "st_ctimensec",
    ),
)


class SimFilesystem(SimStatePlugin):  # pretends links don't exist
    """
    angr's emulated filesystem. Available as state.fs.
    When constructing, all parameters are optional.

    :param files:       A mapping from filepath to SimFile
    :param pathsep:     The character used to separate path elements, default forward slash.
    :param cwd:         The path of the current working directory to use
    :param mountpoints: A mapping from filepath to SimMountpoint

    :ivar pathsep:      The current pathsep
    :ivar cwd:          The current working directory
    :ivar unlinks:      A list of unlink operations, tuples of filename and simfile. Be careful, this list is
                        shallow-copied from successor to successor, so don't mutate anything in it without copying.
    """

    def __init__(self, files=None, pathsep=None, cwd=None, mountpoints=None):
        super().__init__()

        if files is None:
            files = {}
        if pathsep is None:
            pathsep = b"/"
        if cwd is None:
            cwd = pathsep
        if mountpoints is None:
            mountpoints = {}

        self.pathsep = pathsep
        self.cwd = cwd
        self._unlinks = []
        self._files = {}
        self._mountpoints = {}

        for fname in mountpoints:
            self.mount(fname, mountpoints[fname])
        for fname in files:
            self.insert(fname, files[fname])

    @SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)

        o.pathsep = self.pathsep
        o.cwd = self.cwd
        o._unlinks = list(self._unlinks)
        o._files = {k: v.copy(memo) for k, v in self._files.items()}
        o._mountpoints = {k: v.copy(memo) for k, v in self._mountpoints.items()}

        return o

    @property
    def unlinks(self):
        for _, f in self._unlinks:
            f.set_state(self.state)
        return self._unlinks

    def set_state(self, state):
        super().set_state(state)
        for fname in self._files:
            self._files[fname].set_state(state)
        for fname in self._mountpoints:
            self._mountpoints[fname].set_state(state)

    def merge(self, others, merge_conditions, common_ancestor=None):
        for o in others:
            if o.cwd != self.cwd:
                raise SimMergeError("Can't merge filesystems with disparate cwds")
            if len(o._mountpoints) != len(self._mountpoints):
                raise SimMergeError("Can't merge filesystems with disparate mountpoints")
            if list(map(id, o.unlinks)) != list(map(id, self.unlinks)):
                raise SimMergeError("Can't merge filesystems with disparate unlinks")

        for fname in self._mountpoints:
            try:
                subdeck = [o._mountpoints[fname] for o in others]
            except KeyError as err:
                raise SimMergeError("Can't merge filesystems with disparate file sets") from err

            if common_ancestor is not None and fname in common_ancestor._mountpoints:
                common_mp = common_ancestor._mountpoints[fname]
            else:
                common_mp = None

            self._mountpoints[fname].merge(subdeck, merge_conditions, common_ancestor=common_mp)

        # this is a little messy
        deck = [self, *others]
        all_files = set.union(*(set(o._files.keys()) for o in deck))
        for fname in all_files:
            subdeck = [o._files.get(fname, None) for o in deck]
            representative = next(x for x in subdeck if x is not None)
            for i, v in enumerate(subdeck):
                if v is None:
                    subdeck[i] = representative()
                    if i == 0:
                        self._files[fname] = subdeck[i]

            if common_ancestor is not None and fname in common_ancestor._files:
                common_simfile = common_ancestor._files[fname]
            else:
                common_simfile = None

            subdeck[0].merge(subdeck[1:], merge_conditions, common_ancestor=common_simfile)

        return True

    def widen(self, others):  # pylint: disable=unused-argument
        if once("fs_widen_warning"):
            l.warning("Filesystems can't be widened yet - beware unsoundness")

    def _normalize_path(self, path):
        """
        Takes a path and returns a simple absolute path as a list of directories from the root
        """
        if type(path) is str:
            path = path.encode()
        path = path.split(b"\0")[0]

        if path[0:1] != self.pathsep:
            path = self.cwd + self.pathsep + path
        keys = path.split(self.pathsep)
        i = 0
        while i < len(keys):
            if keys[i] == b"" or keys[i] == b".":
                keys.pop(i)
            elif keys[i] == b"..":
                keys.pop(i)
                if i != 0:
                    keys.pop(i - 1)
                    i -= 1
            else:
                i += 1
        return keys

    def _join_chunks(self, keys):
        """
        Takes a list of directories from the root and joins them into a string path
        """
        return self.pathsep + self.pathsep.join(keys)

    def chdir(self, path):
        """
        Changes the current directory to the given path
        """
        self.cwd = self._join_chunks(self._normalize_path(path))

    def get(self, path):
        """
        Get a file from the filesystem. Returns a SimFile or None.
        """
        mountpoint, chunks = self.get_mountpoint(path)

        if mountpoint is None:
            return self._files.get(self._join_chunks(chunks))
        return mountpoint.get(chunks)

    def insert(self, path, simfile):
        """
        Insert a file into the filesystem. Returns whether the operation was successful.
        """
        if self.state is not None:
            simfile.set_state(self.state)
        mountpoint, chunks = self.get_mountpoint(path)

        if mountpoint is None:
            self._files[self._join_chunks(chunks)] = simfile
            return True
        return mountpoint.insert(chunks, simfile)

    def delete(self, path):
        """
        Remove a file from the filesystem. Returns whether the operation was successful.

        This will add a ``fs_unlink`` event with the path of the file and also the index into the `unlinks` list.
        """
        mountpoint, chunks = self.get_mountpoint(path)
        apath = self._join_chunks(chunks)

        if mountpoint is None:
            try:
                simfile = self._files.pop(apath)
            except KeyError:
                return False
            else:
                self.state.history.add_event("fs_unlink", path=apath, unlink_idx=len(self.unlinks))
                self.unlinks.append((apath, simfile))
                return True
        else:
            return mountpoint.delete(chunks)

    def mount(self, path, mount):
        """
        Add a mountpoint to the filesystem.
        """
        self._mountpoints[self._join_chunks(self._normalize_path(path))] = mount

    def unmount(self, path):
        """
        Remove a mountpoint from the filesystem.
        """
        del self._mountpoints[self._join_chunks(self._normalize_path(path))]

    def get_mountpoint(self, path):
        """
        Look up the mountpoint servicing the given path.

        :return: A tuple of the mount and a list of path elements traversing from the mountpoint to the specified file.
        """
        path_chunks = self._normalize_path(path)
        for i in range(len(path_chunks) - 1, -1, -1):
            partial_path = self._join_chunks(path_chunks[:-i])
            if partial_path in self._mountpoints:
                mountpoint = self._mountpoints[partial_path]
                if mountpoint is None:
                    break
                return mountpoint, path_chunks[-i:]

        return None, path_chunks


SimFilesystem.register_default("fs")


class SimMount(SimStatePlugin):
    """
    This is the base class for "mount points" in angr's simulated filesystem. Subclass this class and
    give it to the filesystem to intercept all file creations and opens below the mountpoint.
    Since this a SimStatePlugin you may also want to implement set_state, copy, merge, etc.
    """

    def get(self, path_elements):
        """
        Implement this function to instrument file lookups.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :return:                A SimFile, or None
        """
        raise NotImplementedError

    def insert(self, path_elements, simfile):
        """
        Implement this function to instrument file creation.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :param simfile:         The file to insert
        :return:                A bool indicating whether the insert occurred
        """
        raise NotImplementedError

    def delete(self, path_elements):
        """
        Implement this function to instrument file deletion.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :return:                A bool indicating whether the delete occurred
        """
        raise NotImplementedError

    def lookup(self, sim_file):
        """
        Look up the path of a SimFile in the mountpoint

        :param sim_file:        A SimFile object needs to be looked up
        :return:                A string representing the path of the file in the mountpoint
                                Or None if the SimFile does not exist in the mountpoint
        """
        raise NotImplementedError


class SimConcreteFilesystem(SimMount):
    """
    Abstract SimMount allowing the user to import files from some external source into the guest

    :param str pathsep:         The host path separator character, default os.path.sep
    """

    def __init__(self, pathsep=os.path.sep):
        super().__init__()
        self.pathsep = pathsep
        self.cache = {}
        self.deleted_list = set()

    def get(self, path_elements):
        path = self._join_chunks([x.decode() for x in path_elements])
        if path in self.deleted_list:
            return None
        if path not in self.cache:
            simfile = self._load_file(path)
            if simfile is None:
                return None
            self.insert(path_elements, simfile)

        return self.cache[path]

    def _load_file(self, guest_path):
        raise NotImplementedError

    def _get_stat(self, guest_path, dereference=False):
        raise NotImplementedError

    def insert(self, path_elements, simfile):
        path = self._join_chunks([x.decode() for x in path_elements])
        simfile.set_state(self.state)
        self.cache[path] = simfile
        self.deleted_list.discard(path)
        return True

    def delete(self, path_elements):
        path = self._join_chunks([x.decode() for x in path_elements])
        self.deleted_list.add(path)
        return self.cache.pop(path, None) is not None

    def lookup(self, sim_file):
        for key, val in self.cache.items():
            if sim_file == val:
                return key
        return None

    @SimStatePlugin.memo
    def copy(self, memo):
        x = type(self)(pathsep=self.pathsep)
        x.cache = {fname: self.cache[fname].copy(memo) for fname in self.cache}
        x.deleted_list = set(self.deleted_list)
        return x

    def set_state(self, state):
        super().set_state(state)
        for fname in self.cache:
            self.cache[fname].set_state(state)

    def merge(self, others, merge_conditions, common_ancestor=None):
        merging_occurred = False

        for o in others:
            if o.pathsep != self.pathsep:
                raise SimMergeError("Can't merge concrete filesystems with disparate pathseps")
            if o.deleted_list != self.deleted_list:
                raise SimMergeError("Can't merge concrete filesystems with disparate deleted files")

        deck = [self, *others]
        all_files = set.union(*(set(o._files.keys()) for o in deck))
        for fname in all_files:
            subdeck = []
            basecase = None
            for o in deck:
                try:
                    subdeck.append(o.cache[fname])
                except KeyError:
                    if basecase is None:
                        basecase = self._load_file(fname)
                    subdeck.append(basecase)

            if common_ancestor is not None and fname in common_ancestor.cache:
                common_simfile = common_ancestor.cache[fname]
            else:
                common_simfile = None

            merging_occurred |= subdeck[0].merge(subdeck[1:], merge_conditions, common_ancestor=common_simfile)
        return merging_occurred

    def widen(self, others):  # pylint: disable=unused-argument
        if once("host_fs_widen_warning"):
            l.warning("The host filesystem mount can't be widened yet - beware unsoundness")

    def _join_chunks(self, keys):
        """
        Takes a list of directories from the root and joins them into a string path
        """
        return self.pathsep + self.pathsep.join(keys)


class SimHostFilesystem(SimConcreteFilesystem):
    """
    Simulated mount that makes some piece from the host filesystem available to the guest.

    :param str host_path:       The path on the host to mount
    :param str pathsep:         The host path separator character, default os.path.sep
    """

    def __init__(self, host_path=None, **kwargs):
        super().__init__(**kwargs)
        self.host_path = host_path if host_path is not None else self.pathsep

    @SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.host_path = self.host_path
        return o

    def _load_file(self, guest_path):
        guest_path = guest_path.lstrip(self.pathsep)
        path = os.path.join(self.host_path, guest_path)
        try:
            with open(path, "rb") as fp:
                content = fp.read()
        except OSError:
            return None
        else:
            return SimFile(name="file://" + os.path.realpath(path), content=content, size=len(content))

    def _get_stat(self, guest_path, dereference=False):
        guest_path = guest_path.lstrip(self.pathsep)
        path = os.path.join(self.host_path, guest_path)
        try:
            if dereference:
                path = os.path.realpath(path)
            s = os.stat(path)
            return Stat(
                s.st_dev,
                s.st_ino,
                s.st_nlink,
                s.st_mode,
                s.st_uid,
                s.st_gid,
                s.st_rdev,
                s.st_size,
                s.st_blksize,
                s.st_blocks,
                round(s.st_atime),
                s.st_atime_ns,
                round(s.st_mtime),
                s.st_mtime_ns,
                round(s.st_ctime),
                s.st_ctime_ns,
            )
        except OSError:
            return None
