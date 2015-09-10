from collections import namedtuple

from .plugin import SimStatePlugin
from ..storage.file import SimFile

import os
import simuvex
import logging
l = logging.getLogger('simuvex.plugins.posix')

max_fds = 8192

Stat = namedtuple('Stat', ('st_dev', 'st_ino', 'st_nlink', 'st_mode', 'st_uid',
                           'st_gid', 'st_rdev', 'st_size', 'st_blksize',
                           'st_blocks', 'st_atime', 'st_atimensec', 'st_mtime',
                           'st_mtimensec', 'st_ctime', 'st_ctimensec'))

class SimStateSystem(SimStatePlugin):
    #__slots__ = [ 'maximum_symbolic_syscalls', 'files', 'max_length' ]

    def __init__(self, initialize=True, files=None, concrete_fs=False, chroot=None, sockets=None,
            pcap_backer=None, inetd=False, argv=None, argc=None, environ=None, auxv=None, tls_modules=None,
            fs=None):
        SimStatePlugin.__init__(self)
        self.maximum_symbolic_syscalls = 255
        self.files = { } if files is None else files
        self.max_length = 2 ** 16
        self.sockets = {} if sockets is None else sockets
        self.pcap = None if pcap_backer is None else pcap_backer
        self.pflag = 0 if self.pcap is None else 1
        self.fs = {} if fs is None else fs
        self.argc = argc
        self.argv = argv
        self.environ = environ
        self.auxv = auxv
        self.concrete_fs = concrete_fs
        self.chroot = chroot
        self.tls_modules = tls_modules if tls_modules is not None else {}

        if initialize:
            l.debug("Initializing files...")
            if inetd:
                self.open("inetd", "r")
                self.add_socket(0)
            else:
                self.open("/dev/stdin", "r") # stdin
            self.open("/dev/stdout", "w") # stdout
            self.open("/dev/stderr", "w") # stderr
        else:
            if len(self.files) == 0:
                l.debug("Not initializing files...")

    #to keep track of sockets
    def add_socket(self, fd):
        self.sockets[fd] = self.files[fd]

    #back a file with a pcap
    def back_with_pcap(self, fd):
        #import ipdb;ipdb.set_trace()
        if self.pcap is not None:
            self.get_file(fd).bind_file(self.pcap)

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)
        l.debug("%s setting state to %s", self, state)
        for fd, f in self.files.iteritems():
            l.debug("... file %s with fd %s", f, fd)
            f.set_state(state)

            if self.state is not f.state:
                raise SimError("states somehow differ")

    def open(self, name, mode, preferred_fd=None):
        '''
        open a file

        :param name: name of the file
        :param mode: file operation mode
        :param preferred_fd: assign this fd if it's not already claimed
        '''
        # TODO: speed this up
        fd = None
        if preferred_fd is not None and preferred_fd not in self.files:
            fd = preferred_fd
        else:
            for fd_ in xrange(0, 8192):
                if fd_ not in self.files:
                    fd = fd_
                    break
        if fd is None:
            raise SimPosixError('exhausted file descriptors')

        if name in self.fs:
            # we assume we don't need to copy the file object, the file has been created just for
            # us to use
            f = self.fs[name]
        # if it's a device file we probably don't want to try to read in the entire thing
        elif self.concrete_fs and not os.path.abspath(name).startswith("/dev"):
            # if we're in a chroot update the name
            if self.chroot is not None:
                # this is NOT a secure implementation of chroot, it is only for convenience
                name = self._chrootize(name)

            # create the backing
            backing = SimSymbolicMemory(memory_id="file_%s" % name)
            backing.set_state(self.state)

            # if we're in read mode get the file contents
            if not isinstance(mode, (int, long)):
                mode = self.state.se.any_int(mode)
            if mode == simuvex.storage.file.Flags.O_RDONLY or (mode & simuvex.storage.file.Flags.O_RDWR):
                try:
                    with open(name, "r") as fp:
                        content = fp.read()
                except IOError: # if the file doesn't exist return error
                    return -1
                cbvv = self.state.BVV(content)
                backing.store(0, cbvv)
                f = SimFile(name, mode, content=backing, size=len(content))
            else:
                f = SimFile(name, mode)
        else:
            f = SimFile(name, mode)
        if self.state is not None:
            f.set_state(self.state)

        self.files[fd] = f

        return fd

    def read(self, fd, dst_addr, length):
        # TODO: error handling
        # TODO: symbolic support
        return self.get_file(fd).read(dst_addr, length)

    def read_from(self, fd, length):
        return self.get_file(fd).read_from(length)

    def write(self, fd, content, length):
        # TODO: error handling
        self.get_file(fd).write(content, length)
        return length

    def close(self, fd):
        # TODO: error handling
        # TODO: symbolic support?
        # Ugly hack?

        if self.state.se.symbolic(fd):
            raise SimPosixError("Symbolic fd ?")

        fd = self.state.se.any_int(fd)
        try:
            del self.files[fd]
        except KeyError:
            l.error("Could not close fd 0x%x", fd)

    def fstat(self, fd): #pylint:disable=unused-argument
        # sizes are AMD64-specific for now
        return Stat(self.state.se.BVV(0, 64), # st_dev
                    self.state.se.BVV(0, 64), # st_ino
                    self.state.se.BVV(0, 64), # st_nlink
                    self.state.se.BVV(0, 32), # st_mode
                    self.state.se.BVV(0, 32), # st_uid (lol root)
                    self.state.se.BVV(0, 32), # st_gid
                    self.state.se.BVV(0, 64), # st_rdev
                    self.state.se.BVV(0, 64), # st_size
                    self.state.se.BVV(0, 64), # st_blksize
                    self.state.se.BVV(0, 64), # st_blocks
                    self.state.se.BVV(0, 64), # st_atime
                    self.state.se.BVV(0, 64), # st_atimensec
                    self.state.se.BVV(0, 64), # st_mtime
                    self.state.se.BVV(0, 64), # st_mtimensec
                    self.state.se.BVV(0, 64), # st_ctime
                    self.state.se.BVV(0, 64)) # st_ctimensec

    def seek(self, fd, seek):
        # TODO: symbolic support?
        self.get_file(fd).seek(seek)

    def pos(self, fd):
        # TODO: symbolic support?
        return self.get_file(fd).pos

    def filename_to_fd(self, name):
        # TODO: replace with something better
        for fd, f in self.files.items():
            if f.name == name:
                return fd

        return None

    def copy(self):
        sockets = {}
        files = { fd:f.copy() for fd,f in self.files.iteritems() }
        for f in self.files:
            if f in self.sockets:
                sockets[f] = files[f]

        return SimStateSystem(initialize=False, files=files, concrete_fs=self.concrete_fs, chroot=self.chroot, sockets=sockets, pcap_backer=self.pcap, argv=self.argv, argc=self.argc, environ=self.environ, auxv=self.auxv, tls_modules=self.tls_modules, fs=self.fs)

    def merge(self, others, merge_flag, flag_values):
        all_files = set.union(*(set(o.files.keys()) for o in [ self ] + others))
        all_constraints = [ ]

        merging_occured = False
        for fd in all_files:
            merging_result, constraints = self.get_file(fd).merge([ o.get_file(fd) for o in others ], merge_flag, flag_values)
            merging_occured |= merging_result
            all_constraints += constraints

        return merging_occured, all_constraints

    def widen(self, others, merge_flag, flag_values):
        return self.merge(others, merge_flag, flag_values)

    def dumps(self, fd):
        return self.state.se.any_str(self.get_file(fd).all_bytes())

    def dump(self, fd, filename):
        with open(filename, "w") as f:
            f.write(self.dumps(fd))

    def get_file(self, fd):
        fd = self.state.make_concrete_int(fd)
        if fd not in self.files:
            l.warning("Accessing non-existing file with fd %d. Creating a new file.", fd)
            self.open("tmp_%d" % fd, "wr", preferred_fd=fd)
        return self.files[fd]

    def _chrootize(self, name):
        '''
        take a path and make sure if fits within the chroot
        remove '../', './', and '/' from the beginning of path
        '''
        normalized = os.path.normpath(os.path.abspath(name))

        # if it starts with the chroot after absolution and normalization it's good
        if normalized.startswith(self.chroot):
            return normalized

        normalized = os.path.normpath(name)
        # otherwise we trim the path and append it to the chroot
        while True:
            if normalized.startswith("/"):
                normalized = normalized[1:]
            elif normalized.startswith("./"):
                normalized = normalized[2:]
            elif normalized.startswith("../"):
                normalized = normalized[3:]
            else:
                break

        return os.path.join(self.chroot, normalized)


SimStatePlugin.register_default('posix', SimStateSystem)

from ..plugins.symbolic_memory import SimSymbolicMemory
from ..s_errors import SimPosixError, SimError
