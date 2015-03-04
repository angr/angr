from collections import namedtuple

from .plugin import SimStatePlugin
from ..s_file import SimFile
from ..s_pcap import PCAP
from ..s_errors import SimMergeError

import logging
l = logging.getLogger('simuvex.plugins.posix')

max_fds = 8192

Stat = namedtuple('Stat', ('st_dev', 'st_ino', 'st_nlink', 'st_mode', 'st_uid',
                           'st_gid', 'st_rdev', 'st_size', 'st_blksize',
                           'st_blocks', 'st_atime', 'st_atimensec', 'st_mtime',
                           'st_mtimensec', 'st_ctime', 'st_ctimensec')) 

class SimStateSystem(SimStatePlugin):
    #__slots__ = [ 'maximum_symbolic_syscalls', 'files', 'max_length' ]

    def __init__(self, initialize=True, files=None, sockets=None, pcap_backer=None, inetd=False, argv=None, argc=None,
                 environ=None, tls_modules=None):
        SimStatePlugin.__init__(self)
        self.maximum_symbolic_syscalls = 255
        self.files = { } if files is None else files
        self.max_length = 2 ** 16
        self.sockets = {} if sockets is None else sockets
        self.pcap = None if pcap_backer is None else pcap_backer
        self.pflag = 0 if self.pcap is None else 1
        self.argc = argc
        self.argv = argv
        self.environ = environ
        self.tls_modules = tls_modules if tls_modules is not None else {}

        if initialize:
            l.debug("Initializing files...")
            if inetd:
                self.open("inetd", "r")
                self.add_socket(0)
            else:
                self.open("stdin", "r") # stdin
            self.open("stdout", "w") # stdout
            self.open("stderr", "w") # stderr
            #TODO: Fix the temp hack of a tuple - used to determine traffic from us vs traffic to us
            if pcap_backer is not None:
                self.pcap = PCAP(pcap_backer, ('127.0.0.1', 8888))
                if inetd:
                    self.back_with_pcap(0)
        else:
            if len(self.files) == 0:
                l.debug("Not initializing files...")

        #if inetd:
            #import ipdb;ipdb.set_trace()
            #self.close(0)
            #inetfd = self.open("inetd", "w+", 0)

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

        self.files[fd] = SimFile(fd, name, mode)
        if self.state is not None:
            self.files[fd].set_state(self.state)
        return fd

    def read(self, fd, length, pos=None):
        # TODO: error handling
        # TODO: symbolic support
        expr, constraints = self.get_file(fd).read(length, pos)
        self.state.add_constraints(*constraints)
        return expr

    def write(self, fd, content, length, pos=None):
        # TODO: error handling
        self.get_file(fd).write(content, length, pos)
        return length

    def close(self, fd):
        # TODO: error handling
        # TODO: symbolic support?
        del self.files[fd]

    def fstat(self, fd):
        # sizes are AMD64-specific for now
        bvv = lambda val, sz: self.state.se.BVV(val, sz)
        return Stat(bvv(0, 64), # st_dev
                    bvv(0, 64), # st_ino
                    bvv(0, 64), # st_nlink
                    bvv(0, 32), # st_mode
                    bvv(0, 32), # st_uid (lol root)
                    bvv(0, 32), # st_gid
                    bvv(0, 64), # st_rdev
                    bvv(0, 64), # st_size
                    bvv(0, 64), # st_blksize
                    bvv(0, 64), # st_blocks
                    bvv(0, 64), # st_atime
                    bvv(0, 64), # st_atimensec
                    bvv(0, 64), # st_mtime
                    bvv(0, 64), # st_mtimensec
                    bvv(0, 64), # st_ctime
                    bvv(0, 64)) # st_ctimensec

    def seek(self, fd, seek):
        # TODO: symbolic support?
        self.get_file(fd).seek(seek)

    def pos(self, fd):
        # TODO: symbolic support?
        return self.get_file(fd).pos

    def copy(self):
        sockets = {}
        files = { fd:f.copy() for fd,f in self.files.iteritems() }
        for f in self.files:
            if f in self.sockets:
                sockets[f] = files[f]

        return SimStateSystem(initialize=False, files=files, sockets=sockets, pcap_backer=self.pcap, argv=self.argv, argc=self.argc, environ=self.environ, tls_modules=self.tls_modules)

    def merge(self, others, merge_flag, flag_values):
        if len(set(frozenset(o.files.keys()) for o in [ self ] + others)) != 1:
            raise SimMergeError("Unable to merge SimStateSystem with different sets of open files.")

        all_constraints = [ ]

        merging_occured = False
        for fd in self.files:
            merging_result, constraints = self.get_file(fd).merge([ o.files[fd] for o in others ], merge_flag, flag_values)
            merging_occured |= merging_result
            all_constraints += constraints

        return merging_occured, all_constraints

    def dumps(self, fd):
        return self.state.se.any_str(self.get_file(fd).all_bytes())

    def dump(self, fd, filename):
        open(filename, "w").write(self.dumps(fd))

    def get_file(self, fd):
        fd = self.state.make_concrete_int(fd)
        if fd not in self.files:
            l.warning("Accessing non-existing file with fd %d. Creating a new file.", fd)
            self.open("tmp_%d" % fd, "wr", preferred_fd=fd)
        return self.files[fd]

SimStatePlugin.register_default('posix', SimStateSystem)

from ..s_errors import SimPosixError, SimError
