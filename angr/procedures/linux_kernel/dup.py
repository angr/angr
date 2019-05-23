import angr
from angr.sim_type import SimTypeInt, SimTypeFd
from angr.state_plugins import SimSystemPosix

##################################
# dup
##################################


class dup(angr.SimProcedure):  #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, oldfd): # pylint:disable=arguments-differ
        self.argument_types = {0: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        if oldfd not in self.state.posix.fd.keys():
            return SimSystemPosix.EBADF

        # The new fd gets the lowest free number, so we search
        newfd = len(self.state.posix.fd.keys()) # e.g. '3' for [0, 1, 2]
        for i, fd in enumerate(self.state.posix.fd.keys()):
            if i != fd: # "Free" slot in keys
                newfd = i
        
        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd

class dup2(angr.SimProcedure):

    def run(self, oldfd, newfd):# pylint:disable=arguments-differ
        self.argument_types = {0: SimTypeInt(32, True),
                               1: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        if oldfd not in self.state.posix.fd.keys():
            return SimSystemPosix.EBADF

        if oldfd == newfd:
            return newfd

        if newfd >= 4096 or newfd < 0:  # ulimits 4096 is the default limit.
            return SimSystemPosix.EBADF

        # copy old_fd to new_fd so they point to the same FD
        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd

class dup3(angr.SimProcedure):

    def run(self, oldfd, newfd, flags):# pylint:disable=arguments-differ
        self.argument_types = {0: SimTypeInt(32, True),
                               1: SimTypeInt(32, True),
                               2: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        if oldfd not in self.state.posix.fd.keys():
            return SimSystemPosix.EBADF

        if oldfd == newfd:
            return newfd

        if newfd >= 4096 or newfd < 0:  # ulimits 4096 is the default limit.
            return SimSystemPosix.EBADF

        # copy old_fd to new_fd so they point to the same FD
        self.state.posix.fd[newfd] = self.state.posix.fd[oldfd]
        return newfd