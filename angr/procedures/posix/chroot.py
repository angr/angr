from __future__ import annotations

import logging
import stat

import angr
from angr.state_plugins.filesystem import SimHostFilesystem

l = logging.getLogger(name=__name__)


class chroot(angr.SimProcedure):
    # pylint:disable=arguments-differ
    """
    Changes the root directory of the emulated filesystem (``state.fs``) to the given path.

    The new root is resolved inside the filesystem the state already has, so this can only narrow what the guest is
    able to reach.
    """

    def run(self, path_addr):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        p_strlen = self.inline_call(strlen, path_addr)
        if p_strlen.max_null_index == 0:
            return self.state.libc.ret_errno("ENOENT")

        p_expr = self.state.memory.load(path_addr, p_strlen.max_null_index, endness="Iend_BE")
        if self.state.solver.symbolic(p_expr):
            l.warning("chroot() was called with a symbolic path. Concretizing it.")
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        mountpoint, chunks = self.state.fs.get_mountpoint(path)
        if isinstance(mountpoint, SimHostFilesystem):
            # the host can tell us whether this is really a directory
            guest_path = mountpoint._join_chunks(  # pylint:disable=protected-access
                [chunk.decode(errors="surrogateescape") for chunk in chunks]
            )
            host_stat = mountpoint._get_stat(guest_path, dereference=True)  # pylint:disable=protected-access
            if host_stat is None:
                return self.state.libc.ret_errno("ENOENT")
            if not stat.S_ISDIR(host_stat.st_mode):
                return self.state.libc.ret_errno("ENOTDIR")
            l.warning(
                "chroot(%r) is changing the root to a directory of the host filesystem mounted at %r. Everything "
                "under it remains reachable by the guest.",
                path,
                mountpoint.host_path,
            )
        elif self.state.fs.get(path) is not None:
            # the path names a regular file
            return self.state.libc.ret_errno("ENOTDIR")

        self.state.fs.chroot(path)
        return 0
