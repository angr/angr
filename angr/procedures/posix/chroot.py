from __future__ import annotations
import os
import angr


class chroot(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument
    """
    Chroot will change the root directory of a file system to a new folder from your current position
    """

    def run(self, file_path):
        size = 0
        while True:
            s_bv = self.state.memory.load(file_path, size)
            newPath = self.state.solver.eval(s_bv, cast_to=bytes)
            newPath = str(newPath)
            if newPath[size : size + 1] == "\\":
                newPath = newPath[2:size]
                break
            size += 1

        if not os.path.exists(newPath):
            return -1

        self.state.fs.mount("/", angr.SimHostFilesystem(newPath))
        return 0
