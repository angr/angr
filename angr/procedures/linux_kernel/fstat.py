import angr

# TODO see comment in fstat64


class fstat(angr.SimProcedure):
    def run(self, fd, stat_buf):
        stat = self.state.posix.fstat(fd)
        if self.state.arch.name == "AMD64":
            self._store_amd64(stat_buf, stat)
        elif self.state.arch.name == "PPC64":
            self._store_ppc64(stat_buf, stat)
        elif self.state.arch.name == "MIPS64":
            self._store_mips64(stat_buf, stat)
        elif self.state.arch.name == "AARCH64":
            self._store_aarch64(stat_buf, stat)
        else:
            raise angr.errors.SimProcedureError("unsupported fstat arch: %s" % self.state.arch)
        return 0

    def _store_amd64(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness="Iend_LE")

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_mode)
        store(0x18, stat.st_nlink)
        store(0x1C, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x24, self.state.solver.BVV(0, 32))
        store(0x28, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x50, stat.st_atimensec)
        store(0x58, stat.st_mtime)
        store(0x60, stat.st_mtimensec)
        store(0x68, stat.st_ctime)
        store(0x70, stat.st_ctimensec)
        store(0x78, self.state.solver.BVV(0, 64))
        store(0x80, self.state.solver.BVV(0, 64))
        store(0x88, self.state.solver.BVV(0, 64))

        # return struct.pack('<QQQLLLxxxxQqqqQqQqQxxxxxxxxxxxxxxxxxxxxxxxx',
        #                    stat.st_dev,
        #                    stat.st_ino,
        #                    stat.st_nlink,
        #                    stat.st_mode,
        #                    stat.st_uid,
        #                    stat.st_gid,
        #                    stat.st_rdev,
        #                    stat.st_size,
        #                    stat.st_blksize,
        #                    stat.st_blocks,
        #                    stat.st_atime,
        #                    stat.st_atimensec,
        #                    stat.st_mtime,
        #                    stat.st_mtimesec,
        #                    stat.st_ctime,
        #                    state.st_ctimensec)

    def _store_ppc64(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness=self.state.arch.memory_endness)

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_nlink)
        store(0x18, stat.st_mode)
        store(0x1C, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x28, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x50, stat.st_atimensec)
        store(0x58, stat.st_mtime)
        store(0x60, stat.st_mtimensec)
        store(0x68, stat.st_ctime)
        store(0x70, stat.st_ctimensec)
        store(0x78, self.state.solver.BVV(0, 64))
        store(0x80, self.state.solver.BVV(0, 64))
        store(0x88, self.state.solver.BVV(0, 64))

    def _store_mips64(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness=self.state.arch.memory_endness)

        store(0x00, stat.st_dev)
        store(0x04, self.state.solver.BVV(0, 32 * 3))
        store(0x10, stat.st_ino)
        store(0x18, stat.st_mode)
        store(0x1C, stat.st_nlink)
        store(0x20, stat.st_uid)
        store(0x24, stat.st_gid)
        store(0x28, stat.st_rdev)
        store(0x2C, self.state.solver.BVV(0, 32 * 3))
        store(0x38, stat.st_size)
        store(0x40, stat.st_atime)
        store(0x44, stat.st_atimensec)
        store(0x48, stat.st_mtime)
        store(0x4C, stat.st_mtimensec)
        store(0x50, stat.st_ctime)
        store(0x54, stat.st_ctimensec)
        store(0x58, stat.st_blksize)
        store(0x5C, self.state.solver.BVV(0, 32))
        store(0x60, stat.st_blocks)

    def _store_aarch64(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness=self.state.arch.memory_endness)

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_mode)
        store(0x14, stat.st_nlink)
        store(0x18, stat.st_uid)
        store(0x1C, stat.st_gid)
        store(0x20, stat.st_rdev)
        store(0x28, self.state.solver.BVV(0, 64))
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x3C, self.state.solver.BVV(0, 32))
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x50, stat.st_atimensec)
        store(0x58, stat.st_mtime)
        store(0x60, stat.st_mtimensec)
        store(0x68, stat.st_ctime)
        store(0x70, stat.st_ctimensec)
        store(0x78, self.state.solver.BVV(0, 64))
