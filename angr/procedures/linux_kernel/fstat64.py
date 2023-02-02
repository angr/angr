import angr

# these structs can be easily-ish pulled out of qemu/linux-user/syscall_defs.h
# TODO FIXME XXX THESE ARE NOT CORRECT
# we need to actually properly define the data sizes returned from posix.fstat, since they may change from arch to arch


class fstat64(angr.SimProcedure):
    def run(self, fd, stat_buf):  # pylint:disable=arguments-differ
        stat = self.state.posix.fstat(fd)
        # TODO: make arch-neutral
        if self.arch.name == "X86":
            self._store_i386(stat_buf, stat)
        elif self.arch.name == "AMD64":
            self._store_amd64(stat_buf, stat)
        elif self.arch.name == "PPC32":
            self._store_ppc32(stat_buf, stat)
        elif self.arch.name == "MIPS32":
            self._store_mips32(stat_buf, stat)
        elif self.arch.name.startswith("ARM"):
            self._store_arm(stat_buf, stat)
        else:
            raise angr.errors.SimProcedureError("Unsupported fstat64 arch: %s" % self.arch.name)
        return 0

    def _store_arm(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness="Iend_LE")

        store(0x00, stat.st_dev)
        store(0x0C, stat.st_ino)
        store(0x10, stat.st_mode)
        store(0x14, stat.st_nlink)
        store(0x18, stat.st_uid)
        store(0x1C, stat.st_gid)
        store(0x20, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x4C, stat.st_atimensec)
        store(0x50, stat.st_mtime)
        store(0x54, stat.st_mtimensec)
        store(0x58, stat.st_ctime)
        store(0x5C, stat.st_ctimensec)
        store(0x60, stat.st_ino)  # weird verification st_ino

    def _store_i386(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness="Iend_LE")

        store(0x00, stat.st_dev)
        store(0x0C, stat.st_ino)
        store(0x10, stat.st_mode)
        store(0x14, stat.st_nlink)
        store(0x18, stat.st_uid)
        store(0x1C, stat.st_gid)
        store(0x20, stat.st_rdev)
        store(0x2C, stat.st_size)
        store(0x34, stat.st_blksize)
        store(0x38, stat.st_blocks)
        store(0x3C, self.state.solver.BVV(0, 32))  # padding
        store(0x40, stat.st_atime)
        store(0x44, stat.st_atimensec)
        store(0x48, stat.st_mtime)
        store(0x4C, stat.st_mtimensec)
        store(0x50, stat.st_ctime)
        store(0x54, stat.st_ctimensec)
        store(0x5C, stat.st_ino)  # weird verification st_ino

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

    def _store_ppc32(self, stat_buf, stat):
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
        store(0x4C, stat.st_atimensec)
        store(0x50, stat.st_mtime)
        store(0x54, stat.st_mtimensec)
        store(0x58, stat.st_ctime)
        store(0x5C, stat.st_ctimensec)
        store(0x60, self.state.solver.BVV(0, 32))
        store(0x64, self.state.solver.BVV(0, 32))

    def _store_mips32(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness=self.state.arch.memory_endness)

        store(0x00, stat.st_dev)
        store(0x04, self.state.solver.BVV(0, 32 * 3))
        store(0x10, stat.st_ino)
        store(0x18, stat.st_uid)
        store(0x1C, stat.st_gid)
        store(0x20, stat.st_rdev)
        store(0x24, self.state.solver.BVV(0, 32 * 3))
        store(0x30, stat.st_size)
        store(0x38, stat.st_atime)
        store(0x3C, stat.st_atimensec)
        store(0x40, stat.st_mtime)
        store(0x44, stat.st_mtimensec)
        store(0x48, stat.st_ctime)
        store(0x4C, stat.st_ctimensec)
        store(0x50, stat.st_blksize)
        store(0x54, self.state.solver.BVV(0, 32))
        store(0x58, stat.st_blocks)

    def _store_arm_eabi(self, stat_buf, stat):
        def store(offset, val):
            return self.state.memory.store(stat_buf + offset, val, endness=self.state.arch.memory_endness)

        store(0x00, stat.st_dev)
        store(0x02, self.state.solver.BVV(0, 8 * 10))
        store(0x0C, stat.st_ino)
        store(0x10, stat.st_mode)
        store(0x14, stat.st_nlink)
        store(0x18, stat.st_uid)
        store(0x1C, stat.st_gid)
        store(0x20, stat.st_rdev)
        store(0x22, self.state.solver.BVV(0, 8 * 10))
        store(0x2C, stat.st_size)
        store(0x34, stat.st_blksize)
        store(0x38, stat.st_blocks)
        store(0x3C, self.state.solver.BVV(0, 32))
        store(0x40, stat.st_atime)
        store(0x44, stat.st_atimensec)
        store(0x48, stat.st_mtime)
        store(0x4C, stat.st_mtimensec)
        store(0x50, stat.st_ctime)
        store(0x54, stat.st_ctimensec)
        store(0x58, stat.st_ino)
