import simuvex

class fstat(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, fd, stat_buf):
        stat = self.state.posix.fstat(fd)
        # TODO: make arch-neutral
        self._store_amd64(stat_buf, stat)
        return self.state.se.BVV(0, 64) # success

    def _store_amd64(self, stat_buf, stat):
        store = lambda offset, val: self.state.memory.store(stat_buf + offset, val)

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_nlink)
        store(0x18, stat.st_mode)
        store(0x1c, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x24, self.state.se.BVV(0, 32))
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
        store(0x78, self.state.se.BVV(0, 64))
        store(0x80, self.state.se.BVV(0, 64))
        store(0x88, self.state.se.BVV(0, 64))

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
