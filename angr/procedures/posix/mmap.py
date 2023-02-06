import angr
from ...storage.file import SimFileDescriptor

import logging

l = logging.getLogger(name=__name__)


PROT_READ = 0x1  #    /* Page can be read.  */
PROT_WRITE = 0x2  #    /* Page can be written.  */
PROT_EXEC = 0x4  #    /* Page can be executed.  */
PROT_NONE = 0x0  #    /* Page can not be accessed.  */
MAP_SHARED = 0x01  #    /* Share changes.  */
MAP_PRIVATE = 0x02  #    /* Changes are private.  */
MAP_ANONYMOUS = 0x20  #    /* Don't use a file.  */
MAP_FIXED = 0x10  #    /* Interpret addr exactly.  */


class mmap(angr.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset):  # pylint:disable=arguments-differ,unused-argument
        # if self.state.solver.symbolic(flags) or self.state.solver.eval(flags) != 0x22:
        #   raise Exception("mmap with other than MAP_PRIVATE|MAP_ANONYMOUS unsupported")
        l.debug("mmap(%s, %s, %s, %s, %s, %s) = ...", addr, length, prot, flags, fd, offset)

        #
        # File descriptor sanity check
        #
        sim_fd = None
        if self.state.solver.is_false(fd[31:0] == -1):
            if self.state.solver.symbolic(fd):
                raise angr.errors.SimPosixError("Can't map a symbolic file descriptor!!")
            if self.state.solver.symbolic(offset):
                raise angr.errors.SimPosixError("Can't map with a symbolic offset!!")
            sim_fd = self.state.posix.get_fd(fd)
            if sim_fd is None:
                l.warning("Trying to map a non-exsitent fd")
                return -1
            if not isinstance(sim_fd, SimFileDescriptor) or sim_fd.file is None:
                l.warning("Trying to map fd not supporting mmap (maybe a SimFileDescriptorDuplex?)")
                return -1

        #
        # Length
        #

        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > self.state.libc.max_variable_size:
                l.warning(
                    "mmap size requested of %d exceeds libc.max_variable_size. Using size %d instead.",
                    size,
                    self.state.libc.max_variable_size,
                )
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(length)

        #
        # Addr
        #

        # Not handling symbolic addr for now
        addrs = self.state.solver.eval_upto(addr, 2)
        if len(addrs) == 2:
            err = "Cannot handle symbolic addr argument for mmap."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        addr = addrs[0]

        # Call is asking for system to provide an address
        if addr == 0:
            addr = self.allocate_memory(size)

        #
        # Flags
        #

        # Only want concrete flags
        flags = self.state.solver.eval_upto(flags, 2)

        if len(flags) == 2:
            err = "Cannot handle symbolic flags argument for mmap."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        flags = flags[0]

        # Sanity check. All mmap must have exactly one of MAP_SHARED or MAP_PRIVATE
        if (flags & MAP_SHARED and flags & MAP_PRIVATE) or flags & (MAP_SHARED | MAP_PRIVATE) == 0:
            l.debug("... = -1 (bad flags)")
            return self.state.solver.BVV(-1, self.state.arch.bits)

        # Do region mapping
        while True:
            try:
                self.state.memory.map_region(addr, size, prot[2:0], init_zero=bool(flags & MAP_ANONYMOUS))
                l.debug("... = %#x", addr)
                break

            except angr.SimMemoryError:
                # This page is already mapped

                if flags & MAP_FIXED:
                    l.debug("... = -1 (MAP_FIXED failure)")
                    return self.state.solver.BVV(-1, self.state.arch.bits)

                # Can't give you that address. Find a different one and loop back around to try again.
                addr = self.allocate_memory(size)

        # If the mapping comes with a file descriptor
        if sim_fd:
            if not sim_fd.file.seekable:
                raise angr.errors.SimPosixError("Only support seekable SimFile at the moment.")

            prot = self.state.solver.eval_exact(prot, 1)[0]

            if prot & PROT_WRITE:
                l.warning("Trying to map a file descriptor backed by a file")
                l.warning("Updates to the mapping are not carried through to the underlying file")

            # read data
            saved_pos = sim_fd.tell()
            sim_fd.seek(self.state.solver.eval(offset), whence="start")
            data, _ = sim_fd.read_data(size)
            sim_fd.seek(saved_pos, whence="start")
            self.state.memory.store(addr, data)

        return addr

    def allocate_memory(self, size):
        addr = self.state.heap.mmap_base
        new_base = addr + size

        if new_base & 0xFFF:
            new_base = (new_base & ~0xFFF) + 0x1000

        self.state.heap.mmap_base = new_base

        return addr
