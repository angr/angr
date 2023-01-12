import angr


class uname(angr.SimProcedure):
    def run(self, uname_buf):  # pylint: disable=arguments-differ
        # struct utsname {
        #     char sysname[];    /* Operating system name (e.g., "Linux") */
        #     char nodename[];   /* Name within "some implementation-defined
        #                           network" */
        #     char release[];    /* Operating system release (e.g., "2.6.28") */
        #     char version[];    /* Operating system version */
        #     char machine[];    /* Hardware identifier */
        # };

        off = self._store(uname_buf, b"Linux", 0)
        off += self._store(uname_buf, b"localhost", off)
        off += self._store(uname_buf, b"4.0.0", off)
        off += self._store(uname_buf, b"#1 SMP Mon Jan 01 00:00:00 GMT 1970", off)
        if self.state.arch.bits == 64:
            self._store(uname_buf, b"x86_64", off)
        else:
            self._store(uname_buf, b"x86", off)

        return 0  # success

    def _store(self, uname_buf, val, off):
        self.state.memory.store(uname_buf + off, val + (b"\0" * (65 - len(val))))
        return 65
