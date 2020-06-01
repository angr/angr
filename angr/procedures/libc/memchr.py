import angr
import logging

l = logging.getLogger(name=__name__)


class memchr(angr.SimProcedure):
    # change from strncmp, only can deal with single valued
    # pylint:disable=arguments-differ

    def run(self, a_addr, b, limit):  # pylint:disable=arguments-differ

        concrete_run = False
        if self.state.solver.single_valued(limit):
            maxlen = self.state.solver.eval(limit)
            concrete_run = True

        if maxlen == 0:
            # return NULL
            return self.state.solver.BVV(0, self.state.arch.bits)

        # the string bytes
        a_bytes = self.state.memory.load(a_addr, maxlen, endness='Iend_BE')

        if self.state.solver.single_valued(b):
            b_conc = self.state.solver.eval(b)

            for i in range(maxlen):
                l.debug("Processing byte %d", i)
                maxbit = (maxlen-i)*8
                a_byte = a_bytes[maxbit-1:maxbit-8]

                if concrete_run and self.state.solver.single_valued(a_byte):
                    a_conc = self.state.solver.eval(a_byte)
                    if a_conc == b_conc:
                        l.debug(
                            "... found matched concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                        return a_addr + self.state.solver.BVV(i, self.state.arch.bits)
                else:
                    concrete_run = False

        # default return NULL
        return self.state.solver.BVV(0, self.state.arch.bits)
