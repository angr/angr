import claripy
import angr
from angr.sim_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("angr.procedures.libc.strlen")

class strlen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len

        if self.state.mode == 'static':

            self.max_null_index = [  ]

            # Make sure to convert s to ValueSet
            s_list = self.state.memory.normalize_address(s, convert_to_valueset=True)

            length = self.state.se.ESI(self.state.arch.bits)
            for s_ptr in s_list:

                r, c, i = self.state.memory.find(s, self.state.se.BVV(0, 8), max_str_len, max_symbolic_bytes=max_symbolic_bytes)

                self.max_null_index = max(self.max_null_index + i)

                # Convert r to the same region as s
                r_list = self.state.memory.normalize_address(r, convert_to_valueset=True, target_region=s_ptr._model_vsa.regions.keys()[0])

                for r_ptr in r_list:
                    length = length.union(r_ptr - s_ptr)

            return length

        else:
            search_len = max_str_len
            r, c, i = self.state.memory.find(s, self.state.se.BVV(0, 8), search_len, max_symbolic_bytes=max_symbolic_bytes)

            # try doubling the search len and searching again
            while all(con.is_false() for con in c):
                search_len *= 2
                r, c, i = self.state.memory.find(s, self.state.se.BVV(0, 8), search_len, max_symbolic_bytes=max_symbolic_bytes)
                # stop searching after some reasonable limit
                if search_len > 0x10000:
                    raise angr.SimMemoryLimitError("strlen hit limit of 0x10000")

            self.max_null_index = max(i)
            self.state.add_constraints(*c)
            return r - s
