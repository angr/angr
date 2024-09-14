from __future__ import annotations
import claripy

import angr


class Redirect(angr.SimProcedure):
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self, redirect_to=None):
        if redirect_to is None:
            raise Exception("Please specify where you wanna jump to.")

        self._custom_name = f"Redirect to 0x{redirect_to:08x}"
        # There is definitely no refs
        self.add_successor(self.state, redirect_to, claripy.true, "Ijk_Boring")
