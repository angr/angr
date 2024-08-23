from __future__ import annotations
import angr


class _Unwind_Resume(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self):
        pass
