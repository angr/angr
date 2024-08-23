from __future__ import annotations
import angr


class std____throw_bad_cast(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True
    ALT_NAMES = ("std::__throw_bad_cast()",)

    def run(self):
        # FIXME: we need the concept of C++ exceptions to implement this right
        self.exit(1)
