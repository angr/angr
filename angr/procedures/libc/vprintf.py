from __future__ import annotations

import logging

import angr
from angr.misc.ux import once

l = logging.getLogger(name=__name__)


def unmodeled_format_length(proc: angr.SimProcedure, fmt):
    """
    Return strlen(fmt) for a v*printf procedure, which copies its format as is: angr does not model va_list, so
    conversions are not substituted. Warns once per procedure when a concrete format contains a '%'.
    """
    strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
    length = proc.inline_call(strlen, fmt).ret_expr
    if not length.symbolic and (n := proc.state.solver.eval(length)):
        data = proc.state.memory.load(fmt, n, inspect=False, disable_actions=True)
        if b"%" in proc.state.solver.eval(data, cast_to=bytes) and once(f"vprintf-unmodeled-{proc.display_name}"):
            l.warning("%s: va_list is not modeled, so the format is output without %%-substitution", proc.display_name)
    return length


def as_return(proc: angr.SimProcedure, value):
    """Fit a length to the procedure's return type: glibc declares the v*printf family as returning int."""
    ret_ty = proc.prototype.returnty if proc.prototype is not None else None
    bits = ret_ty.size if ret_ty is not None and ret_ty.size is not None else value.size()
    if bits < value.size():
        return value[bits - 1 : 0]
    return value.zero_extend(bits - value.size()) if bits > value.size() else value


class vprintf(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fmt, ap):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1
        length = unmodeled_format_length(self, fmt)
        stdout.write(fmt, length)
        return as_return(self, length)


class __vprintf_chk(vprintf):
    def run(self, flag, fmt, ap):  # type:ignore[reportIncompatibleMethodOverride] # pylint:disable=arguments-differ,unused-argument
        return super().run(fmt, ap)
