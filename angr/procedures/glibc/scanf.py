from __future__ import annotations

from angr.procedures.libc.fscanf import fscanf
from angr.procedures.libc.scanf import scanf


class __isoc99_scanf(scanf):
    pass


class __isoc23_scanf(scanf):
    pass


class __isoc99_fscanf(fscanf):
    pass


class __isoc23_fscanf(fscanf):
    pass
