from __future__ import annotations
from angr.procedures.libc.scanf import scanf
from angr.procedures.libc.fscanf import fscanf


class __isoc99_scanf(scanf):
    pass


class __isoc99_fscanf(fscanf):
    pass
