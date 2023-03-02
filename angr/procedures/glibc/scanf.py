from angr.procedures.libc.fscanf import fscanf
from angr.procedures.libc.scanf import scanf


class __isoc99_scanf(scanf):
    pass


class __isoc99_fscanf(fscanf):
    pass
