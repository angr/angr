import simuvex
from ..libc____so____6.__libc_start_main import __libc_start_main

######################################
# __uClibc_main
######################################

class __uClibc_main(simuvex.SimProcedure):
    ADDS_EXITS = True

    self.__init__ = __libc_start_main.__init__

