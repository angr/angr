
from ..glibc.__libc_start_main import __libc_start_main as fucker

######################################
# __uClibc_main
######################################
class __uClibc_main(fucker):
    ADDS_EXITS = True
    NO_RET = True

    # This is called "fucker" cause otherwise the double underscores cause
    # python to name-mangle and everything gets fucked.
