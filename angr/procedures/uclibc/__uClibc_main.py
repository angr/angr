from ..glibc.__libc_start_main import __libc_start_main as fucker


class __uClibc_main(fucker):
    # pylint: disable=missing-class-docstring
    NO_RET = True

    # This is called "fucker" cause otherwise the double underscores cause
    # python to name-mangle and everything gets fucked.
