import angr

from ..glibc.__libc_start_main import __libc_start_main

######################################
# exit
######################################

class exit(__libc_start_main):

    NO_RET = True
    def run(self, exit_code):
        self._run_exit_handler()
        self.exit(exit_code)
