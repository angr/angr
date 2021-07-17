import logging

import angr

l = logging.getLogger(name=__name__)

######################################
# setlocale
######################################

class setlocale(angr.SimProcedure):
    #pylint:disable=arguments-differ,missing-class-docstring

    def run(self, category, locale):
        #pylint:disable=unused-argument
        # A stub for setlocale that does not do anything yet.
        l.warning("Executing setlocale SimProcedure which does nothing. Unhook to run actual libc code.")
