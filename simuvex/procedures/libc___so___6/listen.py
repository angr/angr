import simuvex

######################################
# listen (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.listen")

class listen(simuvex.SimProcedure):
    def analyze(self):
        # who even cares? Just return that shit, sure man, we called bind...whatever lol
        l.debug("I'm listening. (JK I didn't actually do anything)")
        self.ret()

