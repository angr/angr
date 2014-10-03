import simuvex

######################################
# bind (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.bind")

class bind(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # who even cares? Just return that shit, sure man, we called bind...whatever lol
        l.debug("Yeah man, I totally just called bind (lol)")
        self.ret()

