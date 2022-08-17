import angr
import claripy

from ..cgc.random import random as orig_random


class random(orig_random):
    #pylint:disable=arguments-differ

    def run(self, buf, count, rnd_bytes, concrete_data=None):
        """
        This a passthrough to the CGC version which pretty much implements same and more. Removing this requires
        regenerating angrop caches used by rex and so this is being retained
        """

        return super(random, self).run(buf, count, rnd_bytes, concrete_data)
