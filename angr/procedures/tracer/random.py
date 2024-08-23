from __future__ import annotations
from ..cgc.random import random as orig_random


class random(orig_random):
    """
    This a passthrough to the CGC version. Removing this requires regenerating angrop caches used by rex and so this is
    being retained.
    """
