"""
These procedures implement system calls for the cgc DECREE platform, in a
specific way for tracing.
"""


from .random import FixedRandom
from .receive import FixedInReceive
from .transmit import FixedOutTransmit


TRACER_CGC_SYSCALLS = {'random'  : FixedRandom(display_name='random'),
                       'receive' : FixedInReceive(display_name='receive'),
                       'transmit': FixedOutTransmit(display_name='transmit')}
