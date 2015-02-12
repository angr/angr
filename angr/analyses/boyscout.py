import re
import logging
from collections import defaultdict

import simuvex

from ..analysis import Analysis

l = logging.getLogger("angr.analyses.boyscout")

class BoyScout(Analysis):
    '''
    Try to determine the architecture and endieness of a binary blob
    '''
    def __init__(self):
        self.arch = None
        self.endianness = None

        self._reconnoiter()

    def _reconnoiter(self):
        '''
        The implementation here is simple - just perform a pattern matching of all different architectures we support,
        and then perform a vote.
        :return: None
        '''

        # Retrieve the binary string of main binary
        strides = self._p.main_binary._memory.stride_repr

        votes = defaultdict(int)

        for arch_name, arch_class in simuvex.Architectures.items():
            for endianness in ('Iend_LE', 'Iend_BE'):
                l.debug("Checking %s %s", arch_name, endianness)
                arch = arch_class(endness=endianness)

                # Precompile all regexes
                regexes = set()
                for ins_regex in arch.function_prologs:
                    r = re.compile(ins_regex)
                    regexes.add(r)

                for start_, end_, bytes in strides:
                    for regex in regexes:
                        # Match them!
                        for mo in regex.finditer(bytes):
                            position = mo.start() + start_
                            if position % self._p.arch.instruction_alignment == 0:
                                votes[(arch_name, endianness)] += 1

                l.debug("%s %s hits %d times", arch_name, endianness, votes[(arch_name, endianness)])

        arch_name, endianness, hits = sorted([(k[0], k[1], v) for k, v in votes.iteritems()], key=lambda x: x[2], reverse=True)[0]

        self.arch = arch_name
        self.endianness = endianness

        l.debug("The architecture should be %s with %s", self.arch, self.endianness)
