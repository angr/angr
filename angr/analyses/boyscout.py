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
    def __init__(self, cookiesize=1):
        self.arch = None
        self.endianness = None
        self.cookiesize = cookiesize

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

            # TODO: We should move this part into simuvex
            endianness_set = ('Iend_LE', 'Iend_BE')
            if arch_name in ('X86', 'AMD64'):
                endianness_set = ('Iend_LE', )

            for endianness in endianness_set:
                l.debug("Checking %s %s", arch_name, endianness)
                arch = arch_class(endness=endianness)

                # Precompile all regexes
                regexes = set()
                for ins_regex in arch.function_prologs.union(arch.function_epilogs):
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

        if hits < self.cookiesize * 2:
        # this cannot possibly be code
            arch_name = "DATA"
            endianness = ""

        self.arch = arch_name
        self.endianness = endianness
        # Save it as well for debugging
        self.votes = votes

        l.debug("The architecture should be %s with %s", self.arch, self.endianness)
