import re
import logging
from collections import defaultdict

from archinfo import all_arches

from ..analysis import Analysis, register_analysis

l = logging.getLogger("angr.analyses.boyscout")

class BoyScout(Analysis):
    """
    Try to determine the architecture and endieness of a binary blob
    """
    def __init__(self, cookiesize=1):
        self.arch = None
        self.endianness = None
        self.votes = None
        self.cookiesize = cookiesize

        self._reconnoiter()

    def _reconnoiter(self):
        """
        The implementation here is simple - just perform a pattern matching of all different architectures we support,
        and then perform a vote.
        """

        # Retrieve the binary string of main binary
        strides = self.project.loader.main_bin.memory.stride_repr

        votes = defaultdict(int)

        for arch in all_arches:
            regexes = set()
            for ins_regex in set(arch.function_prologs).union(arch.function_epilogs):
                r = re.compile(ins_regex)
                regexes.add(r)

            for start_, _, data in strides:
                for regex in regexes:
                    # Match them!
                    for mo in regex.finditer(data):
                        position = mo.start() + start_
                        if position % arch.instruction_alignment == 0:
                            votes[(arch.name, arch.memory_endness)] += 1

            l.debug("%s %s hits %d times", arch.name, arch.memory_endness,
                    votes[(arch.name, arch.memory_endness)])

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

register_analysis(BoyScout, 'BoyScout')
