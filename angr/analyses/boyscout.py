from __future__ import annotations
import logging
import re
from collections import defaultdict

from archinfo import all_arches
from archinfo.arch_arm import is_arm_arch

from . import Analysis


l = logging.getLogger(name=__name__)


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
        votes = defaultdict(int)

        for arch in all_arches:
            regexes = set()
            if not arch.function_prologs:
                continue
            # TODO: BoyScout does not support Thumb-only / Cortex-M binaries yet.

            for ins_regex in set(arch.function_prologs).union(arch.function_epilogs):
                r = re.compile(ins_regex)
                regexes.add(r)

            for start_, data in self.project.loader.main_object.memory.backers():
                for regex in regexes:
                    # Match them!
                    for mo in regex.finditer(data):
                        position = mo.start() + start_
                        if position % arch.instruction_alignment == 0:
                            if is_arm_arch(arch):
                                votes[("ARM", arch.memory_endness)] += 1
                            else:
                                votes[(arch.name, arch.memory_endness)] += 1

            l.debug("%s %s hits %d times", arch.name, arch.memory_endness, votes[(arch.name, arch.memory_endness)])

        arch_name, endianness, hits = sorted(
            [(k[0], k[1], v) for k, v in votes.items()], key=lambda x: x[2], reverse=True
        )[0]

        if hits < self.cookiesize * 2:
            # this cannot possibly be code
            arch_name = "DATA"
            endianness = ""

        self.arch = arch_name
        self.endianness = endianness
        # Save it as well for debugging
        self.votes = votes

        l.debug("The architecture should be %s with %s", self.arch, self.endianness)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("BoyScout", BoyScout)
