import re
from collections import defaultdict

import simuvex

from ..analysis import Analysis

class BoyScout(Analysis):
    '''
    Try to determine the architecture and endieness of a binary blob
    '''
    def __init__(self):

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

        for arch_name, arch_class in simuvex.Archtectures.items():
            for endianess in ('Iend_LE', 'Iend_BE'):
                arch = arch_class(endianess=endianess)

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
                                votes[(arch_name, endianess)] += 1

        import ipdb; ipdb.set_trace()

        print ""