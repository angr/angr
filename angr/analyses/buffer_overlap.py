import logging

from collections import namedtuple
from ..analysis import Analysis
from .cfg import CFG

STACKFRAME_PREFIX = "stack_"
ARRAY_SIZE_LBOUND = 8  # Number of bytes that are still not regarded as an array

l = logging.getLogger(name="angr.buffer")
# l.setLevel(logging.DEBUG)

class Overlap(namedtuple("Overlap",
                         'offset, size, boundary, state, aloc, block, statement, stackframe, out_of_frame, instruction')):
    # Immutable namedtuple containing info about the Overlap.
    def __new__(cls, aloc, stackframe, state, boundary):
        return super(Overlap, cls).__new__(cls, aloc.offset, aloc.size, boundary, state, aloc, aloc.basicblock_key,
                                           aloc.statement_id, stackframe, aloc.offset + aloc.size > 0,
                                           "0x%x:%d" % (aloc.basicblock_key, aloc.statement_id))

    def __unicode__(self):
        return u"Overlap[Stackframe %s, Offset: -0x%x, Size: %d, OutOfFrame: %r, Block: 0x%x, Statement: %d]" % (
            self.stackframe.id, - self.offset, self.size, self.out_of_frame, self.block, self.statement)

    def __repr__(self):
        return unicode(self).encode('utf-8')


def process_vfg(vfg):
    found = []

    for state in vfg.final_states:
        regions = state.memory.regions
        stackframes = [v for k, v in regions.iteritems() if k.startswith(STACKFRAME_PREFIX)]
        if len(stackframes) == 0:
            l.info("No stackframe found in state %s. Skipping.", str(state))
        for stackframe in stackframes:  # Should usually be 1 anyway.
            l.debug("Processing stackframe %s in %s", str(stackframe), str(state))
            alocs = sorted(stackframe.alocs.values(), key=lambda x: x.offset)

            for idx, aloc in enumerate(alocs):
                if aloc.size > ARRAY_SIZE_LBOUND:  # variable <= 64 bit: unlikely to be an array.
                    boundary = 0  # Offsets are negative
                    for aloc2 in alocs[idx:]:
                        if aloc2.offset != aloc.offset:
                            boundary = aloc2.offset
                            break

                    if aloc.offset + aloc.size > boundary:  # TODO: Is this off by 1?
                        overlap = Overlap(aloc, stackframe, state, boundary)
                        l.info("Found overlap: " + str(overlap))
                        found.append(overlap)

    return found


class BufferOverlap(Analysis):
    """
    This class looks for overlapping buffers on the stack and buffer that exceed the stackframe
    """
    def process_function(self, f, interfunction_level):
        interfunction_level = self._interfunction_level if interfunction_level is None else interfunction_level

        with self._resilience():
            self.vfg._construct(f, interfunction_level=interfunction_level)
            self.seeker._construct(func_start=f)

        self.finished_functions.add(f)

    def __init__(self):
        """
        This class looks for overlapping buffers on the stack and buffer that exceed the stackframe.
        Exceeding a stackframe is very likely a leak, overlapping buffers might in rare cases be a reused stack region
        :return: a dict containing a list of occuring overflows for every instruction. Example:
        {'0x4004f0:19': [Overlap[..., Offset: -0x58, ...], Overlap[..., Offset:-0x50, ...]]}
        found the same overlap in two possible states, caused by instruction 19 in basic block 0x4004f0.
        """
        self._cfg = self._p.results.CFG
        self.result = {}

        for func in self._cfg.function_manager.functions:
            # Create one VFG for every function in the binary
            vfg = self._p.analyses.VFG(function_start=func, interfunction_level=3, context_sensitivity_level=2)
            for overlap in process_vfg(vfg):
                if overlap.instruction not in self.result:
                    self.result[overlap.instruction] = []
                self.result[overlap.instruction].append(overlap)
