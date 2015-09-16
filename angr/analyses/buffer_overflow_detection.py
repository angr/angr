import logging
import os.path
import pickle
from collections import namedtuple

from ..analysis import Analysis, register_analysis

STACKFRAME_PREFIX = "stack_"
ARRAY_SIZE_LBOUND = 8  # Number of bytes that are still not regarded as an array

l = logging.getLogger(name="angr.buffer")

class Overlap(namedtuple("Overlap",
                         'offset, size, boundary, state, aloc, block, statement, stackframe, out_of_frame, instruction')):
    # Immutable namedtuple containing info about the Overlap.
    def __new__(cls, aloc, seg, stackframe, state, boundary):
        return super(Overlap, cls).__new__(cls, seg.offset, seg.size, boundary, state, aloc, aloc.basicblock_key,
                                           aloc.statement_id, stackframe, seg.offset + seg.size > 0,
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
            all_segments = ((a, s) for a in stackframe.alocs.values() for s in a._segment_list)
            segs = sorted(all_segments, key=lambda (_, seg): seg.offset)

            for idx, (aloc, seg) in enumerate(segs):
                if seg.size > ARRAY_SIZE_LBOUND:  # variable <= 64 bit: unlikely to be an array.
                    boundary = 0  # Offsets are negative
                    for (_, seg2) in segs[idx:]:
                        if seg2.offset != seg.offset:
                            boundary = seg2.offset
                            break

                    if seg.offset + seg.size > boundary:  # TODO: Is this off by 1?
                        overlap = Overlap(aloc, seg, stackframe, state, boundary)
                        l.info("Found overlap: " + str(overlap))
                        found.append(overlap)

    return found

class BufferOverflowDetection(Analysis):
    """
    This class looks for overlapping buffers on the stack and buffer that exceed the stackframe
    """
    def process_function(self, f, interfunction_level):
        interfunction_level = self._interfunction_level if interfunction_level is None else interfunction_level

        with self._resilience():
            self.vfg._construct(f, interfunction_level=interfunction_level)
            self.seeker._construct(func_start=f)

        self.finished_functions.add(f)

    def __init__(self, cfg=None, functions=None):
        """
        This class looks for overlapping buffers on the stack and buffer that exceed the stackframe.
        Exceeding a stackframe is very likely a leak, overlapping buffers might in rare cases be a reused stack region
        :return: a dict containing a list of occuring overflows for every instruction. Example:
        {'0x4004f0:19': [Overlap[..., Offset: -0x58, ...], Overlap[..., Offset:-0x50, ...]]}
        found the same overlap in two possible states, caused by instruction 19 in basic block 0x4004f0.
        """

        self.result = {}
        self._cfg = cfg

        all_functions = functions

        if not all_functions:
            self._cfg = cfg if cfg else self.project.analyses.CFG()
            all_functions = self._cfg.function_manager.functions

        self.vfgs = {}

        for func in all_functions:
            if self.project.is_hooked(func):
                continue
            # Create one VFG for every function in the binary
            vfg = self.project.analyses.VFG(cfg=self._cfg, function_start=func, interfunction_level=3, context_sensitivity_level=2)
            self.vfgs[func] = vfg
            for overlap in process_vfg(vfg):
                if overlap.instruction not in self.result:
                    self.result[overlap.instruction] = []
                self.result[overlap.instruction].append(overlap)

register_analysis(BufferOverflowDetection, 'BufferOverflowDetection')
