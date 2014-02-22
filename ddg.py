from collections import defaultdict
from simuvex.s_ref import RefTypes, SimMemRead, SimMemWrite
from simuvex import SimIRSB, SimProcedure
import logging

l = logging.getLogger("angr.ddg")
l.setLevel(logging.DEBUG)

class DDG(object):
    def __init__(self, cfg, entry_point):
        self._cfg = cfg
        self._entry_point = entry_point

        self._ddg = defaultdict(lambda:defaultdict(set))

    def debug_print(self):
        print self._ddg

    def construct(self):
        worklist = set()
        # Added the first container into the worklist
        initial_container = AddrToRefContainer(self._cfg.get_irsb((None, None, self._entry_point)), defaultdict(set))
        worklist.add(initial_container)
        analyzed_runs = set()
        analyzed_containers = {}
        while len(worklist) > 0:
            container = worklist.pop()
            run = container.run
            # If we updated our addr_to_ref map, we should set redo_flag to
            # True, then all of its successors will be reanalyzed
            redo_flag = container.reanalyze_successors
            if isinstance(run, SimIRSB):
                irsb = run
                l.debug("Running %s", irsb)
                # Simulate the execution of this irsb.
                # For MemWriteRef, fill the addr_to_ref dict with every single concretizable
                # memory address, and ignore those symbolic ones
                # For MemReadRef, get its related MemoryWriteRef from our dict
                # TODO: Is it possible to trace memory operations even if the memory is not
                # concretizable itself?
                statements = irsb.statements
                # if run.addr == 0xff84cb8c:
                #     import ipdb
                #     ipdb.set_trace()
                for i in range(len(statements)):
                    stmt = statements[i]
                    refs = stmt.refs
                    if len(refs) > 0:
                        real_ref = refs[len(refs) - 1]
                        if type(real_ref) == SimMemWrite:
                            addr = real_ref.addr
                            if not addr.is_symbolic():
                                concrete_addr = addr.any()
                                tpl = (irsb, i)
                                if tpl not in container.addr_to_ref[concrete_addr]:
                                    container.addr_to_ref[concrete_addr].add((irsb, i))
                                    redo_flag = True
                            else:
                                # We ignore them for now
                                pass
                    for ref in refs:
                        if type(ref) == SimMemRead:
                            addr = ref.addr
                            if not addr.is_symbolic():
                                concrete_addr = addr.any()
                                if concrete_addr in container.addr_to_ref:
                                    self._ddg[irsb][i] |= (container.addr_to_ref[concrete_addr])
                                else:
                                    # raise Exception("wtf...")
                                    pass
            elif isinstance(run, SimProcedure):
                sim_proc = run
                l.debug("Running %s", sim_proc)
                refs = sim_proc.refs()
                for ref in refs:
                    if isinstance(ref, SimMemRead):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            concrete_addr = addr.any()
                            # print sim_proc
                            # print "0x%08x" % concrete_addr
                            if concrete_addr in container.addr_to_ref:
                                self._ddg[sim_proc][-1] |= (container.addr_to_ref[concrete_addr])
                                # print "In list"
                    elif isinstance(ref, SimMemWrite):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            concrete_addr = addr.any()
                            tpl = (sim_proc, -1)
                            if tpl not in container.addr_to_ref[concrete_addr]:
                                container.addr_to_ref[concrete_addr].add((sim_proc, -1))
                                redo_flag = True

            analyzed_runs.add(run)
            analyzed_containers[run] = container

            # Get successors of the current irsb,
            successors = self._cfg.get_successors(run)
            if redo_flag:
                for successor in successors:
                    if successor in analyzed_runs:
                        analyzed_runs.remove(successor)
            # ... and add them to our worklist with a shallow copy of the addr_to_ref dict
            for successor in successors:
                if successor not in analyzed_runs:
                    # Let's see if there is any changes in the addresses dict
                    new_addr_to_ref = container.addr_to_ref.copy()
                    new_container = None
                    if successor in analyzed_containers:
                        old_container = analyzed_containers[successor]
                        new_container = AddrToRefContainer(successor, old_container.addr_to_ref, reanalyze_successors=True)
                        if not new_container.combine(container.addr_to_ref):
                            # There isn't any new addresses
                            continue
                    if new_container is None:
                        new_container = AddrToRefContainer(successor, container.addr_to_ref.copy())
                    worklist.add(new_container)


class AddrToRefContainer(object):
    def __init__(self, run, addr_to_ref, reanalyze_successors=False):
        self.run = run
        self.addr_to_ref = addr_to_ref
        self.reanalyze_successors = reanalyze_successors

    def combine(self, new_addr_to_ref):
        altered = False
        for k, v in new_addr_to_ref.items():
            if k not in self.addr_to_ref:
                self.addr_to_ref[k] = v.copy()
                altered = True
            else:
                if not v.issubset(self.addr_to_ref[k]):
                    altered = True
                    self.addr_to_ref[k] |= v
        return altered
