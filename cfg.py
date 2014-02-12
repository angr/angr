import networkx
import sys
import logging
import simuvex
import angr
from .translate import translate_bytes

l = logging.getLogger(name="sliceit.s_cfg")
l.setLevel(logging.DEBUG)


class CFG(object):

    def __init__(self):
        self.cfg = networkx.DiGraph()
        self.bbl_dict = None

    # Construct the CFG from an angr. binary object
    def construct(self, binary, project):
        # Re-create the DiGraph
        self.cfg = networkx.DiGraph()

        # Traverse all the IRSBs, and put them to a dict
        # It's actually a multi-dict, as each SIRSB might have different states
        # on different call predicates
        self.bbl_dict = {}
        traced_sim_blocks = set()
        entry_point = binary.entry()
        l.debug("Entry point = 0x%x", entry_point)

        # Crawl the binary, create CFG and fill all the refs inside project!
        l.debug("Pulling all memory")
        project.mem.pull()
        project.perm.pull()

        loaded_state = project.initial_state()
        entry_point_exit = simuvex.SimExit(
            addr=entry_point,
            state=loaded_state.copy_after(),
            jumpkind="Ijk_boring")
        remaining_exits = [entry_point_exit]
        traced_sim_blocks.add(entry_point_exit.concretize())

        # Iteratively analyze every exit
        while len(remaining_exits) > 0:
            current_exit = remaining_exits.pop()
            addr = current_exit.concretize()
            initial_state = current_exit.state
            jumpkind = current_exit.jumpkind

            try:
                sim_run = project.sim_run(addr, initial_state, mode="static")
                sim_run.is_fake = False
            except simuvex.s_irsb.SimIRSBError:
                # It's a tragedy that we came across some instructions that VEX does not support
                # Let's make a fake IRSB with a simple ret instruction inside
                l.warning("Error while creating SimRun at 0x%x, " % addr +
                          "we'll create a pseudo nop IRSB instead.")
                fake_irsb = initial_state.arch.get_nop_irsb(addr)
                sim_run = simuvex.SimIRSB(
                    initial_state,
                    fake_irsb,
                    mode="static")
                # This is a dirty fix
                sim_run.is_fake = True
            except angr.errors.AngrException as ex:
                l.error(
                    "AngrException %s when creating SimRun at 0x%x" %
                    (ex, addr))
                # We might be on a wrong branch, and is likely to encounter the "No bytes
                # in memory xxx" exception
                # Just ignore it
                continue

            tmp_exits = sim_run.exits()

            # Adding the new sim_run to our CFG
            self.bbl_dict[addr] = sim_run

            # TODO: Fill the mem/code references!

            for ex in tmp_exits:
                try:
                    new_addr = ex.concretize()
                except simuvex.s_value.ConcretizingException:
                    # It cannot be concretized currently. Maybe we could handle it later,
                    # maybe it just cannot be concretized
                    continue
                new_initial_state = ex.state.copy_after()
                new_jumpkind = ex.jumpkind

                if new_addr not in traced_sim_blocks:
                    traced_sim_blocks.add(new_addr)
                    new_exit = simuvex.SimExit(
                        addr=new_addr,
                        state=new_initial_state,
                        jumpkind=ex.jumpkind)
                    remaining_exits.append(new_exit)

        # Adding edges of direct control flow transition like calls and
        # boring-exits
        for basic_block_addr, basic_block in self.bbl_dict.items():
            exits = basic_block.exits()
            # debugging!
            l.debug("Basic block [%x]" % basic_block_addr)
            for exit in exits:
                try:
                    l.debug("|      target: %x", exit.concretize())
                except:
                    l.debug("|      target cannot be concretized.")
            for exit in exits:
                try:
                    target_addr = exit.concretize()
                    if target_addr in self.bbl_dict.keys():
                        self.cfg.add_edge(
                            basic_block,
                            self.bbl_dict[target_addr])
                    else:
                        l.warning("Key %x does not exist." % target_addr)
                except:
                    l.warning("Cannot concretize the target address.")

        # Adding edges of indirect control flow transition like returns
        for basic_block_addr, basic_block in self.bbl_dict.items():
            exits = basic_block.exits()
            callsites = []
            if len(exits) == 1 and exits[0].jumpkind == "Ijk_Ret":
                # A ret is here
                # Let's assume the control flow of this block comes from the closest call instruction
                # TODO: Handle other common cases like syscall

                # Back-traverse the control flow path and search for the
                # closest exit-call
                if basic_block in self.cfg:
                    basic_block_stack = self.cfg.predecessors(basic_block)
                    if len(basic_block_stack) == 0:
                        l.warning("Error: len(basic_block_stack) == 0")
                        sys.exit()
                    # Log which blocks are accessed before
                    basic_block_stack_record = []
                    while len(basic_block_stack) > 0:
                        prev_block = basic_block_stack[0]
                        basic_block_stack = basic_block_stack[1:]
                        basic_block_stack_record.append(prev_block)
                        prev_block_exits = prev_block.exits()
                        is_callsite = False
                        for ex in prev_block_exits:
                            if ex.jumpkind == "Ijk_Call":
                                try:
                                    if ex.concretize() == basic_block_addr:
                                        callsites.append(prev_block)
                                        is_callsite = True
                                        break
                                except:
                                    # Callee cannot be determined :p Let it be
                                    pass
                        if not is_callsite:
                            # Get predecessors of this block and append them
                            # into the stack
                            predecessors = self.cfg.predecessors(prev_block)
                            for block in predecessors:
                                if block not in basic_block_stack_record:
                                    basic_block_stack.append(block)
                else:
                    # Some bugs might have happened!
                    # raise Exception("Basic block [%08x] is not in CFG. Something wrong must happened." % basic_block_addr)
                    print (
                        "Basic block [%08x] is not in CFG. Something wrong must happened." %
                        basic_block_addr)

            for callsite_block in callsites:
                callsite_block_exits = callsite_block.exits()
                if len(callsite_block_exits) != 2:
                    raise Exception(
                        "Please report this fact. len(callsite_block_exits) == %x" %
                        len(callsite_block_exits))
                if callsite_block_exits[0].jumpkind == "Ijk_Call":
                    boring_exit = callsite_block_exits[1]
                else:
                    boring_exit = callsite_block_exits[0]
                exit_target_addr = boring_exit.concretize()
                self.cfg.add_edge(basic_block, self.bbl_dict[exit_target_addr])

    def _get_block_addr(self, b):
        if isinstance(b, simuvex.SimIRSB):
            return b.first_imark.addr
        elif isinstance(b, simuvex.SimProcedure):
            return b.addr
        else:
            raise Exception("Unsupported block type %s" % type(b))

    def output(self):
        print "Edges:"
        for edge in self.cfg.edges():
            x = edge[0]
            y = edge[1]
            print "(%x -> %x)" % (self._get_block_addr(x), self._get_block_addr(y))

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self.bbl_dict

    def get_predecessors(self, basic_block):
        return self.cfg.predecessors(basic_block)

    def get_successors(self, basic_block):
        return self.cfg.successors(basic_block)

    def get_irsb(self, addr):
        # TODO: Support getting irsb at arbitary address
        if addr in self.bbl_dict.keys():
            return self.bbl_dict[addr]
        else:
            return None
