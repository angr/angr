from collections import defaultdict

import networkx

import logging
import simuvex
import angr
from angr.exit_wrapper import SimExitWrapper

l = logging.getLogger(name="angr.cfg")

class CFG(object):
    def __init__(self):
        self._cfg = None
        self._bbl_dict = None
        self._edge_map = None

    # Construct the CFG from an angr. binary object
    def construct(self, binary, project):
        # Re-create the DiGraph
        self._cfg = networkx.DiGraph()

        # Traverse all the IRSBs, and put them to a dict
        # It's actually a multi-dict, as each SIRSB might have different states
        # on different call predicates
        self._bbl_dict = {}
        entry_point = binary.entry()
        l.debug("Entry point = 0x%x", entry_point)

        # Crawl the binary, create CFG and fill all the refs inside project!
        l.debug("Pulling all memory")
        project.mem.pull()
        project.perm.pull()

        loaded_state = project.initial_state(mode="static")
        entry_point_exit = simuvex.SimExit(addr=entry_point,
                                           state=loaded_state.copy_after(),
                                           jumpkind="Ijk_boring")
        exit_wrapper = SimExitWrapper(entry_point_exit)
        remaining_exits = [exit_wrapper]
        traced_sim_blocks = defaultdict(set)
        traced_sim_blocks[exit_wrapper.stack_suffix()].add(
            entry_point_exit.concretize())

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_Ret that is a simulated exit
        # for the retn address. There are certain cases that the control flow
        # never returns to the next instruction of a callsite due to
        # imprecision of the concrete execution. So we save those simulated
        # exits here to increase our code coverage. Of course the real retn from
        # that call always precedes those "fake" retns.
        # Tuple --> (Initial state, stack)
        fake_func_retn_exits = {}
        # A dict to log edges bddetween each basic block
        exit_targets = defaultdict(list)
        # A dict to record all blocks that returns to a specific address
        retn_target_sources = defaultdict(list)
        # Iteratively analyze every exit
        while len(remaining_exits) > 0:
            current_exit_wrapper = remaining_exits.pop()
            current_exit = current_exit_wrapper.sim_exit()
            stack_suffix = current_exit_wrapper.stack_suffix()
            addr = current_exit.concretize()
            initial_state = current_exit.state

            try:
                sim_run = project.sim_run(current_exit)
            except simuvex.s_irsb.SimIRSBError:
                # It's a tragedy that we came across some instructions that VEX
                # does not support. I'll create a terminating stub there
                sim_run = \
                    simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                        initial_state, addr=addr, mode="static", options=None)
            except angr.errors.AngrException as ex:
                l.error("AngrException %s when creating SimRun at 0x%x",
                        ex, addr)
                # We might be on a wrong branch, and is likely to encounter the
                # "No bytes in memory xxx" exception
                # Just ignore it
                continue

            # We will put this block into our dict only if it doesn't exist
            # in our basic block list, aka we haven't traced it in the
            # specified context
            if stack_suffix + (addr,) not in self._bbl_dict:
                # Adding the new sim_run to our dict
                self._bbl_dict[stack_suffix + (addr,)] = sim_run

                # Generate exits
                tmp_exits = sim_run.exits()

                # If there is no valid exit in this branch, we should make it
                # return to its callsite. However, we don't want to use its
                # state as it might be corrupted. Just create a link in the
                # exit_targets map.
                if len(tmp_exits) == 0:
                    #
                    retn_target = current_exit_wrapper.stack().get_ret_target()
                    if retn_target is not None:
                        new_stack = current_exit_wrapper.stack_copy()
                        exit_targets[stack_suffix + (addr,)].append(
                            new_stack.stack_suffix() + (retn_target,))
            else:
                # Remember to empty it!
                tmp_exits = []

            # TODO: Fill the mem/code references!

            # If there is a call exit, we shouldn't put the default exit (which
            # is artificial) into the CFG. The exits will be Ijk_Call and
            # Ijk_Ret, and Ijk_Call always goes first
            is_call_exit = False

            for ex in tmp_exits:
                try:
                    new_addr = ex.concretize()
                except simuvex.s_value.ConcretizingException:
                    # It cannot be concretized currently. Maybe we could handle
                    # it later, maybe it just cannot be concretized
                    continue
                new_initial_state = ex.state.copy_after()
                new_jumpkind = ex.jumpkind

                if new_jumpkind == "Ijk_Call":
                    is_call_exit = True

                # Get the new stack of target block
                if new_jumpkind == "Ijk_Call":
                    new_stack = current_exit_wrapper.stack_copy()
                    # FIXME: We assume the 2nd exit is the default one
                    new_stack.call(addr, new_addr,
                                   retn_target=tmp_exits[1].concretize())
                elif new_jumpkind == "Ijk_Ret" and not is_call_exit:
                    new_stack = current_exit_wrapper.stack_copy()
                    new_stack.ret(new_addr)
                else:
                    new_stack = current_exit_wrapper.stack()
                new_stack_suffix = new_stack.stack_suffix()

                new_tpl = new_stack_suffix + (new_addr,)
                if new_jumpkind == "Ijk_Ret" and not is_call_exit:
                    # This is the real retn exit
                    # Remember this retn!
                    retn_target_sources[new_addr].append(stack_suffix + (addr,))
                    # Check if this retn is inside our fake_func_retn_exits set
                    if new_tpl in fake_func_retn_exits:
                        del fake_func_retn_exits[new_tpl]

                if new_jumpkind == "Ijk_Ret" and is_call_exit:
                    # This is the default "fake" retn that generated at each
                    # call. Save them first, but don't process them now
                    fake_func_retn_exits[new_tpl] = \
                        (new_initial_state, new_stack)
                elif new_addr not in traced_sim_blocks[new_stack_suffix]:
                    traced_sim_blocks[stack_suffix].add(new_addr)
                    new_exit = simuvex.SimExit(addr=new_addr,
                                               state=new_initial_state,
                                               jumpkind=ex.jumpkind)
                    new_exit_wrapper = SimExitWrapper(new_exit, new_stack)
                    remaining_exits.append(new_exit_wrapper)

                if not is_call_exit or new_jumpkind == "Ijk_Call":
                    exit_targets[stack_suffix + (addr,)].append(new_tpl)

            # debugging!
            l.debug("Basic block %s", sim_run)
            l.debug("|    Has default call exit: %s", is_call_exit)
            for ex in tmp_exits:
                try:
                    l.debug("|    target: %x", ex.concretize())
                except Exception:
                    l.debug("|    target cannot be concretized.")

            while len(remaining_exits) == 0 and len(fake_func_retn_exits) > 0:
                # We don't have any exits remaining. Let's pop a fake exit to
                # process
                fake_exit_tuple = fake_func_retn_exits.keys()[0]
                fake_exit_state, fake_exit_stack = \
                    fake_func_retn_exits.pop(fake_exit_tuple)
                fake_exit_addr = fake_exit_tuple[len(fake_exit_tuple) - 1]
                # Let's check whether this address has been traced before.
                targets = filter(lambda r: r == fake_exit_tuple,
                                 exit_targets)
                if len(targets) > 0:
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." + \
                            "Trying the next one...", fake_exit_addr)
                    continue
                new_exit = simuvex.SimExit(addr=fake_exit_addr,
                    state=fake_exit_state,
                    jumpkind="Ijk_Ret")
                new_exit_wrapper = SimExitWrapper(new_exit, fake_exit_stack)
                remaining_exits.append(new_exit_wrapper)
                l.debug("Tracing a missing retn exit 0x%08x", fake_exit_addr)
                break

        # Save the exit_targets dict
        self._edge_map = exit_targets
        # Adding edges
        for tpl, targets in exit_targets.items():
            basic_block = self._bbl_dict[tpl] # Cannot fail :)
            for ex in targets:
                if ex in self._bbl_dict:
                    self._cfg.add_edge(basic_block, self._bbl_dict[ex])

                    # Add edges for possibly missing returns
                    if basic_block.addr in retn_target_sources:
                        for src_irsb_key in \
                                retn_target_sources[basic_block.addr]:
                            self._cfg.add_edge(self._bbl_dict[src_irsb_key],
                                               basic_block)
                else:
                    # Debugging output
                    if ex[0] is None:
                        s = "([None -> None] 0x%08x)" % (ex[2])
                    elif ex[1] is None:
                        s = "([None -> 0x%x] 0x%08x)" % (ex[1], ex[2])
                    else:
                        s = "([0x%x -> 0x%x] 0x%08x)" % (ex[0], ex[1], ex[2])
                    l.warning("Key %s does not exist.", s)


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
            print "(%x -> %x)" % (self._get_block_addr(x),
                                  self._get_block_addr(y))

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self._bbl_dict

    def get_predecessors(self, basic_block):
        return self._cfg.predecessors(basic_block)

    def get_successors(self, basic_block):
        return self._cfg.successors(basic_block)

    def get_irsb(self, addr_tuple):
        # TODO: Support getting irsb at arbitary address
        if addr_tuple in self._bbl_dict.keys():
            return self._bbl_dict[addr_tuple]
        else:
            return None

    def get_nodes(self):
        return self._cfg.nodes()

    def get_any_irsb(self, addr):
        for addr_tuple in self._bbl_dict.keys():
            addr_ = addr_tuple[-1]
            if addr_ == addr:
                return self._bbl_dict[addr_tuple]
        return None
