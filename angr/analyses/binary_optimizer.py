
import logging
import re
from collections import defaultdict

from . import Analysis

from ..knowledge_base import KnowledgeBase
from .. import SIM_PROCEDURES
from ..codenode import HookNode
from ..sim_variable import SimConstantVariable, SimRegisterVariable, SimMemoryVariable, SimStackVariable

l = logging.getLogger(name=__name__)


class ConstantPropagation(object):
    def __init__(self, constant, constant_assignment_loc, constant_consuming_loc):
        self.constant = constant
        self.constant_assignment_loc = constant_assignment_loc
        self.constant_consuming_loc = constant_consuming_loc

    def __repr__(self):
        s = "<Constant %#x propagates from %#x to %#x>" % (
            self.constant,
            self.constant_assignment_loc.ins_addr,
            self.constant_consuming_loc.ins_addr
        )

        return s


class RedundantStackVariable(object):
    def __init__(self, argument, stack_variable, stack_variable_consuming_locs):
        self.argument = argument
        self.stack_variable = stack_variable
        self.stack_variable_consuming_locs = stack_variable_consuming_locs
        self.argument_register_as_retval = False

    def __repr__(self):
        s = "<StackVar %s for %s at %d locations%s>" % (
            self.stack_variable,
            self.argument,
            len(self.stack_variable_consuming_locs),
            " - retval" if self.argument_register_as_retval else "",
        )

        return s


class RegisterReallocation(object):
    def __init__(self, stack_variable, register_variable, stack_variable_sources, stack_variable_consumers,
                 prologue_addr, prologue_size, epilogue_addr, epilogue_size):
        """
        Constructor.

        :param SimStackVariable stack_variable:
        :param SimRegisterVariable register_variable:
        :param list stack_variable_sources:
        :param list stack_variable_consumers:
        :param int prologue_addr:
        :param int prologue_size:
        :param int epilogue_addr:
        :param int epilogue_size:
        """

        self.stack_variable = stack_variable
        self.register_variable = register_variable
        self.stack_variable_sources = stack_variable_sources
        self.stack_variable_consumers = stack_variable_consumers

        self.prologue_addr = prologue_addr
        self.prologue_size = prologue_size
        self.epilogue_addr = epilogue_addr
        self.epilogue_size = epilogue_size

    def __repr__(self):
        s = "<RegisterReallocation %s for %s with %d sources and %d consumers>" % (
            self.register_variable,
            self.stack_variable,
            len(self.stack_variable_sources),
            len(self.stack_variable_consumers),
        )
        return s


class DeadAssignment(object):
    def __init__(self, pv):
        """
        Constructor.

        :param angr.analyses.ddg.ProgramVariable pv: The assignment to remove.
        """

        self.pv = pv

    def __repr__(self):
        s = "<DeadAssignmentElimination %s>" % self.pv
        return s


class BinaryOptimizer(Analysis):
    """
    This is a collection of binary optimization techniques we used in Mechanical Phish during the finals of Cyber Grand
    Challange. It focuses on dealing with some serious speed-impacting code constructs, and *sort of* worked on *some*
    CGC binaries compiled with O0. Use this analysis as a reference of how to use data dependency graph and such.

    There is no guarantee that BinaryOptimizer will ever work on non-CGC binaries. Feel free to give us PR or MR, but
    please *do not* ask for support of non-CGC binaries.
    """

    BLOCKS_THRESHOLD = 500  # do not optimize a function if it has more than this number of blocks

    def __init__(self, cfg, techniques):

        self.cfg = cfg

        if techniques is None:
            raise Exception('At least one optimization technique must be specified.')

        supported_techniques = {
            'constant_propagation',
            'redundant_stack_variable_removal',
            'register_reallocation',
            'dead_assignment_elimination',
        }

        if techniques - supported_techniques:
            raise Exception('At least one optimization technique specified is not supported.')

        self._techniques = techniques.copy()

        self.constant_propagations = [ ]
        self.redundant_stack_variables = [ ]
        self.register_reallocations = [ ]
        self.dead_assignments = [ ]

        self.optimize()

    def optimize(self):
        for f in self.kb.functions.values():  # type: angr.knowledge.Function
            # if there are unresolved targets in this function, we do not try to optimize it
            unresolvable_targets = (SIM_PROCEDURES['stubs']['UnresolvableJumpTarget'],
                                    SIM_PROCEDURES['stubs']['UnresolvableCallTarget'])
            if any([ n.sim_procedure in unresolvable_targets for n in f.graph.nodes()
                     if isinstance(n, HookNode) ]):
                continue

            if len(f.block_addrs_set) > self.BLOCKS_THRESHOLD:
                continue

            self._optimize_function(f)

    def _optimize_function(self, function):
        """

        :param angr.knowledge.Function function:
        :return:
        """

        #if function.addr != 0x8048250:
        #    return

        func_kb = KnowledgeBase(self.project)

        # switch to non-optimized IR, since optimized IR will optimize away register reads/writes
        # for example,
        # .text:08048285 add     eax, [ebp+var_8]
        # .text:08048288 mov     [ebp+var_C], eax
        # becomes
        #    06 | ------ IMark(0x8048285, 3, 0) ------
        #    07 | t25 = Add32(t24,0xfffffff8)
        #    08 | t5 = LDle:I32(t25)
        #    09 | t4 = Add32(t2,t5)
        #    10 | PUT(eip) = 0x08048288
        #    11 | ------ IMark(0x8048288, 3, 0) ------
        #    12 | t27 = Add32(t24,0xfffffff4)
        #    13 | STle(t27) = t4
        #    14 | PUT(eip) = 0x0804828b
        # there is no write to or read from eax

        cfg = self.project.analyses.CFGEmulated(kb=func_kb,
                                                call_depth=1,
                                                base_graph=function.graph,
                                                keep_state=True,
                                                starts=(function.addr,),
                                                iropt_level=0,
                                                )

        ddg = self.project.analyses.DDG(kb=func_kb,
                                        cfg=cfg
                                        )

        if 'constant_propagation' in self._techniques:
            self._constant_propagation(function, ddg.simplified_data_graph)
        if 'redundant_stack_variable_removal' in self._techniques:
            self._redundant_stack_variable_removal(function, ddg.simplified_data_graph)
        if 'register_reallocation' in self._techniques:
            self._register_reallocation(function, ddg.simplified_data_graph)
        if 'dead_assignment_elimination' in self._techniques:
            self._dead_assignment_elimination(function, ddg.simplified_data_graph)

    def _constant_propagation(self, function, data_graph):  #pylint:disable=unused-argument
        """

        :param function:
        :param networkx.MultiDiGraph data_graph:
        :return:
        """

        # find all edge sequences that looks like const->reg->memory

        for n0 in data_graph.nodes():
            if not isinstance(n0.variable, SimConstantVariable):
                continue

            n1s = list(data_graph.successors(n0))
            if len(n1s) != 1:
                continue
            n1 = n1s[0]

            if not isinstance(n1.variable, SimRegisterVariable):
                continue
            if len(list(data_graph.predecessors(n1))) != 1:
                continue

            n2s = list(data_graph.successors(n1))
            if len(n2s) != 1:
                continue
            n2 = n2s[0]

            if not isinstance(n2.variable, SimMemoryVariable):
                continue
            n2_inedges = data_graph.in_edges(n2, data=True)
            if len([ 0 for _, _, data in n2_inedges if 'type' in data and data['type'] == 'mem_data' ]) != 1:
                continue

            cp = ConstantPropagation(n0.variable.value, n0.location, n2.location)
            self.constant_propagations.append(cp)

            # print n0, n1, n2

    def _redundant_stack_variable_removal(self, function, data_graph):
        """
        If an argument passed from the stack (i.e. dword ptr [ebp+4h]) is saved to a local variable on the stack at the
        beginning of the function, and this local variable was never modified anywhere in this function, and no pointer
        of any stack variable is saved in any register, then we can replace all references to this local variable to
        that argument instead.

        :param function:
        :param networkx.MultiDiGraph data_graph:
        :return:
        """

        # check if there is any stack pointer being stored into any register other than esp
        # basically check all consumers of stack pointers
        stack_ptrs = [ ]
        sp_offset = self.project.arch.registers['esp'][0]
        bp_offset = self.project.arch.registers['ebp'][0]
        for n in data_graph.nodes():
            if isinstance(n.variable, SimRegisterVariable) and n.variable.reg in (sp_offset, bp_offset):
                stack_ptrs.append(n)

        # for each stack pointer variable, make sure none of its consumers is a general purpose register
        for stack_ptr in stack_ptrs:
            out_edges = data_graph.out_edges(stack_ptr, data=True)
            for _, dst, data in out_edges:
                if 'type' in data and data['type'] == 'kill':
                    # we don't care about killing edges
                    continue
                if isinstance(dst.variable, SimRegisterVariable) and dst.variable.reg < 40 and \
                        dst.variable.reg not in (sp_offset, bp_offset):
                    # oops
                    l.debug('Function %s does not satisfy requirements of redundant stack variable removal.',
                            repr(function)
                            )
                    return

        argument_variables = [ ]

        for n in data_graph.nodes():
            if isinstance(n.variable, SimStackVariable) and n.variable.base == 'bp' and n.variable.offset >= 0:
                argument_variables.append(n)

        if not argument_variables:
            return

        #print function
        #print argument_variables

        argument_to_local = { }
        argument_register_as_retval = set()

        # for each argument, find its correspondence on the local stack frame

        for argument_variable in argument_variables:
            # is it copied to the stack?
            successors0 = list(data_graph.successors(argument_variable))

            if not successors0:
                continue

            if len(successors0) != 1:
                continue

            if isinstance(successors0[0].variable, SimRegisterVariable):
                # argument -> register -> stack
                out_edges = data_graph.out_edges(successors0[0], data=True)
                successors1 = [ s for _, s, data in out_edges if 'type' not in data or data['type'] != 'kill' ]
                if len(successors1) == 1:
                    successor1 = successors1[0]
                    if isinstance(successor1.variable, SimStackVariable):
                        if (successor1.variable.base == 'sp' and successor1.variable.offset > 0) or \
                                (successor1.variable.base == 'bp' and successor1.variable.offset < 0):
                            # yes it's copied onto the stack!
                            argument_to_local[argument_variable] = successor1

                # if the register is eax, and it's not killed later, it might be the return value of this function
                # in that case, we cannot eliminate the instruction that moves stack argument to that register
                if successors0[0].variable.reg == self.project.arch.registers['eax'][0]:
                    killers = [ s for _, s, data in out_edges if 'type' in data and data['type'] == 'kill']
                    if not killers:
                        # it might be the return value
                        argument_register_as_retval.add(argument_variable)

            else:
                # TODO:
                import ipdb; ipdb.set_trace()

        #import pprint
        #pprint.pprint(argument_to_local, width=160)

        # find local correspondence that are not modified throughout this function
        redundant_stack_variables = [ ]

        for argument, local_var in argument_to_local.items():
            # local_var cannot be killed anywhere
            out_edges = data_graph.out_edges(local_var, data=True)

            consuming_locs = [ ]

            for _, consumer, data in out_edges:
                consuming_locs.append(consumer.location)
                if 'type' in data and data['type'] == 'kill':
                    break
            else:
                # no killing edges. the value is not changed!
                rsv = RedundantStackVariable(argument, local_var, consuming_locs)
                if argument in argument_register_as_retval:
                    rsv.argument_register_as_retval = True
                redundant_stack_variables.append(rsv)

        self.redundant_stack_variables.extend(redundant_stack_variables)

    def _register_reallocation(self, function, data_graph):
        """
        Find unused registers throughout the function, and use those registers to replace stack variables.

        Only functions that satisfy the following criteria can be optimized in this way:
        - The function does not call any other function.
        - The function does not use esp to index any stack variable.
        - Prologue and epilogue of the function is identifiable.
        - At least one register is not used in the entire function.

        :param angr.knowledge.Function function:
        :param networkx.MultiDiGraph data_graph:
        :return: None
        """

        # make sure this function does not call other functions
        if function.callout_sites:
            return

        if len(function.endpoints) != 1:
            return

        # identify function prologue and epilogue
        startpoint_block = self.project.factory.block(function.startpoint.addr).capstone
        startpoint_insns = startpoint_block.insns

        # supported function prologues:
        #
        # push  ebp
        # mov   ebp, esp
        # sub   esp, [0-9a-f]+h
        #
        # push  ebp
        # mov   ebp, esp
        # push  eax

        if len(startpoint_insns) < 3:
            return

        insn0, insn1, insn2 = startpoint_insns[:3]

        if not (insn0.mnemonic == 'push' and insn0.op_str == 'ebp'):
            return
        if not (insn1.mnemonic == 'mov' and insn1.op_str == 'ebp, esp'):
            return
        if not (insn2.mnemonic == 'sub' and re.match(r"esp, [0-9a-fx]+", insn2.op_str)) and \
                not (insn2.mnemonic == 'push' and insn2.op_str == 'eax'):
            return


        endpoint_block = self.project.factory.block(function.endpoints[0].addr).capstone
        endpoint_insns = endpoint_block.insns

        # supported function epilogues:
        #
        # add   esp, [0-9a-f]+h
        # pop   ebp
        # ret

        if len(endpoint_insns) < 3:
            return

        insn3, insn4, insn5 = endpoint_insns[-3:]

        if not (insn3.mnemonic == 'add' and re.match(r"esp, [0-9a-fx]+", insn3.op_str)):
            return
        if not (insn4.mnemonic == 'pop' and insn4.op_str == 'ebp'):
            return
        if not insn5.mnemonic == 'ret':
            return

        # make sure esp is not used anywhere else - all stack variables must be indexed using ebp
        esp_offset = self.project.arch.registers['esp'][0]
        ebp_offset = self.project.arch.registers['ebp'][0]
        esp_variables = [ ]
        for n in data_graph.nodes():
            if isinstance(n.variable, SimRegisterVariable) and n.variable.reg == esp_offset:
                esp_variables.append(n)

        # find out all call instructions
        call_insns = set()
        for src, dst, data in function.transition_graph.edges(data=True):
            if 'type' in data and data['type'] == 'call':
                src_block = function._get_block(src.addr)
                call_insns.add(src_block.instruction_addrs[-1])

        # there should be six esp variables + all call sites
        # push ebp (insn0 - read, insn0 - write) ; sub esp, 0xXX (insn2) ;
        # add esp, 0xXX (insn3) ; pop ebp (insn4) ; ret (insn5)

        esp_insns = set( n.location.ins_addr for n in esp_variables )
        if esp_insns != { insn0.address, insn2.address, insn3.address, insn4.address, insn5.address } | call_insns:
            return

        prologue_addr = insn0.address
        prologue_size = insn0.size + insn1.size + insn2.size
        epilogue_addr = insn3.address
        epilogue_size = insn3.size + insn4.size + insn5.size

        # look at consumer of those esp variables. no other instruction should be consuming them
        # esp_consumer_insns = { insn0.address, insn1.address, insn2.address, insn3.address, insn4.address,
        #                        insn5.address} | esp_insns
        # for esp_variable in esp_variables:  # type: angr.analyses.ddg.ProgramVariable
        #     consumers = data_graph.successors(esp_variable)
        #     if any([ consumer.location.ins_addr not in esp_consumer_insns for consumer in consumers ]):
        #         return

        # make sure we never gets the address of those stack variables into any register
        # say, lea edx, [ebp-0x4] is forbidden
        # check all edges in data graph
        for src, dst, data in data_graph.edges(data=True):
            if isinstance(dst.variable, SimRegisterVariable) and \
                    dst.variable.reg != ebp_offset and \
                    dst.variable.reg < 40:
                #to a register other than ebp
                if isinstance(src.variable, SimRegisterVariable) and \
                        src.variable.reg == ebp_offset:
                    # from ebp
                    l.debug("Found a lea operation from ebp at %#x. Function %s cannot be optimized.",
                            dst.location.ins_addr,
                            repr(function),
                            )
                    return

        # we definitely don't want to mess with fp or sse operations
        for node in data_graph.nodes():
            if isinstance(node.variable, SimRegisterVariable) and \
                    72 <= node.variable.reg < 288:  # offset(mm0) <= node.variable.reg < offset(cs)
                l.debug('Found a float-point/SSE register access at %#x. Function %s cannot be optimized.',
                        node.location.ins_addr,
                        repr(function)
                        )
                return

        l.debug("RegisterReallocation: function %s satisfies the criteria.", repr(function))

        # nice. let's see if we can optimize this function
        # do we have free registers?

        used_general_registers = set()
        for n in data_graph.nodes():
            if isinstance(n.variable, SimRegisterVariable):
                if n.variable.reg < 40:  # this is a hardcoded limit - we only care about general registers
                    used_general_registers.add(n.variable.reg)
        registers = self.project.arch.registers
        all_general_registers = { #registers['eax'][0], registers['ecx'][0], registers['edx'][0],
                                  registers['ebx'][0], registers['edi'][0], registers['esi'][0],
                                  registers['esp'][0], registers['ebp'][0]
                                  }
        unused_general_registers = all_general_registers - used_general_registers

        if not unused_general_registers:
            l.debug("RegisterReallocation: function %s does not have any free register.", repr(function))
            return
        l.debug("RegisterReallocation: function %s has %d free register(s): %s",
                repr(function),
                len(unused_general_registers),
                ", ".join([self.project.arch.register_names[u] for u in unused_general_registers ])
                )

        # find local stack variables of size 4
        stack_variables = set()
        for n in data_graph.nodes():
            if isinstance(n.variable, SimStackVariable) and \
                    n.variable.base == 'bp' and \
                    n.variable.size == 4 and \
                    n.variable.offset < 0:
                stack_variables.add(n)

        # alright, now we need to make sure that stack variables are never accessed by indexes
        # in other words, they must be accessed directly in forms of 'dword ptr [ebp+x]'
        # it's easy to do this: we get mem_addr predecessors of each stack variable, and make sure there are only two of
        # them: one is ebp, the other one is a constant
        #
        # ah, also, since we do not want to mess with crazy fp registers, we further require none of the stack variable
        # sources and consumers is a FP register.

        filtered_stack_variables = set()
        for stack_variable in stack_variables:

            failed = False

            # check how they are accessed
            in_edges = data_graph.in_edges(stack_variable, data=True)
            for src, _, data in in_edges:
                if 'type' in data and data['type'] == 'mem_addr':
                    if isinstance(src.variable, SimRegisterVariable) and src.variable.reg == ebp_offset:
                        # ebp
                        pass
                    elif isinstance(src.variable, SimConstantVariable):
                        # the constant
                        pass
                    else:
                        # ouch
                        failed = True
                        break

                if isinstance(src.variable, SimRegisterVariable) and src.variable.reg >= 72:
                    # it comes from a FP register
                    failed = True
                    break

            if failed:
                continue

            # check consumers
            out_edges = data_graph.out_edges(stack_variable, data=True)
            for _, dst, data in out_edges:
                if 'type' in data and data['type'] == 'kill':
                    continue
                if isinstance(dst.variable, SimRegisterVariable) and dst.variable.reg >= 72:
                    # an FP register is the consumer
                    failed = True
                    break

            if failed:
                continue

            filtered_stack_variables.add(stack_variable)

        # order the stack variables by the sum of their in and out degrees.
        stack_variable_to_degree = defaultdict(int)
        stack_variable_sources = defaultdict(list)
        for sv in filtered_stack_variables:
            stack_variable_to_degree[sv.variable] += data_graph.in_degree(sv)
            stack_variable_to_degree[sv.variable] += data_graph.out_degree(sv)
            stack_variable_sources[sv.variable].append(sv)

        sorted_stack_variables = sorted(stack_variable_to_degree.keys(),
                                       key=lambda sv: stack_variable_to_degree[sv],
                                       reverse=True
                                       )

        # aha these are the ones that we can replace!
        for reg, sv in zip(unused_general_registers, sorted_stack_variables):

            non_initial_sources = [src for src in stack_variable_sources[sv] if not src.initial]

            if not non_initial_sources:
                # we failed to find any source for it, which indicates a failure in our dependence analysis
                # skip
                continue

            # get consumers
            consumers = set()
            for src in stack_variable_sources[sv]:
                out_edges = data_graph.out_edges(src, data=True)
                for _, dst, data in out_edges:
                    if 'type' not in data or data['type'] != 'kill':
                        consumers.add(dst)

            rr = RegisterReallocation(sv, SimRegisterVariable(reg, 4), non_initial_sources,
                                      list(consumers), prologue_addr, prologue_size, epilogue_addr, epilogue_size
                                      )
            self.register_reallocations.append(rr)

            l.debug("RegisterReallocation: %s will replace %s in function %s.",
                    rr.register_variable,
                    rr.stack_variable,
                    repr(function)
                    )

    def _dead_assignment_elimination(self, function, data_graph):  #pylint:disable=unused-argument
        """
        Remove assignments to registers that has no consumers, but immediately killed.

        BROKEN - DO NOT USE IT

        :param angr.knowledge.Function function:
        :param networkx.MultiDiGraph data_graph:
        :return: None
        """

        register_pvs = set()
        for node in data_graph.nodes():
            if isinstance(node.variable, SimRegisterVariable) and \
                    node.variable.reg is not None and \
                    node.variable.reg < 40:
                register_pvs.add(node)

        for reg in register_pvs:
            # does it have a consumer?
            out_edges = data_graph.out_edges(reg, data=True)
            consumers = [ ]
            killers = [ ]
            for _, _, data in out_edges:
                if 'type' in data and data['type'] == 'kill':
                    killers.append(data)
                else:
                    consumers.append(data)

            if not consumers and killers:
                # we can remove the assignment!
                da = DeadAssignment(reg)
                self.dead_assignments.append(da)

from angr.analyses import AnalysesHub
AnalysesHub.register_default('BinaryOptimizer', BinaryOptimizer)
