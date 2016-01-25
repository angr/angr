import logging
import networkx
import string
from collections import defaultdict

import simuvex
import simuvex.s_cc
import claripy

l = logging.getLogger(name="angr.artifacts.function")

class Function(object):
    '''
    A representation of a function and various information about it.
    '''
    def __init__(self, function_manager, addr, name=None, syscall=False):
        '''
        Function constructor

        @param addr             The address of the function
        @param name             (Optional) The name of the function
        @param syscall          (Optional) Whether this function is a sycall or not
        '''
        self._transition_graph = networkx.DiGraph()
        self._local_transition_graph = None

        self._ret_sites = set()
        self._call_sites = {}
        self._retn_addr_to_call_site = {}
        self._addr = addr
        self._function_manager = function_manager
        self.is_syscall = syscall

        self._project = project = self._function_manager._artifact._project

        if name is None:
            # Try to get a name from project.loader
            name = project.loader.find_symbol_name(addr)
        if name is None:
            name = project.loader.find_plt_stub_name(addr)
            if name is not None:
                name = 'plt.' + name
        if project.is_hooked(addr):
            hooker = project.hooked_by(addr)
            if hooker is simuvex.SimProcedures['stubs']['ReturnUnconstrained']:
                kwargs_dict = project._sim_procedures[addr][1]
                if 'resolves' in kwargs_dict:
                    name = kwargs_dict['resolves']
            else:
                name = hooker.__name__.split('.')[-1]
        if name is None:
            name = 'sub_%x' % addr

        self.name = name

        # Register offsets of those arguments passed in registers
        self._argument_registers = []
        # Stack offsets of those arguments passed in stack variables
        self._argument_stack_variables = []

        # These properties are set by VariableManager
        self._bp_on_stack = False
        self._retaddr_on_stack = False

        self._sp_delta = 0

        # Calling convention
        self.call_convention = None

        # Whether this function returns or not. `None` means it's not determined yet
        self.returning = None

        self.prepared_registers = set()
        self.prepared_stack_variables = set()
        self.registers_read_afterwards = set()
        self.blocks = { self._project.factory.block(addr) }

    def _add_block_by_addr(self, addr):
        self.blocks.add(self._project.factory.block(addr))

    @property
    def block_addrs(self):
        return [block.addr for block in self.blocks]

    @property
    def has_unresolved_jumps(self):
        for addr in self._transition_graph.nodes():
            if addr in self._function_manager._artifact._unresolved_indirect_jumps:
                b = self._function_manager.project.factory.block(addr)
                if b.vex.jumpkind == 'Ijk_Boring':
                    return True
        return False

    @property
    def has_unresolved_calls(self):
        for addr in self._transition_graph.nodes():
            if addr in self._function_manager._artifact._unresolved_indirect_jumps:
                b = self._function_manager.project.factory.block(addr)
                if b.vex.jumpkind == 'Ijk_Call':
                    return True
        return False

    @property
    def operations(self):
        '''
        All of the operations that are done by this functions.
        '''
        return [op for block in self.blocks for op in block.vex.operations]

    @property
    def code_constants(self):
        '''
        All of the constants that are used by this functions's code.
        '''
        # TODO: remove link register values
        return [const for block in self.blocks for const in block.vex.constants]

    def string_references(self, minimum_length=1):
        """
        ALl of the constant string reference used by this function
        :param minimum_length: the minimum length of strings to find (default is 1)
        :return: a list of tuples of (address, string) where is address is the location of the string in memory
        """
        strings = []
        memory = self._function_manager.project.loader.memory

        # get known instruction addresses and call targets
        # these addresses cannot be string references, but show up frequently in the runtime values
        known_executable_addresses = set()
        for block in self.blocks:
            known_executable_addresses.update(block.instruction_addrs)
        for node in self._function_manager._cfg.nodes():
            known_executable_addresses.add(node.addr)

        # loop over all local runtime values and check if the value points to a printable string
        for addr in self.partial_local_runtime_values:
            if not isinstance(addr, claripy.fp.FPV) and addr in memory:
                # check that the address isn't an pointing to known executable code
                # and that it isn't an indirect pointer to known executable code
                try:
                    possible_pointer = memory.read_addr_at(addr)
                    if addr not in known_executable_addresses and possible_pointer not in known_executable_addresses:
                        # build string
                        stn = ""
                        offset = 0
                        current_char = memory[addr + offset]
                        while current_char in string.printable:
                            stn += current_char
                            offset += 1
                            current_char = memory[addr + offset]

                        # check that the string was a null terminated string with minimum length
                        if current_char == "\x00" and len(stn) >= minimum_length:
                            strings.append((addr, stn))
                except KeyError:
                    pass
        return strings

    @property
    def partial_local_runtime_values(self):
        """
        Tries to find all runtime values of this function which do not come from inputs.
        These values are generated by starting from a blank state and reanalyzing the basic blocks once each.
        Function calls are skipped, and back edges are never taken so these values are often unreliable,
        This function is good at finding simple constant addresses which the function will use or calculate.
        :return: a set of constants
        """
        constants = set()

        if not self._function_manager.project.loader.main_bin.contains_addr(self.startpoint):
            return constants

        # reanalyze function with a new initial state (use persistent registers)
        initial_state = self._function_manager._cfg.get_any_irsb(self.startpoint).initial_state
        fresh_state = self._function_manager.project.factory.blank_state(mode="fastpath")
        for reg in initial_state.arch.persistent_regs + ['ip']:
            fresh_state.registers.store(reg, initial_state.registers.load(reg))

        # process the nodes in a breadth-first order keeping track of which nodes have already been analyzed
        analyzed = set()
        q = [fresh_state]
        analyzed.add(fresh_state.se.any_int(fresh_state.ip))
        while len(q) > 0:
            state = q.pop()
            # don't trace into simprocedures
            if self._function_manager.project.is_hooked(state.se.any_int(state.ip)):
                continue
            # don't trace outside of the binary
            if not self._function_manager.project.loader.main_bin.contains_addr(state.se.any_int(state.ip)):
                continue

            # get runtime values from logs of successors
            p = self._function_manager.project.factory.path(state)
            p.step()
            for succ in p.next_run.flat_successors + p.next_run.unsat_successors:
                for a in succ.log.actions:
                    for ao in a.all_objects:
                        if not isinstance(ao.ast, claripy.ast.Base):
                            constants.add(ao.ast)
                        elif not ao.ast.symbolic:
                            constants.add(succ.se.any_int(ao.ast))

                # add successors to the queue to analyze
                if not succ.se.symbolic(succ.ip):
                    succ_ip = succ.se.any_int(succ.ip)
                    if succ_ip in self.block_addrs and succ_ip not in analyzed:
                        analyzed.add(succ_ip)
                        q.insert(0, succ)

            # force jumps to missing successors
            # (this is a slightly hacky way to force it to explore all the nodes in the function)
            missing = set(self.transition_graph.successors(state.se.any_int(state.ip))) - analyzed
            for succ_addr in missing:
                l.info("Forcing jump to missing successor: %#x", succ_addr)
                if succ_addr not in analyzed:
                    all_successors = p.next_run.unconstrained_successors + p.next_run.flat_successors + \
                                     p.next_run.unsat_successors
                    if len(all_successors) > 0:
                        # set the ip of a copied successor to the successor address
                        succ = all_successors[0].copy()
                        succ.ip = succ_addr
                        analyzed.add(succ_addr)
                        q.insert(0, succ)
                    else:
                        l.warning("Could not reach successor: %#x", succ_addr)

        return constants

    @property
    def runtime_values(self):
        '''
        All of the concrete values used by this function at runtime (i.e., including passed-in arguments and global values).
        '''
        constants = set()
        for b in self.block_addrs:
            for sirsb in self._function_manager._cfg.get_all_irsbs(b):
                for s in sirsb.successors + sirsb.unsat_successors:
                    for a in s.log.actions:
                        for ao in a.all_objects:
                            if not isinstance(ao.ast, claripy.ast.Base):
                                constants.add(ao.ast)
                            elif not ao.ast.symbolic:
                                constants.add(s.se.any_int(ao.ast))
        return constants

    @property
    def num_arguments(self):
        return len(self._argument_registers) + len(self._argument_stack_variables)

    def __contains__(self, val):
        if isinstance(val, (int, long)):
            return val in self._transition_graph
        else:
            return False

    def __str__(self):
        if self.name is None:
            s = 'Function [%#x]\n' % (self._addr)
        else:
            s = 'Function %s [%#x]\n' % (self.name, self._addr)
        s += '  Syscall: %s\n' % self.is_syscall
        s += '  SP difference: %d\n' % self.sp_delta
        s += '  Has return: %s\n' % self.has_return
        s += '  Returning: %s\n' % ('Unknown' if self.returning is None else self.returning)
        s += '  Arguments: reg: %s, stack: %s\n' % \
            (self._argument_registers,
             self._argument_stack_variables)
        s += '  Blocks: [%s]\n' % ", ".join(['%#x' % i for i in self.block_addrs])
        s += "  Calling convention: %s" % self.call_convention
        return s

    def __repr__(self):
        if self.name is None:
            return '<Function %#x>' % (self._addr)
        else:
            return '<Function %s (%#x)>' % (self.name, self._addr)

    @property
    def startpoint(self):
        return self._addr

    @property
    def endpoints(self):
        return list(self._ret_sites)

    def _clear_transition_graph(self):
        self.blocks = { self._project.factory.block(self._addr) }
        self._transition_graph = networkx.DiGraph()
        self._transition_graph.add_node(self._addr)
        self._local_transition_graph = None

    def _transit_to(self, from_addr, to_addr):
        '''
        Registers an edge between basic blocks in this function's transition graph

        @param from_addr            The address of the basic block that control
                                    flow leaves during this transition
        @param to_addr              The address of the basic block that control
                                    flow enters during this transition
        '''

        self._add_block_by_addr(from_addr)
        self._add_block_by_addr(to_addr)

        self._transition_graph.add_edge(from_addr, to_addr, type='transition')

    def _call_to(self, from_addr, to_addr, return_target, syscall=False):
        """
        Registers an edge between the caller basic block and callee basic block

        :param from_addr: The address of the basic block that control flow leaves during the transition
        :param to_addr: The address of the basic block that control flow enters during the transition, which is also
                        the address of the target function to call
        :param return_target: The address of instruction to execute after returning from the function. `None` indicates
                            the call does not return.
        :param syscall: Whether this call is a syscall or nor.
        """

        self._add_block_by_addr(from_addr)

        if syscall:
            self._transition_graph.add_edge(from_addr, to_addr, type='syscall')

        else:
            self._transition_graph.add_edge(from_addr, to_addr, type='call')
            if return_target is not None:
                self._transition_graph.add_edge(from_addr, return_target, type='fake_return')

    def _return_from_call(self, src_function_addr, to_addr):
        self._add_block_by_addr(to_addr)

        self._transition_graph.add_edge(src_function_addr, to_addr, type='return_from_call')

    def _add_block(self, addr):
        '''
        Registers a basic block as part of this function

        @param addr                 The address of the basic block to add
        '''

        self._add_block_by_addr(addr)

        self._transition_graph.add_node(addr)

    def _add_return_site(self, return_site_addr):
        '''
        Registers a basic block as a site for control flow to return from this function

        @param return_site_addr     The address of the basic block ending with a return
        '''
        self._ret_sites.add(return_site_addr)

    def _add_call_site(self, call_site_addr, call_target_addr, retn_addr):
        '''
        Registers a basic block as calling a function and returning somewhere

        @param call_site_addr       The basic block that ends in a call
        @param call_target_addr     The target of said call
        @param retn_addr            The address that said call will return to
        '''
        self._call_sites[call_site_addr] = (call_target_addr, retn_addr)
        self._retn_addr_to_call_site[retn_addr] = call_site_addr

    def get_call_sites(self):
        '''
        Gets a list of all the basic blocks that end in calls

        @returns                    What the hell do you think?
        '''
        return self._call_sites.keys()

    def get_call_target(self, callsite_addr):
        '''
        Get the target of a call

        @param callsite_addr        The address of the basic block that ends in
                                    a call

        @returns                    The target of said call
        '''
        if callsite_addr in self._call_sites:
            return self._call_sites[callsite_addr][0]
        return None

    def get_call_return(self, callsite_addr):
        '''
        Get the hypothetical return address of a call

        @param callsite_addr        The address of the basic block that ends in
                                    a call

        @returns                    The likely return target of said call
        '''
        if callsite_addr in self._call_sites:
            return self._call_sites[callsite_addr][1]
        return None

    @property
    def transition_graph(self):
        return self._transition_graph

    @property
    def graph(self):
        """
        Return a local transition graph that only contain nodes in current function.
        """

        if self._local_transition_graph is not None:
            return self._local_transition_graph

        g = networkx.DiGraph()
        for src, dst, data in self._transition_graph.edges_iter(data=True):
            if src in self.block_addrs and dst in self.block_addrs:
                g.add_edge(src, dst, attr_dict=data)
            elif src in self.block_addrs:
                g.add_node(src)
            elif dst in self.block_addrs:
                g.add_node(dst)

        for node in self._transition_graph.nodes_iter():
            if node in self.block_addrs:
                g.add_node(node)

        self._local_transition_graph = g

        return g

    def dbg_print(self):
        '''
        Returns a representation of the list of basic blocks in this function
        '''
        return "[%s]" % (', '.join(('%#08x' % n) for n in self._transition_graph.nodes()))

    def dbg_draw(self, filename):
        '''
        Draw the graph and save it to a PNG file
        '''
        import matplotlib.pyplot as pyplot # pylint: disable=import-error
        tmp_graph = networkx.DiGraph()
        for edge in self._transition_graph.edges():
            node_a = "%#08x" % edge[0]
            node_b = "%#08x" % edge[1]
            if node_b in self._ret_sites:
                node_b += "[Ret]"
            if node_a in self._call_sites:
                node_a += "[Call]"
            tmp_graph.add_edge(node_a, node_b)
        pos = networkx.graphviz_layout(tmp_graph, prog='fdp')
        networkx.draw(tmp_graph, pos, node_size=1200)
        pyplot.savefig(filename)

    def _add_argument_register(self, reg_offset):
        '''
        Registers a register offset as being used as an argument to the function

        @param reg_offset           The offset of the register to register
        '''
        if reg_offset in self._function_manager._arg_registers and \
                    reg_offset not in self._argument_registers:
            self._argument_registers.append(reg_offset)

    def _add_argument_stack_variable(self, stack_var_offset):
        if stack_var_offset not in self._argument_stack_variables:
            self._argument_stack_variables.append(stack_var_offset)

    @property
    def arguments(self):
        if self.call_convention is None:
            return self._argument_registers, self._argument_stack_variables
        else:
            return self.call_convention.arguments

    @property
    def bp_on_stack(self):
        return self._bp_on_stack

    @bp_on_stack.setter
    def bp_on_stack(self, value):
        self._bp_on_stack = value

    @property
    def retaddr_on_stack(self):
        return self._retaddr_on_stack

    @retaddr_on_stack.setter
    def retaddr_on_stack(self, value):
        self._retaddr_on_stack = value

    @property
    def sp_delta(self):
        return self._sp_delta

    @sp_delta.setter
    def sp_delta(self, value):
        self._sp_delta = value

    @property
    def has_return(self):
        return len(self._ret_sites) > 0

    @property
    def callable(self):
        return self._function_manager.project.factory.callable(self._addr)

    def normalize(self):
        graph = self.transition_graph
        end_addresses = defaultdict(list)

        for block in self.blocks:
            end_addr = block.addr + block.size
            end_addresses[end_addr].append(block)

        while any([len(x) > 1 for x in end_addresses.itervalues()]):
            end_addr, all_nodes = \
                next((end_addr, x) for (end_addr, x) in end_addresses.iteritems() if len(x) > 1)

            all_nodes = sorted(all_nodes, key=lambda node: node.size)
            smallest_node = all_nodes[0]
            other_nodes = all_nodes[1:]

            # Break other nodes
            for n in other_nodes:
                new_size = smallest_node.addr - n.addr
                if new_size == 0:
                    # This is the node that has the same size as the smallest one
                    continue

                new_end_addr = n.addr + new_size

                # Does it already exist?
                new_node = None
                if new_end_addr in end_addresses:
                    nodes = [i for i in end_addresses[new_end_addr] if i.addr == n.addr]
                    if len(nodes) > 0:
                        new_node = nodes[0]

                if new_node is None:
                    # Create a new one
                    new_node = self._project.factory.block(n.addr, max_size=new_size)
                    # Put the newnode into end_addresses
                    end_addresses[new_end_addr].append(new_node)

                # Modify the CFG
                original_predecessors = list(graph.in_edges_iter([n], data=True))
                for p, _, _ in original_predecessors:
                    graph.remove_edge(p, n)
                graph.remove_node(n)

                for p, _, data in original_predecessors:
                    graph.add_edge(p, new_node, data)

                # We should find the correct successor
                new_successors = [i for i in all_nodes
                                  if i.addr == smallest_node.addr]
                if new_successors:
                    new_successor = new_successors[0]
                    graph.add_edge(new_node, new_successor, jumpkind='Ijk_Boring')
                else:
                    # We gotta create a new one
                    l.error('normalize(): Please report it to Fish/maybe john.')

            end_addresses[end_addr] = [smallest_node]
<<<<<<< c80f584720df22a098443004d6194171fa705bc6

    def _match_cc(self):
        '''
        Try to decide the arguments to this function.
        `cfg` is not necessary, but providing a CFG makes our life easier and will give you a better analysis
        result (i.e. we have an idea of how this function is called in its call-sites).
        If a CFG is not provided or we cannot find the given function address in the given CFG, we will generate
        a local CFG of the function to detect how it is using the arguments.
        '''
        arch = self._project.arch

        args = [ ]
        ret_vals = [ ]
        sp_delta = 0

        #
        # Determine how many arguments this function has.
        #
        reg_args, stack_args = self.arguments

        for arg in reg_args:
            a = simuvex.s_cc.SimRegArg(arch.register_names[arg])
            args.append(a)

        for arg in stack_args:
            a = simuvex.s_cc.SimStackArg(arg)
            args.append(a)

        sp_delta = self.sp_delta

        for c in simuvex.s_cc.CC:
            if c._match(arch, args, sp_delta):
                return c(arch, args, ret_vals, sp_delta)

        # We cannot determine the calling convention of this function.
        return simuvex.s_cc.SimCCUnknown(arch, args, ret_vals, sp_delta)
=======
>>>>>>> Make a whole bunch of mutating methods on function and function manager private
