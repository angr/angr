import logging
import networkx
import string

import claripy

l = logging.getLogger(name="angr.functionmanager")

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
        self.name = name
        self.is_syscall = syscall

        if self.name is None:
            # Try to get a name from project.loader
            self.name = self._function_manager.project.loader.find_symbol_name(addr)
        if self.name is None:
            self.name = self._function_manager.project.loader.find_plt_stub_name(addr)
            if self.name is not None:
                self.name = 'plt.' + self.name
        if self.name is None:
            self.name = 'sub_%x' % addr

        # Register offsets of those arguments passed in registers
        self._argument_registers = []
        # Stack offsets of those arguments passed in stack variables
        self._argument_stack_variables = []

        # These properties are set by VariableManager
        self._bp_on_stack = False
        self._retaddr_on_stack = False

        self._sp_delta = 0

        # Calling convention
        self.cc = None

        # Whether this function returns or not. `None` means it's not determined yet
        self.returning = None

        self.prepared_registers = set()
        self.prepared_stack_variables = set()
        self.registers_read_afterwards = set()
        self.blocks = { addr }

    @property
    def has_unresolved_jumps(self):
        for addr in self._transition_graph.nodes():
            if addr in self._function_manager._cfg.unresolved_indirect_jumps:
                b = self._function_manager.project.factory.block(addr)
                if b.vex.jumpkind == 'Ijk_Boring':
                    return True
        return False

    @property
    def has_unresolved_calls(self):
        for addr in self._transition_graph.nodes():
            if addr in self._function_manager._cfg.unresolved_indirect_jumps:
                b = self._function_manager.project.factory.block(addr)
                if b.vex.jumpkind == 'Ijk_Call':
                    return True
        return False

    @property
    def operations(self):
        '''
        All of the operations that are done by this functions.
        '''
        operations = [ ]
        for b in self.basic_blocks:
            if b in self._function_manager.project.loader.memory:
                try:
                    operations.extend(self._function_manager.project.factory.block(b).vex.operations)
                except AngrTranslationError:
                    continue
        return operations

    @property
    def code_constants(self):
        '''
        All of the constants that are used by this functions's code.
        '''
        # TODO: remove link register values
        constants = [ ]
        for b in self.basic_blocks:
            if b in self._function_manager.project.loader.memory:
                try:
                    constants.extend(v.value for v in self._function_manager.project.factory.block(b).vex.constants)
                except AngrTranslationError:
                    continue
        return constants

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
        for b in self.basic_blocks:
            if b in memory:
                sirsb = self._function_manager.project.factory.block(b)
                known_executable_addresses.update(sirsb.instruction_addrs)
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
                        if not isinstance(ao.ast, claripy.Base):
                            constants.add(ao.ast)
                        elif not ao.ast.symbolic:
                            constants.add(succ.se.any_int(ao.ast))

                # add successors to the queue to analyze
                if not succ.se.symbolic(succ.ip):
                    succ_ip = succ.se.any_int(succ.ip)
                    if succ_ip in self.basic_blocks and succ_ip not in analyzed:
                        analyzed.add(succ_ip)
                        q.insert(0, succ)

            # force jumps to missing successors
            # (this is a slightly hacky way to force it to explore all the nodes in the function)
            missing = set(self.transition_graph.successors(state.se.any_int(state.ip))) - analyzed
            for succ_addr in missing:
                l.info("Forcing jump to missing successor: 0x%x", succ_addr)
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
                        l.warning("Could not reach successor: 0x%x", succ_addr)

        return constants

    @property
    def runtime_values(self):
        '''
        All of the concrete values used by this function at runtime (i.e., including passed-in arguments and global values).
        '''
        constants = set()
        for b in self.basic_blocks:
            for sirsb in self._function_manager._cfg.get_all_irsbs(b):
                for s in sirsb.successors + sirsb.unsat_successors:
                    for a in s.log.actions:
                        for ao in a.all_objects:
                            if not isinstance(ao.ast, claripy.Base):
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
            s = 'Function [0x%x]\n' % (self._addr)
        else:
            s = 'Function %s [0x%x]\n' % (self.name, self._addr)
        s += '  Syscall: %s\n' % self.is_syscall
        s += '  SP difference: %d\n' % self.sp_delta
        s += '  Has return: %s\n' % self.has_return
        s += '  Returning: %s\n' % ('Unknown' if self.returning is None else self.returning)
        s += '  Arguments: reg: %s, stack: %s\n' % \
            (self._argument_registers,
             self._argument_stack_variables)
        s += '  Blocks: [%s]\n' % ", ".join([hex(i) for i in self.blocks])
        s += "  Calling convention: %s" % self.cc
        return s

    def __repr__(self):
        if self.name is None:
            return '<Function 0x%x>' % (self._addr)
        else:
            return '<Function %s (0x%x)>' % (self.name, self._addr)

    @property
    def startpoint(self):
        return self._addr

    @property
    def endpoints(self):
        return list(self._ret_sites)

    def clear_transition_graph(self):
        self.blocks = { self._addr }
        self._transition_graph = networkx.DiGraph()
        self._transition_graph.add_node(self._addr)
        self._local_transition_graph = None

    def transit_to(self, from_addr, to_addr):
        '''
        Registers an edge between basic blocks in this function's transition graph

        @param from_addr            The address of the basic block that control
                                    flow leaves during this transition
        @param to_addr              The address of the basic block that control
                                    flow enters during this transition
        '''

        self.blocks.add(from_addr)
        self.blocks.add(to_addr)

        self._transition_graph.add_edge(from_addr, to_addr, type='transition')

    def call_to(self, from_addr, to_addr, return_target, syscall=False):
        """
        Registers an edge between the caller basic block and callee basic block

        :param from_addr: The address of the basic block that control flow leaves during the transition
        :param to_addr: The address of the basic block that control flow enters during the transition, which is also
                        the address of the target function to call
        :param return_target: The address of instruction to execute after returning from the function. `None` indicates
                            the call does not return.
        :param syscall: Whether this call is a syscall or nor.
        """

        self.blocks.add(from_addr)

        if syscall:
            self._transition_graph.add_edge(from_addr, to_addr, type='syscall')

        else:
            self._transition_graph.add_edge(from_addr, to_addr, type='call')
            if return_target is not None:
                self._transition_graph.add_edge(from_addr, return_target, type='fake_return')

    def return_from_call(self, src_function_addr, to_addr):

        self.blocks.add(to_addr)

        self._transition_graph.add_edge(src_function_addr, to_addr, type='return_from_call')

    def add_block(self, addr):
        '''
        Registers a basic block as part of this function

        @param addr                 The address of the basic block to add
        '''

        self.blocks.add(addr)

        self._transition_graph.add_node(addr)

    def add_return_site(self, return_site_addr):
        '''
        Registers a basic block as a site for control flow to return from this function

        @param return_site_addr     The address of the basic block ending with a return
        '''
        self._ret_sites.add(return_site_addr)

    def add_call_site(self, call_site_addr, call_target_addr, retn_addr):
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
    def basic_blocks(self):
        return self.blocks

    @property
    def transition_graph(self):
        return self._transition_graph

    @property
    def local_transition_graph(self):
        """
        Return a local transition graph that only contain nodes in current function.
        """

        if self._local_transition_graph is not None:
            return self._local_transition_graph

        g = networkx.DiGraph()
        for src, dst, data in self._transition_graph.edges_iter(data=True):
            if src in self.blocks and dst in self.blocks:
                g.add_edge(src, dst, attr_dict=data)
            elif src in self.blocks:
                g.add_node(src)
            elif dst in self.blocks:
                g.add_node(dst)

        for node in self._transition_graph.nodes_iter():
            if node in self.blocks:
                g.add_node(node)

        self._local_transition_graph = g

        return g

    def dbg_print(self):
        '''
        Returns a representation of the list of basic blocks in this function
        '''
        return "[%s]" % (', '.join(('0x%08x' % n) for n in self._transition_graph.nodes()))

    def dbg_draw(self, filename):
        '''
        Draw the graph and save it to a PNG file
        '''
        import matplotlib.pyplot as pyplot # pylint: disable=import-error
        tmp_graph = networkx.DiGraph()
        for edge in self._transition_graph.edges():
            node_a = "0x%08x" % edge[0]
            node_b = "0x%08x" % edge[1]
            if node_b in self._ret_sites:
                node_b += "[Ret]"
            if node_a in self._call_sites:
                node_a += "[Call]"
            tmp_graph.add_edge(node_a, node_b)
        pos = networkx.graphviz_layout(tmp_graph, prog='fdp')
        networkx.draw(tmp_graph, pos, node_size=1200)
        pyplot.savefig(filename)

    def add_argument_register(self, reg_offset):
        '''
        Registers a register offset as being used as an argument to the function

        @param reg_offset           The offset of the register to register
        '''
        if reg_offset in self._function_manager.arg_registers and \
                    reg_offset not in self._argument_registers:
            self._argument_registers.append(reg_offset)

    def add_argument_stack_variable(self, stack_var_offset):
        if stack_var_offset not in self._argument_stack_variables:
            self._argument_stack_variables.append(stack_var_offset)

    @property
    def arguments(self):
        if self.cc is None:
            return self._argument_registers, self._argument_stack_variables
        else:
            return self.cc.arguments

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

class FunctionManager(object):
    '''
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    '''
    def __init__(self, project, cfg):
        self.project = project
        self._cfg = cfg
        # A map that uses function starting address as the key, and maps
        # to a function class
        self._function_map = {}
        self.interfunction_graph = networkx.DiGraph()

        # Registers used for passing arguments around
        self.arg_registers = project.arch.argument_registers

    def _create_function_if_not_exist(self, function_addr):
        if function_addr not in self._function_map:
            self._function_map[function_addr] = Function(self, function_addr)
            self._function_map[function_addr].add_block(function_addr)

    def call_to(self, function_addr, from_addr, to_addr, retn_addr, syscall=False):
        self._create_function_if_not_exist(function_addr)
        self._create_function_if_not_exist(to_addr)
        self._function_map[function_addr].call_to(from_addr, to_addr, retn_addr, syscall=syscall)
        self._function_map[function_addr].add_call_site(from_addr, to_addr, retn_addr)
        self.interfunction_graph.add_edge(function_addr, to_addr)

    def return_from(self, function_addr, from_addr, to_addr=None): #pylint:disable=unused-argument
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].add_return_site(from_addr)

    def transit_to(self, function_addr, from_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].transit_to(from_addr, to_addr)

    def return_from_call(self, function_addr, src_function_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].return_from_call(src_function_addr, to_addr)

    @property
    def functions(self):
        return self._function_map

    def function(self, addr=None, name=None, create_if_not_exist=False):
        if addr:
            if addr in self._function_map:
                return self._function_map[addr]
            elif create_if_not_exist:
                self._create_function_if_not_exist(addr)
                return self._function_map[addr]
        elif name:
            funcs = [ i for i in self._function_map.values() if i.name == name ]
            if funcs:
                return funcs[0]
            else:
                return None
        else:
            return None

    def dbg_print(self):
        result = ''
        for func_addr, func in self._function_map.items():
            f_str = "Function 0x%08x\n%s\n" % (func_addr, func.dbg_print())
            result += f_str
        return result

    def dbg_draw(self):
        for func_addr, func in self._function_map.items():
            filename = "dbg_function_0x%08x.png" % func_addr
            func.dbg_draw(filename)

from .errors import AngrTranslationError
