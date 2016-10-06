import pyvex
import simuvex

class CFGNode(object):
    """
    This class stands for each single node in CFG.
    """
    def __init__(self,
                 addr,
                 size,
                 cfg,
                 callstack=None,
                 input_state=None,
                 simprocedure_name=None,
                 syscall_name=None,
                 looping_times=0,
                 no_ret=False,
                 is_syscall=False,
                 syscall=None,
                 simrun=None,
                 function_address=None,
                 final_states=None,
                 simrun_key=None,
                 irsb=None,
                 instruction_addrs=None,
                 depth=None,
                 callstack_key=None):
        """
        Note: simprocedure_name is not used to recreate the SimProcedure object. It's only there for better
        __repr__.
        """

        self.callstack = callstack
        self.addr = addr
        self.input_state = input_state
        self.simprocedure_name = simprocedure_name
        self.syscall_name = syscall_name
        self.size = size
        self.looping_times = looping_times
        self.no_ret = no_ret
        self.is_syscall = is_syscall
        self.syscall = syscall
        self._cfg = cfg
        self.function_address = function_address
        self.simrun_key = simrun_key
        self.depth = depth

        self._callstack_key = self.callstack.stack_suffix(self._cfg.context_sensitivity_level) \
            if self.callstack is not None else callstack_key

        self.name = simprocedure_name or cfg.project.loader.find_symbol_name(addr)
        if function_address and self.name is None:
            self.name = cfg.project.loader.find_symbol_name(function_address)
            if self.name is not None:
                offset = addr - function_address
                self.name = "%s%+#x" % (self.name, offset)

        # If this CFG contains an Ijk_Call, `return_target` stores the returning site.
        # Note: this is regardless of whether the call returns or not. You should always check the `no_ret` property if
        # you are using `return_target` to do some serious stuff.
        self.return_target = None

        self.instruction_addrs = instruction_addrs if instruction_addrs is not None else [ ]

        if not instruction_addrs and not self.is_simprocedure:
            # We have to collect instruction addresses by ourselves

            # Try to grab all instruction addresses out!
            if simrun is not None:
                # This is a SimIRSB
                irsb = simrun.irsb

            if irsb is not None:
                self.instruction_addrs = [ s.addr for s in irsb.statements if type(s) is pyvex.IRStmt.IMark ]  # pylint:disable=unidiomatic-typecheck

        self.final_states = [ ] if final_states is None else final_states
        self.irsb = irsb

        self.has_return = False

    @property
    def callstack_key(self):
        return self._callstack_key

    @property
    def successors(self):
        return self._cfg.get_successors(self)

    @property
    def predecessors(self):
        return self._cfg.get_predecessors(self)

    @property
    def is_simprocedure(self):
        return self.simprocedure_name is not None

    def downsize(self):
        """
        Drop saved states.
        """

        self.input_state = None
        self.final_states = [ ]

    def copy(self):
        c = CFGNode(self.addr,
                    self.size,
                    self._cfg,
                    callstack_key=self.callstack_key,
                    input_state=self.input_state,
                    simprocedure_name=self.simprocedure_name,
                    looping_times=self.looping_times,
                    no_ret=self.no_ret,
                    is_syscall=self.is_syscall,
                    syscall=self.syscall,
                    function_address=self.function_address,
                    final_states=self.final_states[ :: ]
                    )
        c.instruction_addrs = self.instruction_addrs[ :: ]
        return c

    def __repr__(self):
        if self.name is not None:
            s = "<CFGNode %s (0x%x) [%d]>" % (self.name, self.addr, self.looping_times)
        else:
            s = "<CFGNode 0x%x (%d) [%d]>" % (self.addr, self.size, self.looping_times)

        return s

    def __eq__(self, other):
        if isinstance(other, simuvex.SimIRSB) or isinstance(other, simuvex.SimProcedure):
            raise ValueError("You do not want to be comparing a SimRun to a CFGNode.")
        if not isinstance(other, CFGNode):
            return False
        return (self.callstack_key == other.callstack_key and
                self.addr == other.addr and
                self.size == other.size and
                self.looping_times == other.looping_times and
                self.simprocedure_name == other.simprocedure_name
                )

    def __hash__(self):
        return hash((self.callstack_key, self.addr, self.looping_times, self.simprocedure_name))

    def to_codenode(self):
        if self.is_simprocedure:
            return HookNode(self.addr, self.size, self.simprocedure_name)
        else:
            return BlockNode(self.addr, self.size)

from ..knowledge.codenode import BlockNode, HookNode
