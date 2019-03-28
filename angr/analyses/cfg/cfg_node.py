import traceback
import logging

from archinfo.arch_soot import SootAddressDescriptor
import archinfo

from ...codenode import BlockNode, HookNode, SyscallNode
from ...engines.successors import SimSuccessors

_l = logging.getLogger(__name__)


class CFGNodeCreationFailure:
    """
    This class contains additional information for whenever creating a CFGNode failed. It includes a full traceback
    and the exception messages.
    """
    __slots__ = ['short_reason', 'long_reason', 'traceback']

    def __init__(self, exc_info=None, to_copy=None):
        if to_copy is None:
            e_type, e, e_traceback = exc_info
            self.short_reason = str(e_type)
            self.long_reason = repr(e)
            self.traceback = traceback.format_exception(e_type, e, e_traceback)
        else:
            self.short_reason = to_copy.short_reason
            self.long_reason = to_copy.long_reason
            self.traceback = to_copy.traceback

    def __hash__(self):
        return hash((self.short_reason, self.long_reason, self.traceback))


class CFGNode:
    """
    This class stands for each single node in CFG.
    """

    __slots__ = ( 'addr', 'simprocedure_name', 'syscall_name', 'size', 'no_ret', 'is_syscall', 'function_address',
                  'block_id', 'thumb', 'byte_string', '_name', 'instruction_addrs', 'irsb', 'has_return', '_cfg',
                  '_hash', 'soot_block'
                  )

    def __init__(self,
                 addr,
                 size,
                 cfg,
                 simprocedure_name=None,
                 no_ret=False,
                 function_address=None,
                 block_id=None,
                 irsb=None,
                 soot_block=None,
                 instruction_addrs=None,
                 thumb=False,
                 byte_string=None):
        """
        Note: simprocedure_name is not used to recreate the SimProcedure object. It's only there for better
        __repr__.
        """

        self.addr = addr
        self.simprocedure_name = simprocedure_name
        self.size = size
        self.no_ret = no_ret
        self._cfg = cfg
        self.function_address = function_address
        self.block_id = block_id
        self.thumb = thumb
        self.byte_string = byte_string

        if isinstance(addr, SootAddressDescriptor):
            self._name = repr(addr)
        else:
            self._name = simprocedure_name
        self.instruction_addrs = list(instruction_addrs) if instruction_addrs is not None else []

        self.is_syscall = True if self.simprocedure_name and self._cfg.project.simos.is_syscall_addr(addr) else False
        if not instruction_addrs and not self.is_simprocedure:
            # We have to collect instruction addresses by ourselves
            if irsb is not None:
                self.instruction_addrs = irsb.instruction_addresses

        self.irsb = None
        self.soot_block = soot_block
        self.has_return = False
        self._hash = None

        # Sanity check
        if self.block_id is None and type(self) is CFGNode:  # pylint: disable=unidiomatic-typecheck
            _l.warning("block_id is unspecified for %s. Default to its address %#x.", str(self), self.addr)
            self.block_id = self.addr

    @property
    def name(self):
        if self._name is None:
            sym = self._cfg.project.loader.find_symbol(self.addr)
            if sym is not None:
                self._name = sym.name
        if self._name is None and isinstance(self._cfg.project.arch, archinfo.ArchARM) and self.addr & 1:
            sym = self._cfg.project.loader.find_symbol(self.addr - 1)
            if sym is not None:
                self._name = sym.name
        if self.function_address and self._name is None:
            sym = self._cfg.project.loader.find_symbol(self.function_address)
            if sym is not None:
                self._name = sym.name
            if self._name is not None:
                offset = self.addr - self.function_address
                self._name = "%s%+#x" % (self._name, offset)

        return self._name

    @property
    def successors(self):
        return self._cfg.get_successors(self)

    @property
    def predecessors(self):
        return self._cfg.get_predecessors(self)

    @property
    def accessed_data_references(self):
        if self._cfg.sort != 'fast':
            raise ValueError("Memory data is currently only supported in CFGFast.")

        for instr_addr in self.instruction_addrs:
            if instr_addr in self._cfg.insn_addr_to_memory_data:
                yield self._cfg.insn_addr_to_memory_data[instr_addr]

    @property
    def is_simprocedure(self):
        return self.simprocedure_name is not None

    @property
    def callstack_key(self):
        # A dummy stub for the future support of context sensitivity in CFGFast
        return None

    def copy(self):
        c = CFGNode(self.addr,
                    self.size,
                    self._cfg,
                    simprocedure_name=self.simprocedure_name,
                    no_ret=self.no_ret,
                    function_address=self.function_address,
                    block_id=self.block_id,
                    irsb=self.irsb,
                    instruction_addrs=self.instruction_addrs,
                    thumb=self.thumb,
                    byte_string=self.byte_string,
                    )
        return c

    def merge(self, other):
        """
        Merges this node with the other, returning a new node that spans the both.
        """
        new_node = self.copy()
        new_node.size += other.size
        new_node.instruction_addrs += other.instruction_addrs
        # FIXME: byte_string should never be none, but it is sometimes
        # like, for example, patcherex test_cfg.py:test_fullcfg_properties
        if new_node.byte_string is None or other.byte_string is None:
            new_node.byte_string = None
        else:
            new_node.byte_string += other.byte_string
        return new_node

    def __repr__(self):
        s = "<CFGNode "
        if self.name is not None:
            s += self.name + " "
        elif not isinstance(self.addr, SootAddressDescriptor):
            s += hex(self.addr)
        if self.size is not None:
            s += "[%d]" % self.size
        s += ">"
        return s

    def __eq__(self, other):
        if isinstance(other, SimSuccessors):
            raise ValueError("You do not want to be comparing a SimSuccessors instance to a CFGNode.")
        if not type(other) is CFGNode:
            return False
        return (self.addr == other.addr and
                self.size == other.size and
                self.simprocedure_name == other.simprocedure_name
                )

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.addr, self.simprocedure_name, ))
        return self._hash

    def to_codenode(self):
        if self.is_syscall:
            return SyscallNode(self.addr, self.size, self.simprocedure_name)
        if self.is_simprocedure:
            return HookNode(self.addr, self.size, self.simprocedure_name)
        return BlockNode(self.addr, self.size, thumb=self.thumb)

    @property
    def block(self):
        if self.is_simprocedure or self.is_syscall:
            return None
        project = self._cfg.project  # everything in angr is connected with everything...
        b = project.factory.block(self.addr, size=self.size, opt_level=self._cfg._iropt_level)
        return b


class CFGENode(CFGNode):
    """
    The CFGNode that is used in CFGEmulated.
    """

    __slots__ = [ 'input_state', 'looping_times', 'callstack', 'depth', 'final_states', 'creation_failure_info',
                  'return_target', 'syscall', '_callstack_key',
                  ]

    def __init__(self,
                 addr,
                 size,
                 cfg,
                 simprocedure_name=None,
                 no_ret=False,
                 function_address=None,
                 block_id=None,
                 irsb=None,
                 instruction_addrs=None,
                 thumb=False,
                 byte_string=None,

                 callstack=None,
                 input_state=None,
                 final_states=None,
                 syscall_name=None,
                 looping_times=0,
                 syscall=None,
                 depth=None,
                 callstack_key=None,
                 creation_failure_info=None,
                 ):

        super(CFGENode, self).__init__(addr, size, cfg,
                                       simprocedure_name=simprocedure_name,
                                       no_ret=no_ret,
                                       function_address=function_address,
                                       block_id=block_id,
                                       irsb=irsb,
                                       instruction_addrs=instruction_addrs,
                                       thumb=thumb,
                                       byte_string=byte_string,
                                       )

        self.callstack = callstack
        self.input_state = input_state
        self.syscall_name = syscall_name
        self.looping_times = looping_times
        self.syscall = syscall
        self.depth = depth

        self.creation_failure_info = None
        if creation_failure_info is not None:
            self.creation_failure_info = CFGNodeCreationFailure(creation_failure_info)

        self._callstack_key = self.callstack.stack_suffix(self._cfg.context_sensitivity_level) \
            if self.callstack is not None else callstack_key

        self.final_states = [ ] if final_states is None else final_states

        # If this CFG contains an Ijk_Call, `return_target` stores the returning site.
        # Note: this is regardless of whether the call returns or not. You should always check the `no_ret` property if
        # you are using `return_target` to do some serious stuff.
        self.return_target = None

    @property
    def callstack_key(self):
        return self._callstack_key

    @property
    def creation_failed(self):
        return self.creation_failure_info is not None

    def downsize(self):
        """
        Drop saved states.
        """

        self.input_state = None
        self.final_states = [ ]

    def __repr__(self):
        s = "<CFGENode "
        if self.name is not None:
            s += self.name + " "
        s += hex(self.addr)
        if self.size is not None:
            s += "[%d]" % self.size
        if self.looping_times > 0:
            s += " - %d" % self.looping_times
        if self.creation_failure_info is not None:
            s += ' - creation failed: {}'.format(self.creation_failure_info.long_reason)
        s += ">"
        return s

    def __eq__(self, other):
        if isinstance(other, SimSuccessors):
            raise ValueError("You do not want to be comparing a SimSuccessors instance to a CFGNode.")
        if not isinstance(other, CFGENode):
            return False
        return (self.callstack_key == other.callstack_key and
                self.addr == other.addr and
                self.size == other.size and
                self.looping_times == other.looping_times and
                self.simprocedure_name == other.simprocedure_name
                )

    def __hash__(self):
        return hash((self.callstack_key, self.addr, self.looping_times, self.simprocedure_name, self.creation_failure_info))

    def copy(self):
        return CFGENode(
            self.addr,
            self.size,
            self._cfg,
            simprocedure_name=self.simprocedure_name,
            no_ret=self.no_ret,
            function_address=self.function_address,
            block_id=self.block_id,
            irsb=self.irsb,
            instruction_addrs=self.instruction_addrs,
            thumb=self.thumb,
            byte_string=self.byte_string,
            callstack=self.callstack,
            input_state=self.input_state,
            syscall_name=self.syscall_name,
            looping_times=self.looping_times,
            syscall=self.syscall,
            depth=self.depth,
            final_states=self.final_states[::],
            callstack_key=self.callstack_key,
        )
