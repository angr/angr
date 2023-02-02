import traceback
import logging
from typing import TYPE_CHECKING, Union, Optional

from archinfo.arch_soot import SootAddressDescriptor
import archinfo

from angr.codenode import BlockNode, HookNode, SyscallNode
from angr.engines.successors import SimSuccessors
from angr.serializable import Serializable
from angr.protos import cfg_pb2
from angr.errors import AngrError, SimError

if TYPE_CHECKING:
    from .cfg_model import CFGModel
    import angr

_l = logging.getLogger(__name__)


class CFGNodeCreationFailure:
    """
    This class contains additional information for whenever creating a CFGNode failed. It includes a full traceback
    and the exception messages.
    """

    __slots__ = ["short_reason", "long_reason", "traceback"]

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


class CFGNode(Serializable):
    """
    This class stands for each single node in CFG.
    """

    __slots__ = (
        "addr",
        "simprocedure_name",
        "syscall_name",
        "size",
        "no_ret",
        "is_syscall",
        "function_address",
        "block_id",
        "thumb",
        "byte_string",
        "_name",
        "instruction_addrs",
        "irsb",
        "has_return",
        "_cfg_model",
        "_hash",
        "soot_block",
    )

    def __init__(
        self,
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
        byte_string=None,
        is_syscall=None,
        name=None,
    ):
        """
        Note: simprocedure_name is not used to recreate the SimProcedure object. It's only there for better
        __repr__.
        """

        self.addr = addr
        self.size = size
        self.simprocedure_name = simprocedure_name
        self.no_ret = no_ret
        self._cfg_model: "CFGModel" = cfg
        self.function_address = function_address
        self.block_id: Union["angr.analyses.cfg.cfg_job_base.BlockID", int] = block_id
        self.thumb = thumb
        self.byte_string: Optional[bytes] = byte_string

        self._name = None
        if name is not None:
            self._name = name
        elif isinstance(addr, SootAddressDescriptor):
            self._name = repr(addr)
        else:
            self._name = simprocedure_name
        self.instruction_addrs = list(instruction_addrs) if instruction_addrs is not None else []

        if is_syscall is not None:
            self.is_syscall = is_syscall
        else:
            self.is_syscall = bool(self.simprocedure_name and self._cfg_model.project.simos.is_syscall_addr(addr))

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
            sym = self._cfg_model.project.loader.find_symbol(self.addr)
            if sym is not None:
                self._name = sym.name
        if self._name is None and isinstance(self._cfg_model.project.arch, archinfo.ArchARM) and self.addr & 1:
            sym = self._cfg_model.project.loader.find_symbol(self.addr - 1)
            if sym is not None:
                self._name = sym.name
        if self.function_address and self._name is None:
            sym = self._cfg_model.project.loader.find_symbol(self.function_address)
            if sym is not None:
                self._name = sym.name
            if self._name is not None:
                offset = self.addr - self.function_address
                self._name = f"{self._name}{offset:+#x}"

        return self._name

    @property
    def successors(self):
        return self._cfg_model.get_successors(self)

    @property
    def predecessors(self):
        return self._cfg_model.get_predecessors(self)

    def successors_and_jumpkinds(self, excluding_fakeret=True):
        return self._cfg_model.get_successors_and_jumpkinds(self, excluding_fakeret=excluding_fakeret)

    def predecessors_and_jumpkinds(self, excluding_fakeret=True):
        return self._cfg_model.get_predecessors_and_jumpkinds(self, excluding_fakeret=excluding_fakeret)

    def get_data_references(self, kb=None):
        """
        Get the known data references for this CFGNode via the knowledge base.

        :param kb:  Which knowledge base to use; uses the global KB by default if none is provided
        :return:    Generator yielding xrefs to this CFGNode's block.
        :rtype:     iter
        """
        if not self._cfg_model.ident.startswith("CFGFast"):
            raise ValueError("Memory data is currently only supported in CFGFast.")
        if not kb:
            kb = self._cfg_model.project.kb
        if not kb:
            raise ValueError("The Knowledge Base does not exist!")

        for instr_addr in self.instruction_addrs:
            refs = list(kb.xrefs.get_xrefs_by_ins_addr(instr_addr))
            yield from refs

    @property
    def accessed_data_references(self):
        """
        Property providing a view of all the known data references for this CFGNode via the global knowledge base

        :return:    Generator yielding xrefs to this CFGNode's block.
        :rtype:     iter
        """
        return self.get_data_references()

    @property
    def is_simprocedure(self):
        return self.simprocedure_name is not None

    @property
    def callstack_key(self):
        # A dummy stub for the future support of context sensitivity in CFGFast
        return None

    #
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.CFGNode()

    def serialize_to_cmessage(self):
        if isinstance(self, CFGENode):
            raise NotImplementedError("CFGEmulated instances are not currently serializable")

        obj = self._get_cmsg()
        obj.ea = self.addr
        obj.size = self.size
        if self.block_id is not None:
            if type(self.block_id) is int:
                obj.block_id.append(self.block_id)  # pylint:disable=no-member
            else:  # should be a BlockID
                raise NotImplementedError("CFGEmulated instances are not currently serializable")
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg=None):  # pylint:disable=arguments-differ
        if len(cmsg.block_id) == 0:
            block_id = None
        else:
            block_id = cmsg.block_id[0]

        obj = cls(
            cmsg.ea,
            cmsg.size,
            cfg=cfg,
            block_id=block_id,
        )
        if cfg is not None:
            # fill in self.instruction_addrs
            proj = cfg.project
            try:
                obj.instruction_addrs = proj.factory.block(obj.addr, size=obj.size).instruction_addrs
            except (AngrError, SimError):
                # maybe this is a SimProcedure but not a block. ignore
                # TODO: We should serialize information including is_simprocedure
                pass
        return obj

    #
    # Pickling
    #

    def __getstate__(self):
        s = {
            "addr": self.addr,
            "size": self.size,
            "simprocedure_name": self.simprocedure_name,
            "no_ret": self.no_ret,
            "function_address": self.function_address,
            "block_id": self.block_id,
            "thumb": self.thumb,
            "byte_string": self.byte_string,
            "_name": self._name,
            "instruction_addrs": self.instruction_addrs,
            "is_syscall": self.is_syscall,
            "has_return": self.has_return,
        }
        return s

    def __setstate__(self, state):
        self.__init__(
            state["addr"],
            state["size"],
            None,
            simprocedure_name=state["simprocedure_name"],
            no_ret=state["no_ret"],
            function_address=state["function_address"],
            block_id=state["block_id"],
            thumb=state["thumb"],
            byte_string=state["byte_string"],
            name=state["_name"],
            instruction_addrs=state["instruction_addrs"],
            is_syscall=state["is_syscall"],
        )
        self.has_return = state["has_return"]

    #
    # Methods
    #

    def copy(self):
        c = CFGNode(
            self.addr,
            self.size,
            self._cfg_model,
            simprocedure_name=self.simprocedure_name,
            no_ret=self.no_ret,
            function_address=self.function_address,
            block_id=self.block_id,
            irsb=self.irsb,
            instruction_addrs=self.instruction_addrs,
            thumb=self.thumb,
            byte_string=self.byte_string,
            is_syscall=self.is_syscall,
            name=self._name,
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
        if type(other) is not CFGNode:
            return False
        return self.addr == other.addr and self.size == other.size and self.simprocedure_name == other.simprocedure_name

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(
                (
                    self.addr,
                    self.simprocedure_name,
                )
            )
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
        project = self._cfg_model.project  # everything in angr is connected with everything...
        b = project.factory.block(self.addr, size=self.size, opt_level=self._cfg_model._iropt_level)
        return b


class CFGENode(CFGNode):
    """
    The CFGNode that is used in CFGEmulated.
    """

    __slots__ = [
        "input_state",
        "looping_times",
        "depth",
        "final_states",
        "creation_failure_info",
        "return_target",
        "syscall",
        "_callstack_key",
    ]

    def __init__(
        self,
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
        is_syscall=None,
        name=None,
        # CFGENode specific
        input_state=None,
        final_states=None,
        syscall_name=None,
        looping_times=0,
        depth=None,
        callstack_key=None,
        creation_failure_info=None,
    ):
        super().__init__(
            addr,
            size,
            cfg,
            simprocedure_name=simprocedure_name,
            no_ret=no_ret,
            function_address=function_address,
            block_id=block_id,
            irsb=irsb,
            instruction_addrs=instruction_addrs,
            thumb=thumb,
            byte_string=byte_string,
            is_syscall=is_syscall,
            name=name,
        )

        self.input_state = input_state
        self.syscall_name = syscall_name
        self.looping_times = looping_times
        self.depth = depth

        self.creation_failure_info = None
        if creation_failure_info is not None:
            self.creation_failure_info = CFGNodeCreationFailure(creation_failure_info)

        self._callstack_key = callstack_key

        self.final_states = [] if final_states is None else final_states

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
        self.final_states = []

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
            s += f" - creation failed: {self.creation_failure_info.long_reason}"
        s += ">"
        return s

    def __eq__(self, other):
        if isinstance(other, SimSuccessors):
            raise ValueError("You do not want to be comparing a SimSuccessors instance to a CFGNode.")
        if not isinstance(other, CFGENode):
            return False
        return (
            self.callstack_key == other.callstack_key
            and self.addr == other.addr
            and self.size == other.size
            and self.looping_times == other.looping_times
            and self.simprocedure_name == other.simprocedure_name
        )

    def __hash__(self):
        return hash(
            (self.callstack_key, self.addr, self.looping_times, self.simprocedure_name, self.creation_failure_info)
        )

    #
    # Pickeling
    #

    def __getstate__(self):
        s = super().__getstate__()
        s["syscall_name"] = self.syscall_name
        s["looping_times"] = self.looping_times
        s["depth"] = self.depth
        s["creation_failure_info"] = self.creation_failure_info
        s["_callstack_key"] = self.callstack_key
        s["return_target"] = self.return_target
        return s

    def __setstate__(self, state):
        self.__init__(
            state["addr"],
            state["size"],
            None,
            simprocedure_name=state["simprocedure_name"],
            no_ret=state["no_ret"],
            function_address=state["function_address"],
            block_id=state["block_id"],
            instruction_addrs=state["instruction_addrs"],
            thumb=state["thumb"],
            byte_string=state["byte_string"],
            is_syscall=state["is_syscall"],
            name=state["_name"],
            syscall_name=state["syscall_name"],
            looping_times=state["looping_times"],
            depth=state["depth"],
            callstack_key=state["_callstack_key"],
            creation_failure_info=state["creation_failure_info"],
        )

    def copy(self):
        return CFGENode(
            self.addr,
            self.size,
            self._cfg_model,
            simprocedure_name=self.simprocedure_name,
            no_ret=self.no_ret,
            function_address=self.function_address,
            block_id=self.block_id,
            irsb=self.irsb,
            instruction_addrs=self.instruction_addrs,
            thumb=self.thumb,
            byte_string=self.byte_string,
            input_state=self.input_state,
            syscall_name=self.syscall_name,
            looping_times=self.looping_times,
            is_syscall=self.is_syscall,
            depth=self.depth,
            final_states=self.final_states[::],
            callstack_key=self.callstack_key,
        )
