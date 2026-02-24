from __future__ import annotations

import traceback
import logging
from typing import TYPE_CHECKING

from archinfo.arch_soot import SootAddressDescriptor
import archinfo

from angr.codenode import BlockNode, HookNode, SyscallNode
from angr.engines.successors import SimSuccessors
from angr.serializable import Serializable
from angr.protos import cfg_pb2

if TYPE_CHECKING:
    from angr.block import Block, SootBlock
    from angr.analyses.cfg.cfg_job_base import BlockID
    from .cfg_model import CFGModel

_l = logging.getLogger(__name__)


AddressType = int | SootAddressDescriptor


class CFGNodeCreationFailure:
    """
    This class contains additional information for whenever creating a CFGNode failed. It includes a full traceback
    and the exception messages.
    """

    __slots__ = ["long_reason", "short_reason", "traceback"]

    def __init__(self, exc_info=None, to_copy=None):
        if to_copy is None:
            assert exc_info is not None
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
        "_addr",
        "_block_id",
        "_byte_string",
        "_cfg_model",
        "_dirty",
        "_function_address",
        "_has_return",
        "_hash",
        "_is_syscall",
        "_name",
        "_no_ret",
        "_size",
        "_thumb",
        "instruction_addrs",
        "irsb",
        "simprocedure_name",
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
        block_id: BlockID | int | None = None,
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

        self._addr: AddressType = addr
        self._size = size
        self.simprocedure_name = simprocedure_name
        self._no_ret = no_ret
        self._cfg_model: CFGModel = cfg
        self._function_address = function_address
        self._block_id: BlockID | int | None = block_id
        self._thumb = thumb
        self._byte_string: bytes | None = byte_string

        self._name = None
        if name is not None:
            self._name = name
        elif isinstance(addr, SootAddressDescriptor):
            self._name = repr(addr)
        else:
            self._name = simprocedure_name
        self.instruction_addrs = list(instruction_addrs) if instruction_addrs is not None else []

        if is_syscall is not None:
            self._is_syscall = is_syscall
        else:
            self._is_syscall = bool(
                self.simprocedure_name
                and self._cfg_model.project is not None
                and self._cfg_model.project.simos is not None
                and self._cfg_model.project.simos.is_syscall_addr(addr)
            )

        if not instruction_addrs and not self.is_simprocedure and irsb is not None:
            # We have to collect instruction addresses by ourselves
            self.instruction_addrs = irsb.instruction_addresses

        self.irsb = None
        self.soot_block = soot_block
        self._has_return = False
        self._hash = None
        self._dirty = True

        # Sanity check
        if self._block_id is None and type(self) is CFGNode:  # pylint: disable=unidiomatic-typecheck
            _l.warning("block_id is unspecified for %s. Default to its address %#x.", str(self), self._addr)
            self._block_id = self._addr

    @property
    def dirty(self):
        return self._dirty

    @dirty.setter
    def dirty(self, value: bool):
        self._dirty = value

    @property
    def function_address(self):
        return self._function_address

    @function_address.setter
    def function_address(self, value):
        if value == self._function_address:
            return

        self._function_address = value
        self._name = None  # reset the name so that it can be re-resolved with the new function address
        self.dirty = True

    @property
    def addr(self):
        return self._addr

    @property
    def block_id(self):
        return self._block_id

    @property
    def byte_string(self) -> bytes:
        return self._byte_string

    @property
    def has_return(self) -> bool:
        return self._has_return

    @has_return.setter
    def has_return(self, value: bool):
        if value == self._has_return:
            return

        self._has_return = value
        self.dirty = True

    @property
    def is_syscall(self) -> bool:
        return self._is_syscall

    @property
    def thumb(self) -> bool:
        return self._thumb

    @property
    def size(self) -> bool:
        return self._size

    @property
    def no_ret(self) -> bool:
        return self._no_ret

    @no_ret.setter
    def no_ret(self, value: bool):
        if value == self._no_ret:
            return

        self._no_ret = value
        self.dirty = True

    @property
    def name(self):
        proj = self._cfg_model.project
        if proj is not None:
            if self._name is None:
                sym = proj.loader.find_symbol(self.addr)
                if sym is not None:
                    self._name = sym.name
            if self._name is None and isinstance(proj.arch, archinfo.ArchARM) and self.addr & 1:
                sym = proj.loader.find_symbol(self.addr - 1)
                if sym is not None:
                    self._name = sym.name
            if self.function_address and self._name is None:
                sym = proj.loader.find_symbol(self.function_address)
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
        if not kb and self._cfg_model.project is not None:
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
        obj = self._get_cmsg()
        obj.ea = self.addr
        obj.size = self.size
        obj.returning = self.has_return
        obj.instr_addrs.extend(self.instruction_addrs)
        if self.block_id is not None:
            if type(self.block_id) is int:
                obj.block_id.append(self.block_id)  # pylint:disable=no-member
            else:
                raise NotImplementedError("Non-integer block_id serialization is not supported for CFGNode")
        if self.simprocedure_name is not None:
            obj.simprocedure_name = self.simprocedure_name
        if self.no_ret is not None:
            obj.no_ret = self.no_ret
        if self.function_address is not None:
            obj.function_address = self.function_address
        obj.thumb = self.thumb
        if self.byte_string is not None:
            obj.byte_string = self.byte_string
        if self._name is not None:
            obj.name = self._name
        obj.is_syscall = self.is_syscall
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg=None):  # pylint:disable=arguments-differ
        block_id = None if len(cmsg.block_id) == 0 else cmsg.block_id[0]
        instruction_addrs = None if not cmsg.instr_addrs else list(cmsg.instr_addrs)

        node = cls(
            cmsg.ea,
            cmsg.size,
            cfg=cfg,
            block_id=block_id,
            instruction_addrs=instruction_addrs,
            simprocedure_name=cmsg.simprocedure_name if cmsg.HasField("simprocedure_name") else None,
            no_ret=cmsg.no_ret if cmsg.HasField("no_ret") else None,
            function_address=cmsg.function_address if cmsg.HasField("function_address") else None,
            thumb=cmsg.thumb,
            byte_string=cmsg.byte_string if cmsg.HasField("byte_string") else None,
            is_syscall=cmsg.is_syscall,
            name=cmsg.name if cmsg.HasField("name") else None,
        )
        node._has_return = cmsg.returning
        node._dirty = False
        return node

    #
    # Pickling
    #

    def __getstate__(self):
        return {
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
        return CFGNode(
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

    def merge(self, other):
        """
        Merges this node with the other, returning a new node that spans the both.
        """
        new_node = self.copy()
        new_node._size += other.size
        new_node.instruction_addrs += other.instruction_addrs
        # FIXME: byte_string should never be none, but it is sometimes
        # like, for example, patcherex test_cfg.py:test_fullcfg_properties
        if new_node.byte_string is None or other.byte_string is None:
            new_node._byte_string = None
        else:
            new_node._byte_string += other.byte_string
        new_node.dirty = True
        return new_node

    def __repr__(self):
        s = "<CFGNode "
        if self.name is not None:
            s += self.name + " "
        elif not isinstance(self.addr, SootAddressDescriptor):
            s += hex(self.addr)
        if self.size is not None:
            s += f"[{self.size}]"
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
            if self._cfg_model is not None and self._cfg_model.project is not None:
                hooker = self._cfg_model.project.hooked_by(self.addr)
            else:
                hooker = None
            return SyscallNode(self.addr, self.size, hooker)
        if self.is_simprocedure:
            if self._cfg_model is not None and self._cfg_model.project is not None:
                hooker = self._cfg_model.project.hooked_by(self.addr)
            else:
                hooker = None
            return HookNode(self.addr, self.size, hooker)
        return BlockNode(self.addr, self.size, thumb=self.thumb)

    @property
    def block(self) -> Block | SootBlock | None:
        if self.is_simprocedure or self.is_syscall:
            return None
        project = self._cfg_model.project  # everything in angr is connected with everything...
        if project is None:
            return None
        return project.factory.block(self.addr, size=self.size, opt_level=self._cfg_model._iropt_level)


class CFGENode(CFGNode):
    """
    The CFGNode that is used in CFGEmulated.
    """

    __slots__ = [
        "_callstack_key",
        "_syscall_name",
        "creation_failure_info",
        "depth",
        "final_states",
        "input_state",
        "looping_times",
        "return_target",
        "syscall",
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
        self._syscall_name = syscall_name
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

    @property
    def syscall_name(self) -> str | None:
        return self._syscall_name

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
            s += f"[{self.size}]"
        if self.looping_times > 0:
            s += f" - {self.looping_times}"
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
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.CFGENode()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()

        # Serialize base CFGNode fields into obj.base
        base = obj.base
        base.ea = self.addr
        base.size = self.size
        base.returning = self.has_return
        base.instr_addrs.extend(self.instruction_addrs)
        if self.simprocedure_name is not None:
            base.simprocedure_name = self.simprocedure_name
        base.no_ret = self.no_ret
        if self.function_address is not None:
            base.function_address = self.function_address
        base.thumb = self.thumb
        if self.byte_string is not None:
            base.byte_string = self.byte_string
        if self._name is not None:
            base.name = self._name
        base.is_syscall = self.is_syscall

        # Handle block_id (can be int or BlockID)
        if self.block_id is not None:
            if type(self.block_id) is int:
                base.block_id.append(self.block_id)
            else:
                # BlockID object
                block_id_msg = obj.block_id_obj
                block_id_msg.addr = self.block_id.addr
                if self.block_id.callsite_tuples is not None:
                    for val in self.block_id.callsite_tuples:
                        entry = block_id_msg.callsite_tuples.add()
                        if val is not None:
                            entry.has_value = True
                            entry.value = val
                block_id_msg.jump_type = self.block_id.jump_type

        # CFGENode-specific fields
        if self.callstack_key is not None:
            for val in self.callstack_key:
                entry = obj.callstack_key.add()
                if val is not None:
                    entry.has_value = True
                    entry.value = val

        if self.syscall_name is not None:
            obj.syscall_name = self.syscall_name

        obj.looping_times = self.looping_times

        if self.depth is not None:
            obj.depth = self.depth

        if self.return_target is not None:
            obj.return_target = self.return_target

        if self.creation_failure_info is not None:
            obj.creation_failure_info = self.creation_failure_info.long_reason

        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, cfg=None):  # pylint:disable=arguments-differ
        base = cmsg.base

        # Parse block_id
        block_id = None
        if cmsg.HasField("block_id_obj"):
            from angr.analyses.cfg.cfg_job_base import BlockID

            bid = cmsg.block_id_obj
            callsite_tuples = tuple(entry.value if entry.has_value else None for entry in bid.callsite_tuples)
            block_id = BlockID(bid.addr, callsite_tuples, bid.jump_type)
        elif len(base.block_id) > 0:
            block_id = base.block_id[0]

        instruction_addrs = list(base.instr_addrs) if base.instr_addrs else None

        callstack_key = None
        if cmsg.callstack_key:
            callstack_key = tuple(entry.value if entry.has_value else None for entry in cmsg.callstack_key)

        node = cls(
            base.ea,
            base.size,
            cfg,
            simprocedure_name=base.simprocedure_name if base.HasField("simprocedure_name") else None,
            no_ret=base.no_ret,
            function_address=base.function_address if base.HasField("function_address") else None,
            block_id=block_id,
            instruction_addrs=instruction_addrs,
            thumb=base.thumb,
            byte_string=base.byte_string if base.HasField("byte_string") else None,
            is_syscall=base.is_syscall,
            name=base.name if base.HasField("name") else None,
            # CFGENode specific
            syscall_name=cmsg.syscall_name if cmsg.HasField("syscall_name") else None,
            looping_times=cmsg.looping_times,
            depth=cmsg.depth if cmsg.HasField("depth") else None,
            callstack_key=callstack_key,
        )

        # Set fields that need post-init handling
        node._has_return = base.returning
        node._dirty = False

        if cmsg.HasField("return_target"):
            node.return_target = cmsg.return_target

        if cmsg.HasField("creation_failure_info"):
            # creation_failure_info is stored as repr(); reconstruct a stub object
            cfi = object.__new__(CFGNodeCreationFailure)
            cfi.short_reason = cmsg.creation_failure_info
            cfi.long_reason = cmsg.creation_failure_info
            cfi.traceback = []
            node.creation_failure_info = cfi

        return node

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
