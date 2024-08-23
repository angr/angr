from __future__ import annotations
from typing import TYPE_CHECKING
from collections import defaultdict

import claripy

from ..analyses import AnalysesHub
from ..analyses.reaching_definitions.function_handler import FunctionHandler
from ..knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
from ..storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ..knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from . import Analysis, VtableFinder, CFGFast, ReachingDefinitionsAnalysis

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.function_handler import FunctionCallData
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class PossibleObject:
    """
    This holds the address and class name of possible class instances.
    The address that it holds in mapped outside the binary so it is only valid in this analysis.
    TO DO: map the address to its uses in the registers/memory locations in the instructions
    """

    def __init__(self, size, addr, class_name=None):
        self.size = size
        # This address is only valid during RDA as we map new objects outside the already mapped region
        self.addr = addr
        self.class_name = class_name

    def __hash__(self):
        return hash((self.addr, self.size, self.class_name))

    def __eq__(self, other):
        return self.size == other.size and self.addr == other.size and self.class_name == other.class_name


class NewFunctionHandler(FunctionHandler):
    """
    This handles calls to the function new(), by recording the size parameter passed to it and also assigns a new
     address outside the mapped binary to the newly created space(possible object).

     It also tracks if the function called right after new() is passed the same 'this' pointer and is a constructor,
     if so we mark it as an instance of the class the constructor belongs to.(only for non stripped binaries)
    """

    def __init__(self, max_addr=None, new_func_addr=None, project=None):
        super().__init__()
        self.max_addr = max_addr

        # this is a map between an object addr outside the mapped binary and PossibleObject instance
        self.possible_objects_dict = {}

        # address of the new() function
        self.new_func_addr = new_func_addr
        self.project = project

    def hook(self, analysis):
        return self

    def handle_local_function(
        self,
        state: ReachingDefinitionsState,
        data: FunctionCallData,
    ):
        function_address = data.address
        if function_address == self.new_func_addr:
            word_size = self.project.arch.bits // self.project.arch.byte_width
            # check if this is a call to new()
            # reading from rdi for the size argument passed to new()
            cc = self.project.kb.functions[function_address].calling_convention
            if cc is not None:
                size_arg_reg_offset = self.project.arch.registers[cc.args[0].reg_name][0]
                size_arg_reg_size = cc.args[0].size
            else:
                size_arg_reg_offset = self.project.arch.registers["rdi"][0]
                size_arg_reg_size = word_size
            v0 = state.registers.load(size_arg_reg_offset, size_arg_reg_size).one_value()
            size = v0.concrete_value if v0 is not None and v0.concrete else None

            if size is not None:
                # None since we do not know it's class yet, it is a possible this pointer
                self.possible_objects_dict[self.max_addr] = PossibleObject(size, self.max_addr)

            # assigning eax a concrete address to track the possible this pointer
            if cc is not None:
                ret_val_reg_offset = self.project.arch.registers[cc.return_val.reg_name][0]
                ret_val_reg_size = cc.return_val.size
            else:
                ret_val_reg_offset = self.project.arch.registers["rax"][0]
                ret_val_reg_size = word_size
            atom = Register(ret_val_reg_offset, ret_val_reg_size)
            data.depends(
                atom,
                value=MultiValues(
                    offset_to_values={0: {claripy.BVV(self.max_addr, word_size * state.arch.byte_width)}}
                ),
            )
            # setting the values pointed by rax to zero
            memory_location = MemoryLocation(self.max_addr, size)
            offset_to_values = {}

            for offset in range(0, size, word_size):
                offset_to_values[offset] = {claripy.BVV(0, word_size * state.arch.byte_width)}
            data.depends(memory_location, value=MultiValues(offset_to_values=offset_to_values))
            self.max_addr += size

        else:
            if self.project.kb.functions.contains_addr(function_address):
                func = self.project.kb.functions.get_by_addr(function_address)
                if func is not None and "ctor" in func.demangled_name:
                    # check if rdi has a possible this pointer/ object address, if so then we can assign this object
                    # this class
                    # also if the func is a constructor(not stripped binaries)
                    for addr, possible_object in self.possible_objects_dict.items():
                        v1 = state.registers.load(72, state.arch.bits // state.arch.byte_width).one_value()
                        obj_addr = v1.concrete_value if v1 is not None and v1.concrete else None
                        if obj_addr is not None and addr == obj_addr:
                            col_ind = self.project.kb.functions[function_address].demangled_name.rfind("::")
                            class_name = self.project.kb.functions[function_address].demangled_name[:col_ind]
                            possible_object.class_name = class_name


class StaticObjectFinder(Analysis):
    """
    This analysis tries to find objects on the heap based on calls to new(), and subsequent calls to constructors with
     the 'this' pointer
    """

    def __init__(self):
        vtable_analysis = self.project.analyses[VtableFinder].prep()()
        self.vtables_list = vtable_analysis.vtables_list
        self.possible_objects = {}

        # for stripped binaries
        # This is a mapping between the constructors and the objects that use them
        self.possible_constructors = defaultdict(list)

        self._analyze()

    def _analyze(self):
        if "CFGFast" not in self.project.kb.cfgs:
            self.project.analyses[CFGFast].prep()(cross_references=True)
        all_functions = self.project.kb.functions
        # this is the addr where all the this pointers returned by new() will be pointing to
        max_addr = self.project.loader.main_object.max_addr + 8
        new_func_addr = self.project.kb.functions["_Znwm"].addr
        for func in all_functions.values():
            if func.is_simprocedure:
                continue

            cc = func.calling_convention
            word_size = self.project.arch.bits // self.project.arch.byte_width
            # the map fo this ptrs
            newhandler = NewFunctionHandler(max_addr=max_addr, new_func_addr=new_func_addr, project=self.project)
            max_addr = newhandler.max_addr
            # this performs RDA as well as mark possible object instances for non stripped binaries
            rd = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
                func, observe_all=True, function_handler=newhandler
            )
            for addr, pos_obj in newhandler.possible_objects_dict.items():
                self.possible_objects[addr] = pos_obj

            # for stripped binary we check if the first function called after new(),
            # is passed the this pointer(returned by new)...
            # if so then we say that it is possibly a constructor
            for node in func.graph.nodes():
                if func.get_call_target(node.addr) == new_func_addr:
                    ret_node_addr = func.get_call_return(node.addr)
                    ret_node = self.project.factory.block(ret_node_addr)
                    call_after_new_addr = func.get_call_target(ret_node_addr)
                    rd_before_node = rd.get_reaching_definitions_by_node(ret_node_addr, OP_BEFORE)

                    if cc is not None:
                        ret_val_reg_offset = self.project.arch.registers[cc.return_val.reg_name][0]
                        ret_val_reg_size = cc.return_val.size
                    else:
                        ret_val_reg_offset = self.project.arch.registers["rax"][0]
                        ret_val_reg_size = word_size
                    v0 = rd_before_node.registers.load(ret_val_reg_offset, ret_val_reg_size).one_value()
                    addr_of_new_obj = v0.concrete_value if v0 is not None and v0.concrete else None

                    # we need the state right before the call
                    if ret_node.vex.jumpkind == "Ijk_Call" and ret_node.vex.instruction_addresses:
                        last_ins_addr = ret_node.instruction_addrs[-1]
                        rd_after_node = rd.get_reaching_definitions_by_insn(last_ins_addr, OP_BEFORE)
                    else:
                        rd_after_node = rd.get_reaching_definitions_by_insn(ret_node_addr, OP_AFTER)

                    if cc is not None:
                        this_ptr_reg_offset = self.project.arch.registers[cc.args[0].reg_name][0]
                        this_ptr_reg_size = cc.args[0].size
                    else:
                        this_ptr_reg_offset = self.project.arch.registers["rdi"][0]
                        this_ptr_reg_size = word_size
                    v1 = rd_after_node.registers.load(this_ptr_reg_offset, this_ptr_reg_size).one_value()
                    addr_in_rdi = v1.concrete_value if v1 is not None and v1.concrete else None

                    if addr_of_new_obj is not None and addr_of_new_obj == addr_in_rdi:
                        self.possible_constructors[call_after_new_addr].append(self.possible_objects[addr_of_new_obj])


AnalysesHub.register_default("StaticObjectFinder", StaticObjectFinder)
