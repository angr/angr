import claripy
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from . import Analysis
from ..analyses.reaching_definitions.function_handler import FunctionHandler
from ..knowledge_plugins.key_definitions.atoms import Tmp, Register, MemoryLocation
from ..storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ..knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER


class PossibleObject():
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
    def __init__(self, max_addr=None, new_func_addr=None, cfg=None):
        self.max_addr = max_addr

        # this is a map between an object addr outside the mapped binary and PossibleObject instance
        self.possible_objects_dict = {}

        # address of the new() function
        self.new_func_addr = new_func_addr
        self.cfg = cfg

    def hook(self, analysis):
        return self

    def handle_local_function(self, state, function_address, call_stack,
                              maximum_local_call_depth, visited_blocks, dep_graph,
                              src_ins_addr=None,
                              codeloc=None):
        if function_address == self.new_func_addr:
            # check if this is a call to new()
            # reading from rdi for the size argument passed to new()
            size = state.register_definitions.load(72, state.arch.bits//state.arch.byte_width).values[0].pop()._model_concrete.value

            # None since we do not know it's class yet, it a possible this pointer
            self.possible_objects_dict[self.max_addr] = PossibleObject(size, self.max_addr)

            # assigning eax a concrete address to track the possible this pointer
            atom = Register(16, 8)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {claripy.BVV(self.max_addr,
                                     8 * state.arch.byte_width
                                )}}))
            # setting the values pointed by rax to zero
            memory_location = MemoryLocation(self.max_addr, size)
            offset_to_values = {}
            for offset in range(0, size, 8):
                offset_to_values[offset] = {claripy.BVV(0, 8 * state.arch.byte_width)}
            state.kill_and_add_definition(memory_location, codeloc, MultiValues(offset_to_values=offset_to_values))
            self.max_addr += size

        elif "ctor" in self.cfg.kb.functions[function_address].demangled_name:
            # check if rdi has a possible this pointer/ object address, if so then we can assign this object this class
            # also if the func is a constructor(not stripped binaries)
            for addr in self.possible_objects_dict:
                obj_addr = state.register_definitions.load(72, state.arch.bits // state.arch.byte_width).values[0].pop()._model_concrete.value
                if addr == obj_addr:
                    col_ind = self.cfg.kb.functions[function_address].demangled_name.rfind("::")
                    class_name = self.cfg.kb.functions[function_address].demangled_name[:col_ind]
                    self.possible_objects_dict[addr].class_name = class_name
        executed_rda = True
        return executed_rda, state, visited_blocks, dep_graph


class StaticObjectFinder(ForwardAnalysis, Analysis):
    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1):
        vtable_analysis = self.project.analyses.VtableFinder()
        self.vtables_list = vtable_analysis.vtables_list
        self.possible_objects = set()

        # for stripped binaries
        # This is a set of functions that are possible constructors
        self.possible_constructors = set()

        self._analyze()

    def is_new_func(self, state):
        if state.solver.eval(state.inspect.function_address) in self.possible_new_functions:
            return True
        else:
            False

    def _analyze(self):
        self.cfg = self.project.analyses.CFGFast(cross_references=True)
        all_functions = self.cfg.kb.functions
        # this is the addr where all the this pointers returned by new() will be pointing to
        max_addr = self.project.loader.main_object.max_addr + 8
        new_func_addr = self.cfg.kb.functions['_Znwm'].addr
        for func in all_functions:
            if func == 0x40129d:
                # the map fo this ptrs
                newhandler = NewFunctionHandler(max_addr=max_addr, new_func_addr=new_func_addr, cfg=self.cfg)
                max_addr = newhandler.max_addr
                # this performs RDA as well as mark possible object instances for non stripped binaries
                rd = self.project.analyses.ReachingDefinitions(all_functions[func], observe_all=True, function_handler=newhandler)
                for addr, pos_obj in newhandler.possible_objects_dict.items():
                    self.possible_objects.add(pos_obj)
                print(rd.get_reaching_definitions_by_node(0x4012c3, OP_AFTER))

                # for stripped binary we check if the first function called after new(), is passed the this pointer(returned by new)...
                # if so then we say that it is possibly a constructor
                for node in all_functions[func].graph.nodes():
                    if all_functions[func].get_call_target(node.addr) == new_func_addr:
                        ret_node_addr = all_functions[func].get_call_return(node.addr)
                        call_after_new_addr = all_functions[func].get_call_target(ret_node_addr)
                        rd_before_node = rd.get_reaching_definitions_by_node(ret_node_addr, OP_BEFORE)
                        addr_of_new_obj = rd_before_node.register_definitions.load(16,8).values[0].pop()._model_concrete.value

                        rd_after_node = rd.get_reaching_definitions_by_node(ret_node_addr, OP_AFTER)
                        addr_in_rdi = rd_after_node.register_definitions.load(72, 8).values[0].pop()._model_concrete.value

                        if addr_of_new_obj == addr_in_rdi:
                            self.possible_constructors.add((call_after_new_addr))

        import ipdb;ipdb.set_trace()


from angr.analyses import AnalysesHub
AnalysesHub.register_default('StaticObjectFinder', StaticObjectFinder)