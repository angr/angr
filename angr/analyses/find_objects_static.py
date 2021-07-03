import claripy

from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from . import Analysis
from ..state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..knowledge_plugins.key_definitions.definition import Definition
from ..code_location import CodeLocation
from ..analyses.reaching_definitions.function_handler import FunctionHandler
from ..knowledge_plugins.key_definitions.atoms import Tmp, Register, MemoryLocation
from ..storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

class PossibleObject():
    def __init__(self, size, addr, class_name=None):
        self.size = size
        self.addr = addr
        self.class_name = class_name


class CppLibFunctionHandler(FunctionHandler):
    def __init__(self, max_addr=None, new_func_addr=None, cfg=None):
        self.max_addr = max_addr
        self.possible_objects = {}
        # address of the new() function
        self.new_func_addr = new_func_addr
        self.cfg=cfg

    def hook(self, analysis):
        return self

    def handle_local_function(self, state, function_address, call_stack,
                              maximum_local_call_depth, visited_blocks, dep_graph,
                              src_ins_addr=None,
                              codeloc=None):
        if function_address == self.new_func_addr:
            self.prev_function_is_new = True
            # reading from rdi for the size argument passed to new()
            size = state.register_definitions.load(72, state.arch.bits//state.arch.byte_width).values[0].pop()._model_concrete.value

            # None since we do not know it's class yet, it a possible this pointer
            self.possible_objects[self.max_addr] = PossibleObject(size, self.max_addr)

            # assigning eax a concrete address to track the possible this pointer
            atom = Register(16, 8)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {claripy.BVV(self.max_addr,
                                     8 * state.arch.byte_width
                                )}}))

            memory_location = MemoryLocation(self.max_addr, size)
            offset_to_values = {}
            for offset in range(0, size, 8):
                offset_to_values[offset] = {claripy.BVV(0, 8 * state.arch.byte_width)}
            state.kill_and_add_definition(memory_location, codeloc, MultiValues(offset_to_values=offset_to_values))
            import ipdb;ipdb.set_trace()
            self.max_addr += size

        elif "ctor" in self.cfg.kb.functions[function_address].demangled_name:
            for addr in self.possible_objects:
                # check if rdi has a possible this pointer/ object address, if so then we can assign this object this class
                obj_addr = state.register_definitions.load(72, state.arch.bits // state.arch.byte_width).values[
                               0].pop()._model_concrete.value
                if addr == obj_addr:
                    col_ind = self.cfg.kb.functions[function_address].demangled_name.rfind("::")
                    class_name = self.cfg.kb.functions[function_address].demangled_name[:col_ind]
                    self.possible_objects[addr].class_name = class_name
        # else:
        #     # we guess that the function called after calling new() is the constructor
        #     for addr in self.possible_objects:
        #         # check if rdi has a possible this pointer/ object address, if so then we can assign this object this class
        #         obj_addr = state.register_definitions.load(72, state.arch.bits // state.arch.byte_width).values[
        #                        0].pop()._model_concrete.value
        #         if addr == obj_addr:
        #             col_ind = self.cfg.kb.functions[function_address].demangled_name.rfind("::")
        #             if col_ind == -1:
        #                 class_name = self.cfg.kb.functions[function_address].name
        #
        #             else:
        #                 class_name = self.cfg.kb.functions[function_address].name
        #             self.possible_objects[addr].class_name = class_name


        executed_rda = True
        return executed_rda, state, visited_blocks, dep_graph


class StaticObjectFinder(ForwardAnalysis, Analysis):
    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1):
        self.symbolic_values_by_loc = {}
        self.possible_class_instance_pointers = {}
        vtable_analysis = self.project.analyses.VtableFinder()
        self.vtables_list = vtable_analysis.vtables_list
        self.possible_objects_by_func = {}
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
                cpphandler = CppLibFunctionHandler(max_addr=max_addr, new_func_addr=new_func_addr, cfg=self.cfg)
                rd = self.project.analyses.ReachingDefinitions(all_functions[func], observe_all=True, function_handler=cpphandler)
                self.possible_objects_by_func[func] = cpphandler.possible_objects
                import ipdb;ipdb.set_trace()



from angr.analyses import AnalysesHub
AnalysesHub.register_default('StaticObjectFinder', StaticObjectFinder)