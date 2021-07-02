from . import Analysis
from ..state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..knowledge_plugins.key_definitions.definition import Definition
from ..code_location import CodeLocation
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from angr.engines.vex.heavy.heavy import HeavyVEXMixin
import claripy



class PossibleObject:
    def __init__(self, obj_addr, members=None):
        self.obj_addr = obj_addr
        self.members = {} if members is None else members


class ObjectFinder(ForwardAnalysis, Analysis):
    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1):
        self.symbolic_values_by_loc = {}
        self.possible_class_instance_pointers = {}
        vtable_analysis = self.project.analyses.VtableFinder()
        self.vtables_list = vtable_analysis.vtables_list
        self.possible_objects = {}
        self._analyze()


    def save_symbolic_reg_value(self, state):
        cur_codeloc = CodeLocation(state.globals['cur_block_addr'], stmt_idx=state.globals['cur_stmt_idx'], ins_addr=state.globals['cur_ins_addr'])
        self.symbolic_values_by_loc[cur_codeloc] = state.inspect.reg_write_expr

    def save_symbolic_mem_value(self, state):
        cur_codeloc = CodeLocation(state.globals['cur_block_addr'], stmt_idx=state.globals['cur_stmt_idx'], ins_addr=state.globals['cur_ins_addr'])
        self.symbolic_values_by_loc[cur_codeloc] = state.inspect.mem_write_expr

    def set_cur_block_address(self, state):
        state.globals['cur_block_addr'] = state.inspect.address

    def set_cur_ins_address(self, state):
        state.globals['cur_ins_addr'] = state.inspect.instruction

    def set_cur_stmt_idx(self, state):
        state.globals['cur_stmt_idx'] = state.inspect.statement

    def check_for_ret_from_new(self, state):
        new_this_pointer_name = "this_pointer_"+str(hex(state.addr))
        state.regs.rax = claripy.BVS(new_this_pointer_name, self.project.arch.bits)

    def is_new_func(self, state):
        if state.solver.eval(state.inspect.function_address) in self.possible_new_functions:
            return True
        else:
            False

    def is_this_pointer(self, state):
        # check if this could possible be a this pointer
        if not isinstance(state.inspect.mem_write_address, int) and state.inspect.mem_write_address.symbolic:
            for arg in state.inspect.mem_write_address.args:
                if isinstance(arg, str) and arg.startswith("this_pointer_"):
                    return True
                elif arg is not None and isinstance(arg, claripy.ast.bv.BV) and arg.symbolic:
                    for sub_arg in arg.args:
                        if isinstance(sub_arg, str) and sub_arg.startswith("this_pointer_"):
                            return True
        else:
            return False

    def catch_write_to_this_pointer_address(self, state):
        for arg in state.inspect.mem_write_address.args:
            if isinstance(arg, str) and arg.startswith("this_pointer_"):
                for vtable in self.vtables_list:
                    if state.solver.eval(state.inspect.mem_write_expr) == vtable.vaddr:
                        codeloc = CodeLocation(state.scratch.irsb.addr, stmt_idx=state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)
                        self.possible_class_instance_pointers[codeloc] = state.inspect.mem_write_address
                        members = {arg: vtable.vaddr}
                        if arg not in self.possible_objects:
                            self.possible_objects[arg] = PossibleObject(state.inspect.mem_write_address, members)
                        else:
                            # make assumptions about class hierarchy
                            self.possible_objects[arg].members[arg] = vtable.vaddr
            elif arg is not None and isinstance(arg, claripy.ast.bv.BV) and arg.symbolic:
                for sub_arg in arg.args:
                    if isinstance(sub_arg, str) and sub_arg.startswith("this_pointer_"):
                        if sub_arg in self.possible_objects:
                            if arg not in self.possible_objects[sub_arg].members:
                                self.possible_objects[sub_arg].members[arg] = state.inspect.mem_write_expr
                            else:
                                # make assumptions about class hierarchy
                                self.possible_objects[sub_arg].members[arg] = state.inspect.mem_write_expr

        import ipdb;
        ipdb.set_trace()

    def _analyze(self):
        self.cfg = self.project.analyses.CFGFast(cross_references=True)
        all_functions = self.cfg.kb.functions

        self.possible_new_functions = []
        for func in all_functions:
            if all_functions[func].name == "_Znwm":
                self.possible_new_functions.append(func)

        for func in all_functions:
            #rd = self.project.analyses.ReachingDefinitions(all_functions[func], observe_all=True)
            blank_state = self.project.factory.blank_state(addr=func)
            # blank_state.inspect.b('instruction', when=BP_BEFORE, action=self.set_cur_ins_address)
            # blank_state.inspect.b('irsb', when=BP_BEFORE, action=self.set_cur_block_address)
            # blank_state.inspect.b('statement', when=BP_BEFORE, action=self.set_cur_stmt_idx)
            # blank_state.inspect.b('reg_write', when=BP_AFTER, action=self.save_symbolic_reg_value)
            # blank_state.inspect.b('mem_write', when=BP_AFTER, action=self.save_symbolic_mem_value)
            blank_state.inspect.b('return', when=BP_BEFORE, action=self.check_for_ret_from_new, condition=self.is_new_func)
            blank_state.inspect.b('mem_write', when=BP_AFTER, action=self.catch_write_to_this_pointer_address,
                                  condition=self.is_this_pointer)
            cfg = self.project.analyses.CFGEmulated(initial_state=blank_state, starts=[func])

            # for rd_def in rd.all_definitions:
            #     codeloc = rd_def.codeloc
            #     if codeloc in self.symbolic_values_by_loc:
            #         self.symbolic_values_by_loc[codeloc]
            #     import ipdb;ipdb.set_trace()


from angr.analyses import AnalysesHub
AnalysesHub.register_default('ObjectFinder', ObjectFinder)