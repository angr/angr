from . import Analysis
from ..state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..knowledge_plugins.key_definitions.definition import Definition
from ..code_location import CodeLocation
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from angr.engines.vex.heavy.heavy import HeavyVEXMixin

class SymbolicDefinition(Definition):
    def __init__(self, atom, codeloc, dummy, tags, symbolic_value=None):
        super().__init__(atom, codeloc, dummy, tags)
        self.symbolic_value = symbolic_value

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc and self.symbolic_value == other.symbolic_value

    def __repr__(self):
        if not self.tags:
            return '<Definition {Atom:%s, Symbolic value:%s, Codeloc:%s}%s>' % (self.atom, self.symbolic_value, self.codeloc, "" if not self.dummy else "dummy")
        else:
            return '<Definition {Tags:%s, Atom:%s, Symbolic value:%s, Codeloc:%s}%s>' % (repr(self.tags), self.atom, self.symbolic_value, self.codeloc,
                                                                    "" if not self.dummy else " dummy")
    def __hash__(self):
        return hash((self.atom, self.codeloc, self.symbolic_value))


class ObjectFinder(ForwardAnalysis, Analysis):
    def __init__(self, func=None, func_graph=None, block=None, max_iterations=1):
        self.symbolic_values_by_loc = {}
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

    def check_for_call_to_new(self, state):
        import ipdb;
        ipdb.set_trace()

    def is_new_func(self,state):
        if state.solver.eval(state.inspect.function_address) in self.possible_new_functions:
            return True
        else:
            False

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
            blank_state.inspect.b('call', when=BP_BEFORE, action=self.check_for_call_to_new, condition=self.is_new_func)
            cfg = self.project.analyses.CFGEmulated(initial_state=blank_state, starts=[func])

            # for rd_def in rd.all_definitions:
            #     codeloc = rd_def.codeloc
            #     if codeloc in self.symbolic_values_by_loc:
            #         self.symbolic_values_by_loc[codeloc]
            #     import ipdb;ipdb.set_trace()


from angr.analyses import AnalysesHub
AnalysesHub.register_default('ObjectFinder', ObjectFinder)