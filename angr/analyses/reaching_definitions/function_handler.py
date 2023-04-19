from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.sim_type import SimTypeBottom
from functools import wraps
from typing import TYPE_CHECKING, List, Set, Optional, Tuple, Union
import logging

from cle import Symbol

from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.calling_conventions import SimCC
from angr.sim_type import SimTypeFunction

l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from angr.code_location import CodeLocation
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


# pylint: disable=unused-argument, no-self-use
class FunctionHandler:
    """
    An abstract base class for function handlers.

    To work properly, we expect function handlers to:
      - Be related to a <ReachingDefinitionsAnalysis>;
      - Provide a `handle_local_function` method.
    """

    def hook(self, analysis) -> "FunctionHandler":
        """
        A <FunctionHandler> needs information about the context in which it is executed.
        A <ReachingDefinitionsAnalysis> would "hook" into a handler by calling: `<FunctionHandler>.hook(self)`.

        :param angr.analyses.ReachingDefinitionsAnalysis analysis: A RDA using this <FunctionHandler>.

        :return FunctionHandler:
        """
        return self

    def handle_local_function(
        self,
        state: "ReachingDefinitionsState",
        function_address: int,
        call_stack: Optional[List],
        maximum_local_call_depth: int,
        visited_blocks: Set[int],
        dep_graph: "DepGraph",
        src_ins_addr: Optional[int] = None,
        codeloc: Optional["CodeLocation"] = None,
    ) -> Tuple[bool, "ReachingDefinitionsState", "Set[int]", "DepGraph"]:
        """
        :param state: The state at the entry of the function, i.e. the function's input state.
        :param function_address: The address of the function to handle.
        :param call_stack:
        :param maximum_local_call_depth:
        :param visited_blocks: A set of the addresses of the previously visited blocks.
        :param dep_graph: A definition-use graph, where nodes represent definitions, and edges represent uses.
        :param codeloc: The code location of the call to the analysed function.
        """
        l.warning("Please implement the local function handler with your own logic.")
        return False, state, visited_blocks, dep_graph

    def handle_unknown_call(
        self, state: "ReachingDefinitionsState", src_codeloc: Optional["CodeLocation"] = None
    ) -> Tuple[bool, "ReachingDefinitionsState"]:
        """
        Called when the RDA encounters a function call to somewhere really weird.
        E.g. the function address was invalid (not even TOP),
        or the address of the function is outside of the main object, but also not a known symbol
        :param state:
        :param src_codeloc:
        :return:
        """
        l.error("Encountered unknown call. Implement the unknown function handler with your own logic.")
        return False, state

    def handle_indirect_call(
        self, state: "ReachingDefinitionsState", src_codeloc: Optional["CodeLocation"] = None
    ) -> Tuple[bool, "ReachingDefinitionsState"]:
        """
        The RDA encountered a function call with multiple possible values, or TOP as a target
        :param state:
        :param src_codeloc:
        :return:
        """
        l.warning("Please implement the indirect function handler with your own logic.")
        return False, state

    def handle_external_function_fallback(
        self, state: "ReachingDefinitionsState", src_codeloc: Optional["CodeLocation"] = None
    ) -> Tuple[bool, "ReachingDefinitionsState"]:
        """
        Fallback for a call to an external function, that has no specific implementation
        :param state:
        :param src_codeloc:
        :return:
        """
        return False, state

    def handle_external_function_symbol(
        self,
        state: "ReachingDefinitionsState",
        symbol: Symbol,
        src_codeloc: Optional["CodeLocation"] = None,
    ) -> Tuple[bool, "ReachingDefinitionsState"]:
        """
        The generic handler for external functions with a known symbol
        This is different from
        The default behavior using hasattr/getattr supports existing code,
        but you can also implement the check if the external function is supported in another way,
        e.g. similar to SimProcedures
        :param state:
        :param symbol:
        :param src_codeloc:
        :return:
        """
        if symbol.name:
            return self.handle_external_function_name(state, symbol.name, src_codeloc)
        else:
            l.warning("Symbol %s for external function has no name, falling back to generic handler", symbol)
            return self.handle_external_function_fallback(state, src_codeloc)

    def handle_external_function_name(
        self,
        state: "ReachingDefinitionsState",
        ext_func_name: str,
        src_codeloc: Optional["CodeLocation"] = None,
    ) -> Tuple[bool, "ReachingDefinitionsState"]:
        handler_name = "handle_%s" % ext_func_name
        if ext_func_name and hasattr(self, handler_name):
            return getattr(self, handler_name)(state, src_codeloc)

        l.warning("No handler for external function %s(), falling back to generic handler", ext_func_name)
        return self.handle_external_function_fallback(state, src_codeloc)

    def guess_cc(self, state, func_name=None) -> SimCC:
        hooked_by = state.analysis.project.symbol_hooked_by(func_name) if func_name is not None else None
        if hooked_by is not None:
            return hooked_by.cc
        return state.analysis.project.factory.cc()

    def c_args_as_atoms(self, state, cc, prototype) -> List[Set[Atom]]:
        return [
            {Atom.from_argument(footprint_arg, state.arch, full_reg=True) for footprint_arg in arg.get_footprint()}
            for arg in cc.arg_locs(prototype)
        ]

    def c_return_as_atoms(self, state, cc, prototype) -> Set[Atom]:
        if prototype.returnty is not None and not isinstance(prototype.returnty, SimTypeBottom):
            return {Atom.from_argument(footprint_arg, state.arch, full_reg=True) for footprint_arg in cc.return_val(prototype.returnty).get_footprint()}
        else:
            return set()


class SimpleUsesFunctionHandler(FunctionHandler):
    def handle_external_function_name(self, state, ext_func_name, src_codeloc=None):
        handler_name = "handle_%s" % ext_func_name
        if ext_func_name and hasattr(self, handler_name):
            return super().handler_external_function_name(state, ext_func_name, src_codeloc=src_codeloc)

        hooked_by = state.analysis.project.symbol_hooked_by(ext_func_name)
        if hooked_by is not None:
            for arg in self.c_args_as_atoms(state, hooked_by.cc, hooked_by.prototype):
                for atom in arg:
                    state.add_use(atom, src_codeloc)
            for atom in self.c_return_as_atoms(state, hooked_by.cc, hooked_by.prototype):
                state.kill_and_add_definition(atom, src_codeloc, MultiValues(state.top(atom.bits)))
            return True, state

        return super().handler_external_function_name(state, ext_func_name, src_codeloc=src_codeloc)

def c_args(prototype: Union[str, SimTypeFunction], cc: Optional[SimCC]=None):
    def decorator(f):
        @functools.wraps(f)
        def inner(self: FunctionHandler, state: ReachingDefinitionsState):
            nonlocal cc
            guessed_cc = cc if cc is not None else self.guess_cc(state)
            atomsets = self.c_args_as_atoms(state, guessed_cc, prototype)
            values = [state.live_definitions.get_value_from_atom(next(iter(atomset))) if len(atomset) == 1 else None for atomset in atomsets]
            return f(self, state, *values)
