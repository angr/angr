from angr.knowledge_plugins.key_definitions.atoms import Register
from typing import TYPE_CHECKING, List, Set, Optional, Dict
from dataclasses import dataclass, field
import logging

from cle import Symbol

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.sim_type import SimTypeBottom
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.calling_conventions import SimCC
from angr.sim_type import SimTypeFunction
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.functions import Function
from angr.analyses.reaching_definitions.dep_graph import FunctionCallRelationships
from angr.code_location import CodeLocation


if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

l = logging.getLogger(__name__)


@dataclass
class FunctionEffect:
    sources: Set[Atom]
    value: Optional[MultiValues] = None
    sources_defns: Optional[Set[Definition]] = None

@dataclass
class FunctionCallData:
    callsite: CodeLocation
    address_multi: MultiValues
    address: Optional[int] = None
    symbol: Optional[Symbol] = None
    function: Optional[Function] = None
    name: Optional[str] = None
    cc: Optional[SimCC] = None
    prototype: Optional[SimTypeFunction] = None
    args_atoms: Optional[List[Set[Atom]]] = None
    args_values: Optional[List[MultiValues]] = None
    ret_atoms: Optional[Set[Atom]] = None
    visited_blocks: Optional[Set[int]] = None
    effects: Dict[Atom, FunctionEffect] = field(default_factory=lambda: {})

    def depends(self, dest: Atom, *sources: Atom, value: Optional[MultiValues] = None):
        if dest in self.effects:
            l.warning("Function handler for %s seems to be implemented incorrectly - multiple stores to single atom")
        else:
            self.effects[dest] = FunctionEffect(set(sources), value=value)



# pylint: disable=unused-argument, no-self-use
# TODO FIXME XXX DO NOT MERGE UNTIL AUDREY HAS FIXED THE DOCSTRINGS
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

    def handle_function(self, state: "ReachingDefinitionsState", data: FunctionCallData):
        # META
        if data.address is None:
            val = data.address_multi.one_value()
            if val is not None and val.op == "BVV":
                data.address = val.args[0]
        if data.symbol is None and data.address is not None:
            data.symbol = state.analysis.project.loader.find_symbol(data.address)
        if data.function is None and data.address is not None:
            data.function = state.analysis.project.kb.functions.get(data.address, None)
        if data.name is None and data.function is not None:
            data.name = data.function.name
        if data.name is None and data.symbol is not None:
            data.name = data.symbol.name
        if data.cc is None and data.function is not None:
            data.cc = data.function.calling_convention
        if data.prototype is None and data.function is not None:
            data.prototype = data.function.prototype
        if data.address is not None and (data.cc is None or data.prototype is None):
            hook = None if not state.analysis.project.is_hooked(data.address) else state.analysis.project.hooked_by(data.address)
            if hook is None and data.address in state.analysis.project.loader.main_object.reverse_plt:
                plt_name = state.analysis.project.loader.main_object.reverse_plt[data.address]
                hook = state.analysis.project.symbol_hooked_by(plt_name)
            if data.cc is None and hook is not None:
                data.cc = hook.cc
            if data.prototype is None and hook is not None:
                data.prototype = hook.prototype
        if data.cc is None:
            data.cc = state.analysis.project.factory.cc()  # sketchy
        if data.args_atoms is None and data.cc is not None and data.prototype is not None:
            data.args_atoms = self.c_args_as_atoms(state, data.cc, data.prototype)
        if data.ret_atoms is None and data.cc is not None and data.prototype is not None:
            data.ret_atoms = self.c_return_as_atoms(state, data.cc, data.prototype)
        # TODO what to do about args.values...

        # PROCESS
        if data.name is not None and hasattr(self, f"handle_{data.name}"):
            handler = getattr(self, f"handle_impl_{data.name}")
        elif data.address is not None:
            if state.analysis.project.loader.main_object.contains_addr(data.address):
                handler = self.handle_local_function
            else:
                handler = self.handle_external_function
        else:
            handler = self.handle_indirect_function

        handler(state, data)

        if data.cc is not None:
            for reg in self.caller_saved_regs_as_atoms(state, data.cc):
                if reg not in data.effects:
                    data.depends(reg)
        if state.arch.call_pushes_ret:
            sp_atom = self.stack_pointer_as_atom(state)
            if sp_atom not in data.effects:  # let the user override the stack pointer if they want
                new_sp = None
                sp_val = state.live_definitions.get_value_from_atom(sp_atom)
                if sp_val is not None:
                    one_sp_val = sp_val.one_value()
                    if one_sp_val is not None:
                        new_sp = MultiValues(one_sp_val + state.arch.call_sp_fix)
                data.depends(sp_atom, value=new_sp)

        # OUTPUT
        args_defns = [set().union(*(state.get_definitions(atom) for atom in atoms)) for atoms in (data.args_atoms or set())]
        all_args_defns = set().union(*args_defns)
        other_input_defns = set()
        ret_defns = data.ret_atoms or set()
        other_output_defns = set()

        for effect in data.effects.values():
            if effect.sources_defns is None:
                effect.sources_defns = set().union(*(set(state.get_definitions(atom)) for atom in effect.sources))
                other_input_defns |= effect.sources_defns - all_args_defns
        for dest, effect in data.effects.items():
            # TODO how to generate the codelocation for an unknown address?
            value = effect.value if effect.value is not None else MultiValues(state.top(dest.bits))
            mv, defs = state.kill_and_add_definition(dest, CodeLocation(data.address, None), value, uses=effect.sources_defns)
            other_output_defns |= defs - ret_defns
        if state._dep_graph is not None:
            state.analysis.function_calls[data.callsite] = FunctionCallRelationships(
                target=data.address,
                args_defns=args_defns,
                other_input_defns=other_input_defns,
                ret_defns=ret_defns,
                other_output_defns=other_output_defns,
            )


    def handle_generic_function(self, state: "ReachingDefinitionsState", data: FunctionCallData):
        if data.args_atoms is None:
            return
        sources = {atom for arg in data.args_atoms for atom in arg}
        for atom in data.ret_atoms:
            data.depends(atom, *sources)

    handle_indirect_function = handle_generic_function
    handle_local_function = handle_generic_function
    handle_external_function = handle_generic_function

    @staticmethod
    def c_args_as_atoms(state: "ReachingDefinitionsState", cc: SimCC, prototype: SimTypeFunction) -> List[Set[Atom]]:
        return [
            {Atom.from_argument(footprint_arg, state.arch, full_reg=True) for footprint_arg in arg.get_footprint()}
            for arg in cc.arg_locs(prototype)
        ]

    @staticmethod
    def c_return_as_atoms(state: "ReachingDefinitionsState", cc: SimCC, prototype: SimTypeFunction) -> Set[Atom]:
        if prototype.returnty is not None and not isinstance(prototype.returnty, SimTypeBottom):
            return {
                Atom.from_argument(footprint_arg, state.arch, full_reg=True)
                for footprint_arg in cc.return_val(prototype.returnty).get_footprint()
            }
        else:
            return set()

    @staticmethod
    def caller_saved_regs_as_atoms(state: "ReachingDefinitionsState", cc: SimCC) -> Set[Register]:
        return (
            {Register(*state.arch.registers[reg], state.arch) for reg in cc.CALLER_SAVED_REGS}
            if cc.CALLER_SAVED_REGS is not None
            else set()
        )

    @staticmethod
    def stack_pointer_as_atom(state) -> Register:
        return Register(state.arch.sp_offset, state.arch.bytes, state.arch)
