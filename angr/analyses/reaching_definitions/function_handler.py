from typing import TYPE_CHECKING, List, Set, Optional
from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from angr.code_location import CodeLocation
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class FunctionHandler(ABC):
    """
    An abstract base class for function handlers.

    To work properly, we expect function handlers to:
      - Be related to a <ReachingDefinitionsAnalysis>;
      - Provide a `handle_local_function` method.
    """

    @abstractmethod
    def hook(self, analysis):
        """
        A <FunctionHandler> needs information about the context in which it is executed.
        A <ReachingDefinitionsAnalysis> would "hook" into a handler by calling: `<FunctionHandler>.hook(self)`.

        :param angr.analyses.ReachingDefinitionsAnalysis analysis: A <ReachingDefinitionsAnalysis> using this <FunctionHandler>.

        :return FunctionHandler:
        """
        raise NotImplementedError()

    @abstractmethod
    def handle_local_function(self, state: 'ReachingDefinitionsState', function_address: int, call_stack: List,
                              maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: 'DepGraph',
                              src_ins_addr: Optional[int]=None,
                              codeloc: Optional['CodeLocation']=None):
        """
        :param state: The state at the entry of the function, i.e. the function's input state.
        :param function_address: The address of the function to handle.
        :param call_stack:
        :param maximum_local_call_depth:
        :param visited_blocks: A set of the addresses of the previously visited blocks.
        :param dep_graph: A definition-use graph, where nodes represent definitions, and edges represent uses.
        :param codeloc: The code location of the call to the analysed function.

        :return Tuple[Boolean,LiveDefinitions,List<ailment.Block|Block|CodeNode|CFGNode>,DepGraph]:
        """
        raise NotImplementedError()
