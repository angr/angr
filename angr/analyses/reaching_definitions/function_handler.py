from abc import ABC, abstractmethod


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
    def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth, visited_blocks, dep_graph, codeloc=None):
        """
        :param angr.analyses.reaching_definitions.reaching_definitions.LiveDefinitions state:
            The state at the entry of the function, i.e. the function's input state.
        :param int function_address: The address of the function to handle.
        :param List[Function] call_stack:
        :param int maximum_local_call_depth:
        :param List<ailment.Block|Block|CodeNode|CFGNode> visited_blocks:
            A list of previously visited blocks.
        :param angr.analyses.reaching_definitions.dep_graph.DepGraph dep_graph:
            A definition-use graph, where nodes represent definitions, and edges represent uses.
        :param angr.analyses.code_location.CodeLocation.CodeLocation codeloc:
            The code location of the call to the analysed function.

        :return Tuple[Boolean,LiveDefinitions,List<ailment.Block|Block|CodeNode|CFGNode>,DepGraph]:
        """
        raise NotImplementedError()
