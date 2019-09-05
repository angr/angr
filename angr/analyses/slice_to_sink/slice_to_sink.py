from functools import reduce

from .transitions import direct_transitions_to, merge_transitions


class SliceToSink:
    """
    The representation of a slice of a CFG.
    """
    def __init__(self, target, transitions=None):
        """
        :param angr.knowledge_plugins.functions.function.Function target:
            The targeted sink, to which every path in the slice leads.
        :param Dict[int,List[int]] transitions:
            A mapping representing transitions in the graph.
            Indexes are source addresses and values a list of destination addresses, for which there exists a transition
            in the slice from source to destination.
        """
        self._target = target
        self._transitions = transitions or {}

    @property
    def transitions(self):
        """
        :return Dict[int,List[int]]: The transitions in the slice.
        """
        return self._transitions

    @property
    def transitions_as_tuples(self):
        """
        :return List[Tuple[int,int]]: The list of transitions as pairs of (source, destination).
        """
        return reduce(
            lambda acc, source: acc + [ (source, destination) for destination in self._transitions[source] ],
            self._transitions.keys(),
            []
        )

    @property
    def target(self):
        """
        :return angr.knowledge_plugins.functions.function.Function:
            The targeted sink function, from which the slice is constructed.
        """
        return self._target

    @property
    def _origins(self):
        return set(self._transitions.keys())

    @property
    def _destinations(self):
        return set(reduce(
            lambda acc, destinations: acc + destinations,
            self._transitions.values(),
            []
        ))

    @property
    def nodes(self):
        """
        :return List[int]: The complete list of addresses present in the slice.
        """
        return list(self._origins | self._destinations)

    @property
    def entrypoints(self):
        """
        Entrypoints are all source addresses that are not the destination address of any transition.

        :return List[int]: The list of entrypoints addresses.
        """
        return sorted(list(self._origins - self._destinations))

    def add_transitions_to(self, node):
        """
        Add the transitions flowing into the node to the current slice.

        :param angr.knowledge_plugins.cfg.cfg_node.CFGNode node:
            The node, which we want to add the transitions flowing into.

        :return SliceToSink: The slice, to which the transitions to node have been added.
        """
        transitions = direct_transitions_to(node)
        self._transitions = merge_transitions(transitions, self._transitions)

    def is_empty(self):
        """
        Test if a given slice does not contain any transition.

        :return bool: True if the <SliceToSink> instance does not contain any transitions. False otherwise.
        """
        return not bool(self._transitions)
