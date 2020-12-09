from typing import Generator, Any, Iterable, Tuple
import logging

import networkx

_l = logging.getLogger(name=__name__)


class BaseRule:
    def eval(self, graph: 'networkx.DiGraph') -> Tuple[bool,Any,Any]:
        raise NotImplementedError()


class IllegalNodeBaseRule(BaseRule):
    """
    Ensure all nodes comply with the defined requirements.
    """
    def verify_node(self, graph: 'networkx.DiGraph', node: Any) -> bool:
        raise NotImplementedError()

    def eval(self, graph: 'networkx.DiGraph') -> Tuple[bool,Any,Any]:
        for node in graph.nodes():
            r = self.verify_node(graph, node)
            if not r:
                return False, node, None
        return True, None, None


class MinDelayBaseRule(BaseRule):
    """
    Ensure the delay between two states must be at least certain amount of time.
    """
    def __init__(self, min_delay):
        self.min_delay = min_delay

    def node_a(self, graph: 'networkx.DiGraph') -> Iterable[Any]:
        raise NotImplementedError()

    def node_b(self, graph: 'networkx.DiGraph') -> Iterable[Any]:
        raise NotImplementedError()

    def delay(self, graph: 'networkx.DiGraph', node_a, node_b) -> Generator[float,None,None]:
        for path in networkx.all_simple_paths(graph, node_a, node_b):
            t = 0
            for src, dst in zip(path, path[1:]):
                data = graph.get_edge_data(src, dst)
                if 'time_delta' in data and data['time_delta'] is not None:
                    t += data['time_delta']
            yield t

    def eval(self, graph) -> Tuple[bool,Any,Any]:
        nodes_a = self.node_a(graph)
        nodes_b = self.node_b(graph)

        for a in nodes_a:
            for b in nodes_b:
                for t in self.delay(graph, a, b):
                    if t < self.min_delay:
                        return False, a, b

        return True, None, None


class RuleVerifier:
    """
    Finding rule violations by travering a state graph.
    """
    def __init__(self, abs_state_graph: 'networkx.DiGraph'):
        self.abs_state_graph = abs_state_graph

    def verify(self, rule: BaseRule):
        safe, src_node, dst_node = rule.eval(self.abs_state_graph)

        _l.warning("Checked against %s: %s, %s, %s", rule, safe, src_node, dst_node)

        return safe

