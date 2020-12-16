
import os

import claripy
import angr
from angr.analyses.state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule


binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')


def test_smoketest():
    path = r"C:\Users\Fish\Desktop\temp\mitre\Traffic_Light_Short_Ped\build\Traffic_Light_Short_Ped.so"
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFG()

    # We do not support Python eval (obviously)
    proj.hook(cfg.kb.functions['PYTHON_EVAL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['PYTHON_POLL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_debug'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_py_ext'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None

    base_addr = 0x428ee0  # coming from reverse engineering

    # switch on
    initial_state.memory.store(base_addr + 4, claripy.BVV(0x1, 8), endness=proj.arch.memory_endness)  # value
    initial_state.memory.store(base_addr + 5, claripy.BVV(0x2, 8), endness=proj.arch.memory_endness)  # flag

    # define abstract fields
    fields_desc = {
        'RED': (base_addr + 0x8, 1),
        'ORANGE': (base_addr + 0xa, 1),
        'GREEN': (base_addr + 0xc, 1),
        'PED_RED': (base_addr + 0xe, 1),
        'PED_GREEN': (base_addr + 0x10, 1),
    }
    fields = angr.analyses.state_graph_recovery.AbstractStateFields(fields_desc)

    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecovery(func, fields, init_state=initial_state)
    state_graph = sgr.state_graph

    # state graph acquired. define a rule
    class MinDelayRule(MinDelayBaseRule):
        def node_a(self, graph: 'networkx.DiGraph'):
            # ped light is green
            for node in graph.nodes():
                if dict(node)['PED_GREEN'] == 1 and dict(node)['PED_RED'] == 0:
                    yield node

        def node_b(self, graph: 'networkx.DiGraph'):
            # ped light is red
            for node in graph.nodes():
                if dict(node)['PED_GREEN'] == 0 and dict(node)['PED_RED'] == 1:
                    yield node

    class NoPedGreenCarGreen(IllegalNodeBaseRule):
        def verify_node(self, graph: 'networkx.DiGraph', node) -> bool:
            if dict(node)['GREEN'] == 1 and dict(node)['PED_GREEN'] == 1:
                # both car green light and the pedstrain green light are on at the same time
                # this is bad!
                return False
            return True


    finder = RuleVerifier(state_graph)
    rule = MinDelayRule(10.0)
    finder.verify(rule)

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "state_graph.dot")


if __name__ == "__main__":
    test_smoketest()
