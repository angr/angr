import os
from typing import Dict, Tuple,TYPE_CHECKING

import networkx

import claripy
import angr
from angr.analyses.state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule

if TYPE_CHECKING:
    import networkx


binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')


# state graph acquired. define a rule
class MinDelayRule_PedGreen(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # ped light is green
        for node in graph.nodes():
            if dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 1 and dict(node)['PEDESTRIAN_RED_LIGHT'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph'):
        # ped light is red
        for node in graph.nodes():
            if dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 0 and dict(node)['PEDESTRIAN_RED_LIGHT'] == 1:
                yield node


class MinDelayRule_Orange(MinDelayBaseRule):
    def node_a(self, graph: 'networkx.DiGraph'):
        # ped light is orange
        for node in graph.nodes():
            if dict(node)['ORANGE_LIGHT'] == 1 and dict(node)['RED_LIGHT'] == 0:
                yield node

    def node_b(self, graph: 'networkx.DiGraph'):
        # ped light is red
        for node in graph.nodes():
            if dict(node)['ORANGE_LIGHT'] == 0 and dict(node)['RED_LIGHT'] == 1:
                yield node


class NoPedGreenCarGreen(IllegalNodeBaseRule):
    def verify_node(self, graph: 'networkx.DiGraph', node) -> bool:
        if dict(node)['GREEN_LIGHT'] == 1 and dict(node)['PEDESTRIAN_GREEN_LIGHT'] == 1:
            # both car green light and the pedestrian green light are on at the same time
            # this is bad!
            return False
        return True


def test_smoketest():
    # binary_path = '/home/bonnie/PLCRCA/test/Traffic_Light_Short_Ped.so'
    # variable_path = '/home/bonnie/PLCRCA/test/Traffic_Light_Short_Ped.json'

    # binary_path = '/home/bonnie/PLCRCA/Traffic_Light_both_green/build/Traffic_Light_both_green.so'
    # variable_path = '/home/bonnie/PLCRCA/test/Traffic_Light_variables.json'

    # binary_path = '/home/bonnie/PLCRCA/arm32/Traffic_Light/build/Traffic_Light.so'
    # binary_path = '/home/bonnie/PLCRCA/arm32/Traffic_Light_Short_Ped/build/Traffic_Light_Short_Ped.so'
    # variable_path = '/home/bonnie/PLCRCA/arm32/Traffic_Light_variables.json'

    binary_path = sys.argv[1]
    variable_path = sys.argv[2]
    
    proj = angr.Project(binary_path, auto_load_libs=False)

    cfg = proj.analyses.CFG()

    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

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

    # base_addr = 0x428ee0  # Traffic_Light_short_ped
    # base_addr = 0x44bf00  # Traffic_Light_both_green

    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)

    def switch_on(state):
        # switch on
        switch = next(x for x in data['variables'] if x['name'] == "SWITCH_BUTTON")
        switch_value_addr = base_addr + int(switch['address'], 16)
        switch_flag_addr = switch_value_addr + 1
        state.memory.store(switch_value_addr, claripy.BVV(0x1, 8), endness=proj.arch.memory_endness)  # value
        state.memory.store(switch_flag_addr, claripy.BVV(0x2, 8), endness=proj.arch.memory_endness)  # flag

    # define abstract fields
    fields_desc = {}
    config_fields = {}
    for variable in data['variables']:
        if variable['type'] == 'output':
            fields_desc[variable['name']] = (base_addr + int(variable['address'], 16), variable['size'])
        elif variable['type'] == 'config':
            config_fields[variable['name']] = (base_addr + int(variable['address'], 16), variable['size'])


    # pre-constrain configuration variables so that we can track them
    config_vars = {}
    for var_name, (var_addr, var_size) in config_fields.items():
        print("[.] Preconstraining %s..." % var_name)
        symbolic_v = claripy.BVS(var_name, var_size * 8)
        concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
        initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
        initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
        config_vars['var_name'] = symbolic_v

    # fields_desc = {
    #     'RED': (base_addr + 0x8, 1),
    #     'ORANGE': (base_addr + 0xa, 1),
    #     'GREEN': (base_addr + 0xc, 1),
    #     'PED_RED': (base_addr + 0xe, 1),
    #     'PED_GREEN': (base_addr + 0x10, 1),
    # }
    fields = angr.analyses.state_graph_recovery.AbstractStateFields(fields_desc)
    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecovery(func, fields, time_addr, init_state=initial_state, switch_on=switch_on)
    state_graph = sgr.state_graph

    finder = RuleVerifier(state_graph)
    rule = MinDelayRule_Orange(2.0)
    r, src, dst = finder.verify(rule)
    assert r is True

    rule = MinDelayRule_PedGreen(10.0)
    r, src, dst = finder.verify(rule)

    assert r is False
    # find the constraint and the source of the timing interval from the state graph
    for path in networkx.all_simple_paths(state_graph, src, dst):
        for a, b in zip(path, path[1:]):
            data = state_graph[a][b]
            constraint = data['time_delta_constraint']
            if data['time_delta_src'] is None:
                continue
            block_addr, stmt_idx = data['time_delta_src']

            if constraint is not None and block_addr is not None and stmt_idx is not None:
                print(f"[.] Found a time delta source: {constraint}@{block_addr:#x}:{stmt_idx}")

                # root cause it
                rc = proj.analyses.RootCause(block_addr, stmt_idx, constraint=constraint)
                print("[.] Full root causes:", rc.causes)
                # filter them
                print("[.] Filtering root causes...")
                causes = rule.filter_root_causes(rc.causes)
                print("[+] Filtered root causes:", causes)

    rule = NoPedGreenCarGreen()
    r, src, dst = finder.verify(rule)
    assert r is True

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "state_graph.dot")           # dot -Tpng state_graph.dot > out.png

    # import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_smoketest()
