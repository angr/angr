import os
import struct
from typing import TYPE_CHECKING

import pickle
import networkx
import sys
import json
import claripy
import angr
from angr.analyses.state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule
from angr.analyses.state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

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


def printstate(abs_state):
    # delayed import
    try:
        from termcolor import colored, cprint
    except ImportError:
        def colored(x, _): return x

    light_on = '\u25cf'
    light_off = '\u25cb'
    switch_on = u"\U0001F532"
    switch_off = u"\U0001F533"

    SWITCH_BUTTON = switch_off
    RED_LIGHT = light_off
    ORANGE_LIGHT = light_off
    GREEN_LIGHT = light_off
    PEDESTRIAN_RED_LIGHT = light_off
    PEDESTRIAN_GREEN_LIGHT = light_off

    for state in abs_state:
        if state[0] == "SWITCH_BUTTON":
            if state[1] == 1:
                SWITCH_BUTTON = switch_on
        elif state[0] == "RED_LIGHT":
            if state[1] == 1:
                RED_LIGHT = light_on
        elif state[0] == "ORANGE_LIGHT":
            if state[1] == 1:
                ORANGE_LIGHT = light_on
        elif state[0] == "GREEN_LIGHT":
            if state[1] == 1:
                GREEN_LIGHT = light_on
        elif state[0] == "PEDESTRIAN_RED_LIGHT":
            if state[1] == 1:
                PEDESTRIAN_RED_LIGHT = light_on
        elif state[0] == "PEDESTRIAN_GREEN_LIGHT":
            if state[1] == 1:
                PEDESTRIAN_GREEN_LIGHT = light_on
        else:
            print(state)

    print("SWITCH BUTTON  ", SWITCH_BUTTON)
    print("CAR LIGHTS     ", colored(RED_LIGHT, 'red'), colored(ORANGE_LIGHT, 'yellow'), colored(GREEN_LIGHT, 'green'))
    print("PED LIGHTS     ", colored(PEDESTRIAN_RED_LIGHT, 'red'), colored(PEDESTRIAN_GREEN_LIGHT, 'green'))

def switch_on(state):
    # switch on
    base_addr = int(data['variable_base_addr'], 16)
    switch = next(x for x in data['variables'] if x['name'] == "SWITCH_BUTTON")
    switch_value_addr = base_addr + int(switch['address'], 16)
    switch_flag_addr = switch_value_addr + 1
    state.memory.store(switch_value_addr, claripy.BVV(0x1, 8), endness=state.memory.endness)  # value
    state.memory.store(switch_flag_addr, claripy.BVV(0x2, 8), endness=state.memory.endness)  # flag


def _hook_py_extensions(proj, cfg):
    proj.hook(cfg.kb.functions['PYTHON_EVAL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['PYTHON_POLL_body__'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_debug'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    proj.hook(cfg.kb.functions['__publish_py_ext'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())


def _generate_field_desc(data, base_addr: int):
    # define abstract fields
    fields_desc = {}
    config_fields = {}
    for variable in data['variables']:
        if variable['type'] == 'output':
            fields_desc[variable['name']] = (base_addr + int(variable['address'], 16),
                                             variable.get('sort', "int"),
                                             variable['size'],
                                             )
        elif variable['type'] == 'config':
            config_fields[variable['name']] = (base_addr + int(variable['address'], 16),
                                               variable.get('sort', "int"),
                                               variable['size'],
                                               )

    return fields_desc, config_fields


def test_patch_generation():
    binary_path = sys.argv[1]

    proj = angr.Project(binary_path, auto_load_libs=False)

    from angr.analyses.state_graph_recovery.apis import DataItemCause
    patch = generate_patch(proj.arch, [DataItemCause(0x44e3c0+0x1b0, "float", 4, "LIGHT_LEVEL")])
    patch_id = 0
    output_path = f"{binary_path}.patched.{patch_id:02d}"
    binary_dir = os.path.dirname(binary_path)
    output_path = f"{binary_dir}/patch.{patch_id:02d}.py"
    cfg = proj.analyses.CFG()
    apply_patch(patch, binary_path, output_path, proj, cfg.kb.functions['__run'].addr)
    return


def test_find_violations():
    binary_path = sys.argv[1]
    variable_path = sys.argv[2]
    
    proj = angr.Project(binary_path, auto_load_libs=False)

    global data
    with open(variable_path) as f:
        data = json.load(f)
    # print(data)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()
    _hook_py_extensions(proj, cfg)

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None

    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)

    # define abstract fields
    fields_desc, config_fields = _generate_field_desc(data, base_addr)

    # pre-constrain configuration variables so that we can track them
    config_vars = {}
    symbolic_config_var_to_fields = {}
    for var_name, (var_addr, var_type, var_size) in config_fields.items():
        print("[.] Preconstraining %s..." % var_name)
        # if var_type == "float":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_FLOAT)
        # elif var_type == "double":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_DOUBLE)
        # else:
        symbolic_v = claripy.BVS(var_name, var_size * 8)
        concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
        initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
        initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
        config_vars[var_name] = symbolic_v
        symbolic_config_var_to_fields[symbolic_v] = var_name, var_addr, var_type, var_size

    fields = angr.analyses.state_graph_recovery.AbstractStateFields(fields_desc)
    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecovery(func, fields, time_addr, init_state=initial_state, switch_on=switch_on,
                                           config_vars=set(config_vars.values()), printstate=printstate)
    state_graph = sgr.state_graph
    pickle.dumps(sgr, -1)

    finder = RuleVerifier(state_graph)
    rule = MinDelayRule_Orange(2.0)
    r, src, dst = finder.verify(rule)
    assert r is True

    rule = MinDelayRule_PedGreen(40.0)
    r, src, dst = finder.verify(rule)

    assert r is False
    # find the constraint and the source of the timing interval from the state graph
    for path in networkx.all_simple_paths(state_graph, src, dst):
        for a, b in zip(path, path[1:]):
            data = state_graph[a][b]
            constraint = data['time_delta_constraint']

            if data['time_delta_src'] is None:
                continue
            block_addr, stmt_idx = data['time_delta_src']  # this is the location where final constraint was verified

            if constraint is not None and block_addr is not None and stmt_idx is not None:
                print(f"[.] Found a time delta source: {constraint}@{block_addr:#x}:{stmt_idx}")

                # root cause it
                rc = proj.analyses.RootCause(proj.arch, block_addr, stmt_idx, constraint=constraint,
                                             expression_source=sgr._expression_source,
                                             config_vars=symbolic_config_var_to_fields,
                                             )
                print("[.] All root causes:")
                for idx, cause in enumerate(rc.causes):
                    print(idx, cause)
                # filter them
                print("[.] Retrieving most likely causes...")
                causes = rule.filter_root_causes(rc.causes)
                print("[+] Most likely causes:", causes)

                # interactive
                patch_id = 0
                while True:
                    patch = generate_patch(proj.arch, rc.causes)
                    if patch is None:
                        break
                    bin_dir = os.path.dirname(binary_path)
                    out_path = f"{bin_dir}/patch.{patch_id:02d}.py"
                    apply_patch(patch, binary_path, out_path, proj, func.addr)

                    patch_id += 1

    rule = NoPedGreenCarGreen()
    r, src, dst = finder.verify(rule)
    assert r is True

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "state_graph.dot")


def test_verify_patched_binary():
    binary_path = sys.argv[1]
    variable_path = sys.argv[2]

    proj = angr.Project(binary_path, auto_load_libs=False)

    with open(variable_path) as f:
        data = json.load(f)

    # We do not support Python eval (obviously)
    cfg = proj.analyses.CFG()
    _hook_py_extensions(proj, cfg)

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None

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
    fields_desc, config_fields = _generate_field_desc(data, base_addr)

    # pre-constrain configuration variables so that we can track them
    config_vars = {}
    symbolic_config_var_to_fields = {}
    for var_name, (var_addr, var_type, var_size) in config_fields.items():
        print("[.] Preconstraining %s..." % var_name)
        # if var_type == "float":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_FLOAT)
        # elif var_type == "double":
        #     symbolic_v = claripy.FPS(var_name, claripy.fp.FSORT_DOUBLE)
        # else:
        symbolic_v = claripy.BVS(var_name, var_size * 8)
        concrete_v = initial_state.memory.load(var_addr, size=var_size, endness=proj.arch.memory_endness)
        initial_state.memory.store(var_addr, symbolic_v, endness=proj.arch.memory_endness)
        initial_state.preconstrainer.preconstrain(concrete_v, symbolic_v)
        config_vars[var_name] = symbolic_v
        symbolic_config_var_to_fields[symbolic_v] = var_name, var_addr, var_type, var_size

    def patch_all(state):
        # apply patches previously generated

        # Note that we must patch PED_GREEN_TIME since this variable is only updated during standstill
        p0 = EditDataPatch(base_addr + 0x1d8, struct.pack("<Q", 41), name="PATCH_PED_GREEN_TIME")  # PED_GREEN_TIME
        apply_patch_on_state(p0, state)

        # PED_GREEN_TIME = MIN_WALK_TIME * (1.0 + 1.0 * LIGHT_LEVEL)

        # Updating LIGHT_LEVEL or MIN_WALK_TIME *after standstill* does not impact the pedestrian green light interval
        # Enabling the following two lines and commenting out p0 will lead to a safety violation being detected
        # p1 = EditDataPatch(base_addr + 0x1b0, struct.pack("<f", 10.0), name="PATCH_LIGHT_LEVEL")  # LIGHT_LEVEL
        # apply_patch_on_state(p1, state)

    fields = angr.analyses.state_graph_recovery.AbstractStateFields(fields_desc)
    func = cfg.kb.functions['__run']
    sgr = proj.analyses.StateGraphRecovery(func, fields, time_addr, init_state=initial_state, switch_on=switch_on,
                                           config_vars=set(config_vars.values()), printstate=printstate,
                                           patch_callback=patch_all)
    state_graph = sgr.state_graph

    finder = RuleVerifier(state_graph)
    rule = MinDelayRule_Orange(2.0)
    r, src, dst = finder.verify(rule)
    assert r is True

    rule = MinDelayRule_PedGreen(40.0)
    r, src, dst = finder.verify(rule)
    assert r is True

    rule = NoPedGreenCarGreen()
    r, src, dst = finder.verify(rule)
    assert r is True

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "state_graph.patched.dot")


if __name__ == "__main__":
    test_find_violations()
    # test_verify_patched_binary()
