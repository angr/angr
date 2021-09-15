import os
import struct
import sys
import json
import pickle
from typing import Optional, Dict

import networkx

import claripy
import angr
from angr.analyses.state_graph_recovery.differ import diff_coredump, find_base_addr_in_coredump, compare_state_graphs
from angr.analyses.state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule
from angr.analyses.state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch


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
    switch_on = u"\U0001F532" if sys.platform != "win32" else "ON"
    switch_off = u"\U0001F533" if sys.platform != "win32" else "OFF"

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


def generate_state_graph(library_path: Optional[str], variables_data: Dict,
                         project: Optional[angr.Project]=None) -> networkx.DiGraph:
    if project is None:
        proj = angr.Project(library_path, auto_load_libs=False)
    else:
        proj = project

    cfg = proj.analyses.CFG(show_progressbar=True)
    _hook_py_extensions(proj, cfg)

    # run the state initializer
    init = cfg.kb.functions['config_init__']
    init_callable = proj.factory.callable(init.addr, perform_merge=False)
    init_callable.perform_call()
    initial_state = init_callable.result_state

    assert initial_state is not None

    base_addr = int(variables_data['variable_base_addr'], 16) if isinstance(variables_data['variable_base_addr'], str) \
        else variables_data['variable_base_addr']
    time_addr = int(variables_data['time_addr'], 16) if isinstance(variables_data['time_addr'], str) \
        else variables_data['time_addr']

    # define abstract fields
    fields_desc, config_fields = _generate_field_desc(variables_data, base_addr)

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

    return state_graph


def mem_patch_object(obj, section, new_content: bytes):
    # find the in-memory offset of the section
    section_offset = section.vaddr - obj.mapped_base
    # find which memory backer offers this section
    for idx, (backer_offset, content) in enumerate(obj.memory._backers):
        if backer_offset <= section_offset < backer_offset + len(content):
            # we found it!
            offset_in_backer = section_offset - backer_offset
            obj.memory._backers[idx] = (
                backer_offset,
                content[:offset_in_backer] + new_content[:len(content) - offset_in_backer]
            )
            break
    else:
        raise RuntimeError(f"Cannot find the memory backer to patch for section {section}")


def test_load_coredump():

    base_dir = r"C:\Users\Fish\Desktop\temp\mitre"

    # this test loads a given core dump and compares it against a known binary on a section-by-section basis
    core_dump_location = "core.516581"
    so_filename = "6c561e958548a9b19bdf83f89d68c4b1.so"
    so_path = os.path.join(base_dir, so_filename)

    global data

    diffs = diff_coredump(os.path.join(base_dir, core_dump_location), so_filename, so_path)
    assert diffs

    #
    # Load the core dump for analysis
    #

    proj_coredump = angr.Project(os.path.join(base_dir, core_dump_location))
    so_baseaddr = find_base_addr_in_coredump(proj_coredump, so_filename)
    so_filepath = os.path.join(base_dir, so_filename)
    # let's load the original binary at the same memory location
    proj = angr.Project(so_filepath, main_opts={'base_addr': so_baseaddr}, auto_load_libs=False)
    # memory patch it
    mem_patch_object(proj.loader.main_object, diffs[0][0], diffs[0][1])
    print("[+] Patched runtime differences found in the core dump into the project.")

    # analyze differences - which bytes are different?
    

    #
    # generate a state graph on the core dump
    #
    variable_file_path = os.path.join(base_dir, "6c561e958548a9b19bdf83f89d68c4b1.json")
    with open(variable_file_path) as f:
        data = json.load(f)
    # we also need to update addresses in the json file to reflect differences between static addresses and runtime
    # memory addresses
    data["variable_base_addr"] = hex(int(data['variable_base_addr'], 16) + (so_baseaddr - 0x400000))
    data["time_addr"] = hex(int(data['time_addr'], 16) + (so_baseaddr - 0x400000))
    print("[.] Generating a runtime state graph...")
    if os.path.isfile("runtime_state_graph.dump"):
        with open("runtime_state_graph.dump", "rb") as f:
            runtime_state_graph = pickle.loads(f.read())
    else:
        runtime_state_graph = generate_state_graph(None, data, project=proj)
        with open("runtime_state_graph.dump", "wb") as f:
            pickle.dump(runtime_state_graph, f)

    #
    # generate a state graph on the original binary
    #
    so_filepath = os.path.join(base_dir, so_filename)
    variable_file_path = os.path.join(base_dir, "6c561e958548a9b19bdf83f89d68c4b1.json")
    with open(variable_file_path) as f:
        data = json.load(f)

    if os.path.isfile("reference_state_graph.dump"):
        with open("reference_state_graph.dump", "rb") as f:
            reference_state_graph = pickle.loads(f.read())
    else:
        reference_state_graph = generate_state_graph(so_filepath, data)
        with open("reference_state_graph.dump", "wb") as f:
            pickle.dump(reference_state_graph, f)

    #
    # Compare two state graphs
    #

    compare_state_graphs(runtime_state_graph, so_baseaddr, reference_state_graph, 0x400000)


if __name__ == "__main__":
    # test_find_violations()
    # test_verify_patched_binary()
    test_load_coredump()
