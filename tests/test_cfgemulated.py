import nose
import time
import pickle
import networkx

import logging
l = logging.getLogger("angr.tests.test_cfgemulated")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

import angr
from angr import options as o


def compare_cfg(standard, g, function_list):
    """
    Standard graph comes with addresses only, and it is based on instructions, not on basic blocks
    """

    def get_function_name(addr):
        start = 0
        end = len(function_list) - 1

        while start <= end:
            mid = (start + end) / 2
            f = function_list[mid]
            if addr < f['start']:
                end = mid - 1
            elif addr > f['end']:
                start = mid + 1
            else:
                return f['name']

        return None

    # Sort function list
    function_list = sorted(function_list, key=lambda x: x['start'])

    # Convert the IDA-style CFG into VEX-style CFG
    s_graph = networkx.DiGraph()
    all_nodes = sorted(standard.nodes())
    addr_to_basicblock = {}
    last_basicblock = None
    for n in all_nodes:
        if last_basicblock is None:
            last_basicblock = (n, n)

        block = last_basicblock
        successors = standard.successors(n)
        if len(successors) == 1 and successors[0] >= block[0]:
            last_basicblock = (block[0], successors[0])
        else:
            # Save the existing block
            addr_to_basicblock[block[0]] = block

            # Create edges
            for s in successors:
                s_graph.add_edge(block[0], s)

            # Clear last_basicblock so that we create a new basicblock next time
            last_basicblock = None

    graph = networkx.DiGraph()
    for src, dst in g.edges():
        graph.add_edge(src.addr, dst.addr)

    # Graph comparison
    for src, dst in s_graph.edges():
        if graph.has_edge(src, dst):
            continue
        else:
            # Edge doesn't exist in our CFG
            l.error("Edge (%s-0x%x, %s-0x%x) only exists in IDA CFG.", get_function_name(src), src, get_function_name(dst), dst)

    for src, dst in graph.edges():
        if s_graph.has_edge(src, dst):
            continue
        else:
            # Edge doesn't exist in our CFG
            l.error("Edge (%s-0x%x, %s-0x%x) only exists in angr's CFG.", get_function_name(src), src, get_function_name(dst), dst)

def perform_single(binary_path, cfg_path=None):
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic',
                        load_options={'auto_load_libs': False})
    start = time.time()
    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1, fail_fast=True)
    end = time.time()
    duration = end - start
    bbl_dict = cfg.nodes()

    l.info("CFG generated in %f seconds.", duration)
    l.info("Contains %d members in BBL dict.", len(bbl_dict))

    if cfg_path is not None and os.path.isfile(cfg_path):
        # Compare the graph with a predefined CFG
        info = pickle.load(open(cfg_path, "rb"))
        standard = info['cfg']
        functions = info['functions']
        graph = cfg.graph

        compare_cfg(standard, graph, functions)
    else:
        l.warning("No standard CFG specified.")

def disabled_cfg_0():
    binary_path = test_location + "/x86_64/cfg_0"
    cfg_path = binary_path + ".cfg"
    perform_single(binary_path, cfg_path)

def disabled_cfg_1():
    binary_path = test_location + "/x86_64/cfg_1"
    cfg_path = binary_path + ".cfg"
    perform_single(binary_path, cfg_path)

def disabled_cfg_2():
    binary_path = test_location + "/armel/test_division"
    cfg_path = binary_path + ".cfg"
    perform_single(binary_path, cfg_path)

def disabled_cfg_3():
    binary_path = test_location + "/mips/test_arrays"
    cfg_path = binary_path + ".cfg"
    perform_single(binary_path, cfg_path)

def disabled_cfg_4():
    binary_path = test_location + "/mipsel/darpa_ping"
    cfg_path = binary_path + ".cfg"
    perform_single(binary_path, cfg_path)

def test_additional_edges():
    # Test the `additional_edges` parameter for CFG generation

    binary_path = test_location + "/x86_64/switch"
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic',
                        load_options={'auto_load_libs': False})
    additional_edges = {
        0x400573 : [ 0x400580, 0x40058f, 0x40059e ]
    }
    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=0, additional_edges=additional_edges, fail_fast=True,
                                    resolve_indirect_jumps=False,  # For this test case, we need to disable the
                                                                   # jump table resolving, otherwise CFGEmulated
                                                                   # can automatically find the node 0x4005ad.
                                    )

    nose.tools.assert_not_equal(cfg.get_any_node(0x400580), None)
    nose.tools.assert_not_equal(cfg.get_any_node(0x40058f), None)
    nose.tools.assert_not_equal(cfg.get_any_node(0x40059e), None)
    nose.tools.assert_equal(cfg.get_any_node(0x4005ad), None)

def test_not_returning():
    # Make sure we are properly labeling functions that do not return in function manager

    binary_path = test_location + "/x86_64/not_returning"
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        load_options={'auto_load_libs': False}
                        )
    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=0, fail_fast=True)  # pylint:disable=unused-variable

    # function_a returns
    nose.tools.assert_not_equal(proj.kb.functions.function(name='function_a'), None)
    nose.tools.assert_true(proj.kb.functions.function(name='function_a').returning)

    # function_b does not return
    nose.tools.assert_not_equal(proj.kb.functions.function(name='function_b'), None)
    nose.tools.assert_false(proj.kb.functions.function(name='function_b').returning)

    # function_c does not return
    nose.tools.assert_not_equal(proj.kb.functions.function(name='function_c'), None)
    nose.tools.assert_false(proj.kb.functions.function(name='function_c').returning)

    # main does not return
    nose.tools.assert_not_equal(proj.kb.functions.function(name='main'), None)
    nose.tools.assert_false(proj.kb.functions.function(name='main').returning)

    # function_d should not be reachable
    nose.tools.assert_equal(proj.kb.functions.function(name='function_d'), None)

def disabled_cfg_5():
    binary_path = test_location + "/mipsel/busybox"
    cfg_path = binary_path + ".cfg"

    perform_single(binary_path, cfg_path)

def test_cfg_6():
    function_addresses = [0xfa630, 0xfa683, 0xfa6d4, 0xfa707, 0xfa754, 0xfa779, 0xfa7a9, 0xfa7d6, 0xfa844, 0xfa857,
                          0xfa8d9, 0xfa92f, 0xfa959, 0xfa9fb, 0xfabd6, 0xfac61, 0xfacc2, 0xfad29, 0xfaf94, 0xfbd07,
                          0xfc100, 0xfc101, 0xfc14f, 0xfc18e, 0xfc25e, 0xfc261, 0xfc3c6, 0xfc42f, 0xfc4a3, 0xfc4cf,
                          0xfc4db, 0xfc5ba, 0xfc5ef, 0xfc5fe, 0xfc611, 0xfc682, 0xfc6b7, 0xfc7fc, 0xfc8a8, 0xfc8e7,
                          0xfcb42, 0xfcb50, 0xfcb72, 0xfcc3b, 0xfcc7a, 0xfcc8b, 0xfccdc, 0xfd1a3, 0xff06e]

    # We need to add DO_CCALLS to resolve long jmp and support real mode
    o.modes['fastpath'] |= {o.DO_CCALLS}
    binary_path = test_location + "/i386/bios.bin.elf"
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        page_size=1)
    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1, fail_fast=True)  # pylint:disable=unused-variable
    nose.tools.assert_greater_equal(set(f for f in proj.kb.functions), set(function_addresses))
    o.modes['fastpath'] ^= {o.DO_CCALLS}

def test_fauxware():
    binary_path = test_location + "/x86_64/fauxware"
    cfg_path = binary_path + ".cfg"

    perform_single(binary_path, cfg_path)

def disabled_loop_unrolling():
    binary_path = test_location + "/x86_64/cfg_loop_unrolling"

    p = angr.Project(binary_path)
    cfg = p.analyses.CFGEmulated(fail_fast=True)

    cfg.normalize()
    cfg.unroll_loops(5)

    nose.tools.assert_equal(len(cfg.get_all_nodes(0x400636)), 7)

def test_thumb_mode():
    # In thumb mode, all addresses of instructions and in function manager should be odd numbers, which loyally
    # reflect VEX's trick to encode the THUMB state in the address.

    binary_path = test_location + "/armhf/test_arrays"
    p = angr.Project(binary_path)
    cfg = p.analyses.CFGEmulated(fail_fast=True)

    def check_addr(a):
        if a % 2 == 1:
            nose.tools.assert_true(cfg.is_thumb_addr(a))
        else:
            nose.tools.assert_false(cfg.is_thumb_addr(a))

    # CFGNodes
    cfg_node_addrs = [ n.addr for n in cfg.graph.nodes() if not n.is_simprocedure ]
    for a in cfg_node_addrs:
        check_addr(a)

    # Functions in function manager
    for f_addr, f in p.kb.functions.items():
        if f.is_simprocedure:
            continue
        check_addr(f_addr)
        if f.startpoint is not None:
            check_addr(f.startpoint.addr)

def test_fakeret_edges_0():

    # Test the bug where a fakeret edge can be missing in certain cases
    # Reported by Attila Axt (GitHub: @axt)
    # Ref: https://github.com/angr/angr/issues/72

    binary_path = os.path.join(test_location, "x86_64", "cfg_3")

    p = angr.Project(binary_path)
    cfg = p.analyses.CFGEmulated(context_sensitivity_level=3, fail_fast=True)

    putchar_plt = cfg.functions.function(name="putchar", plt=True)
    nose.tools.assert_true(putchar_plt.returning)

    putchar = cfg.functions.function(name="putchar", plt=False)
    nose.tools.assert_true(putchar.returning)

    # Since context sensitivity is 3, there should be two different putchar nodes
    putchar_cfgnodes = cfg.get_all_nodes(putchar.addr)
    nose.tools.assert_equal(len(putchar_cfgnodes), 2)

    # Each putchar node has a different predecessor as their PLT entry
    plt_entry_0 = cfg.get_predecessors(putchar_cfgnodes[0])
    nose.tools.assert_equal(len(plt_entry_0), 1)
    plt_entry_0 = plt_entry_0[0]

    plt_entry_1 = cfg.get_predecessors(putchar_cfgnodes[1])
    nose.tools.assert_equal(len(plt_entry_1), 1)
    plt_entry_1 = plt_entry_1[0]

    nose.tools.assert_true(plt_entry_0 is not plt_entry_1)

    # Each PLT entry should have a FakeRet edge
    preds_0 = cfg.get_predecessors(plt_entry_0)
    nose.tools.assert_equal(len(preds_0), 1)
    preds_1 = cfg.get_predecessors(plt_entry_1)
    nose.tools.assert_equal(len(preds_1), 1)

    # Each predecessor must have a call edge and a FakeRet edge
    edges_0 = cfg.get_successors_and_jumpkind(preds_0[0], excluding_fakeret=False)
    nose.tools.assert_equal(len(edges_0), 2)
    jumpkinds = { jumpkind for _, jumpkind in edges_0 }
    nose.tools.assert_set_equal(jumpkinds, { 'Ijk_Call', 'Ijk_FakeRet' })

    edges_1 = cfg.get_successors_and_jumpkind(preds_1[0], excluding_fakeret=False)
    nose.tools.assert_equal(len(edges_1), 2)
    jumpkinds = { jumpkind for _, jumpkind in edges_1 }
    nose.tools.assert_set_equal(jumpkinds, { 'Ijk_Call', 'Ijk_FakeRet' })

def test_string_references():

    # Test AttributeError on 'addr' which occurs when searching for string
    # references

    binary_path = os.path.join(test_location, "i386", "ctf_nuclear")
    b = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFGEmulated(keep_state=True, fail_fast=True)

    string_references = []
    for f in cfg.functions.values():
        string_references.append(f.string_references())

    # test passes if hasn't thrown an exception

def test_arrays():

    binary_path = os.path.join(test_location, "armhf", "test_arrays")
    b = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFGEmulated(fail_fast=True)

    node = cfg.model.get_any_node(0x10415)
    nose.tools.assert_is_not_none(node)

    successors = cfg.model.get_successors(node)
    nose.tools.assert_equal(len(successors), 2)

def test_max_steps():

    binary_path = os.path.join(test_location, "x86_64", "fauxware")
    b = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFGEmulated(max_steps=5, fail_fast=True)

    dfs_edges = networkx.dfs_edges(cfg.graph)

    depth_map = {}
    for src, dst in dfs_edges:
        if src not in depth_map:
            depth_map[src] = 0
        if dst not in depth_map:
            depth_map[dst] = depth_map[src] + 1
        depth_map[dst] = max(depth_map[src] + 1, depth_map[dst])

    nose.tools.assert_less_equal(max(depth_map.values()), 5)


def test_armel_final_missing_block():

    # Due to a stupid bug in CFGEmulated, the last block of a function might go missing in the function graph if the
    # only entry edge to that block is an Ijk_Ret edge. See #475 on GitHub.
    # Thank @gergo for reporting and providing this test binary.

    binary_path = os.path.join(test_location, 'armel', 'last_block')
    b = angr.Project(binary_path, auto_load_libs=False)
    cfg = b.analyses.CFGEmulated(fail_fast=True)

    blocks = list(cfg.kb.functions[0x8000].blocks)

    nose.tools.assert_equal(len(blocks), 3)
    nose.tools.assert_set_equal({ block.addr for block in blocks }, { 0x8000, 0x8014, 0x8020 })


def test_armel_final_missing_block_b():

    # When _pending_jobs is not sorted, it is possible that we first process a pending job created earlier and then
    # process another pending job created later. Ideally, we hope that jobs are always processed in a topological order,
    # and the unsorted pending jobs break this assumption. In this test binary, at one point there can be two pending
    # jobs, 0x10b05/0x10ac5(Ijk_FakeRet) and 0x10bbe(Ijk_FakeRet). If 0x10bbe is processed before 0x10b05, we do not
    # know whether the function 0x10a29(aes) returns or not. As a result, the final block of the main function is not
    # confirmed, and is not added to the function graph of function main.
    #
    # In fact, this also hints a different bug. We should always "confirm" that a function returns if its FakeRet job
    # are processed for whatever reason.
    #
    # Fixing either bug will resolve the issue that the final block does not show up in the function graph of main. To
    # stay on the safe side, both of them are fixed. Thanks @tyb0807 for reporting this issue and providing a test
    # binary.
    # EDG says: This binary is compiled incorrectly.
    # The binary's app code was compiled as CortexM, but linked against ARM libraries.
    # This is illegal, and does not actually execute on a real CortexM.
    # Somebody should recompile it....
    binary_path = os.path.join(test_location, 'armel', 'aes')
    b = angr.Project(binary_path, arch="ARMEL", auto_load_libs=False)

    function = b.loader.main_object.get_symbol('main').rebased_addr
    cfg = b.analyses.CFGEmulated(starts=[function],
                                 context_sensitivity_level=0,
                                 normalize=True,
                                 fail_fast=True,
                                 )

    blocks = list(cfg.kb.functions['main'].blocks)

    nose.tools.assert_equal(len(blocks), 2)
    nose.tools.assert_set_equal(set(block.addr for block in blocks), { 0x10b79, 0x10bbf })

def test_armel_incorrect_function_detection_caused_by_branch():

    # GitHub issue #685
    binary_path = os.path.join(test_location, "armel", "RTOSDemo.axf.issue_685")
    b = angr.Project(binary_path, auto_load_libs=False)

    cfg = b.analyses.CFGEmulated()

    # The Main function should be identified as a single function
    nose.tools.assert_in(0x80a1, cfg.functions)
    main_func = cfg.functions[0x80a1]

    # All blocks should be there
    block_addrs = sorted([ b.addr for b in main_func.blocks ])
    nose.tools.assert_equal(block_addrs, [0x80a1, 0x80b1, 0x80bb, 0x80cd, 0x80df, 0x80e3, 0x80ed])

    # The ResetISR function should be identified as a single function, too
    nose.tools.assert_in(0x8009, cfg.functions)
    resetisr_func = cfg.functions[0x8009]

    # All blocks should be there
    block_addrs = sorted([ b.addr for b in resetisr_func.blocks ])
    nose.tools.assert_equal(block_addrs, [0x8009, 0x8011, 0x801f, 0x8027])


def test_cfg_switches():

    #logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.INFO)
    #logging.getLogger('angr.analyses.cfg.indirect_jump_resolvers.jumptable').setLevel(logging.DEBUG)

    filename = "cfg_switches"

    edges = {
        'x86_64': {
            # jump table 0 in func_0
            (0x40053a, 0x400547),
            (0x40053a, 0x400552),
            (0x40053a, 0x40055d),
            (0x40053a, 0x400568),
            (0x40053a, 0x400573),
            (0x40053a, 0x400580),
            (0x40053a, 0x40058d),
            # jump table 0 in func_1
            (0x4005bc, 0x4005c9),
            (0x4005bc, 0x4005d8),
            (0x4005bc, 0x4005e7),
            (0x4005bc, 0x4005f6),
            (0x4005bc, 0x400605),
            (0x4005bc, 0x400614),
            (0x4005bc, 0x400623),
            (0x4005bc, 0x400632),
            (0x4005bc, 0x40063e),
            (0x4005bc, 0x40064a),
            (0x4005bc, 0x4006b0),
            # jump table 1 in func_1
            (0x40065a, 0x400667),
            (0x40065a, 0x400673),
            (0x40065a, 0x40067f),
            (0x40065a, 0x40068b),
            (0x40065a, 0x400697),
            (0x40065a, 0x4006a3),
            # jump table 0 in main
            (0x4006e1, 0x4006ee),
            (0x4006e1, 0x4006fa),
            (0x4006e1, 0x40070b),
            (0x4006e1, 0x40071c),
            (0x4006e1, 0x40072d),
            (0x4006e1, 0x40073e),
            (0x4006e1, 0x40074f),
            (0x4006e1, 0x40075b),
        },
    }

    arches = edges.keys()

    for arch in arches:
        path = os.path.join(test_location, arch, filename)
        proj = angr.Project(path, load_options={'auto_load_libs': False})

        cfg = proj.analyses.CFGEmulated()

        for src, dst in edges[arch]:
            src_node = cfg.get_any_node(src)
            dst_node = cfg.get_any_node(dst)
            nose.tools.assert_in(dst_node, src_node.successors,
                                 msg="CFG edge %s-%s is not found." % (src_node, dst_node)
                                 )


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print(f)
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("angr.state_plugins.abstract_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.analyses.cfg.cfg_emulated").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
