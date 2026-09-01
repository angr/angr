"""
Round-trip every branch of the deobf writer/reader on a synthetic function.

The CTF eval targets only ever produce five statement kinds and six expression kinds, and never
populate callsite_prototypes or calls_as_rets.  This builds a function that exercises the rest, so
those paths are tested without waiting on a multi-hour eval run.

    python test_deobf_format.py
"""

import os
import sys
import tempfile

import pyvex

import angr
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import parse_signature

# Any AMD64 binary will do -- the synthetic function is built by hand, the binary only supplies an
# arch and a loader. Override with DEOBF_TEST_BINARY.
BINARY = os.environ.get(
    "DEOBF_TEST_BINARY",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 os.pardir, "pushan-evaluation", "sample_vm_x-mas-ctf", "VM"),
)

# Wider than 64 bits, like pushan's encoded BlockIDs.
WIDE_A = int.from_bytes(b"None41975120", "big")
WIDE_B = int.from_bytes(b"None41975330", "big")


def _u64(v):
    return pyvex.const.U64(v)


def exotic_statements(arch):
    """One of every statement kind the writer claims to support."""
    ccall = pyvex.expr.CCall("Ity_I64", pyvex.enums.IRCallee(3, "amd64g_calculate_rflags_all", 0xFFFF),
                             [pyvex.expr.RdTmp.get_instance(0), pyvex.expr.Const(_u64(7))])
    regarray = pyvex.enums.IRRegArray(776, "Ity_F64", 8)
    return [
        pyvex.stmt.IMark(WIDE_A, 5, 0),
        pyvex.stmt.NoOp(),
        pyvex.stmt.AbiHint(pyvex.expr.RdTmp.get_instance(0), 128, pyvex.expr.Const(_u64(0x1234))),
        pyvex.stmt.WrTmp(1, pyvex.expr.Get(48, "Ity_I64")),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Add64", [pyvex.expr.RdTmp.get_instance(1),
                                                           pyvex.expr.Const(_u64(16))])),
        pyvex.stmt.WrTmp(3, pyvex.expr.Unop("Iop_64to32", [pyvex.expr.RdTmp.get_instance(2)])),
        pyvex.stmt.WrTmp(4, pyvex.expr.Triop("Iop_AddF64", [pyvex.expr.Const(_u64(0)),
                                                            pyvex.expr.RdTmp.get_instance(1),
                                                            pyvex.expr.RdTmp.get_instance(2)])),
        pyvex.stmt.WrTmp(5, pyvex.expr.Qop("Iop_MAddF64", [pyvex.expr.Const(_u64(0)),
                                                           pyvex.expr.RdTmp.get_instance(1),
                                                           pyvex.expr.RdTmp.get_instance(2),
                                                           pyvex.expr.RdTmp.get_instance(3)])),
        pyvex.stmt.WrTmp(6, pyvex.expr.Load("Iend_LE", "Ity_I64", pyvex.expr.RdTmp.get_instance(1))),
        pyvex.stmt.WrTmp(7, pyvex.expr.ITE(pyvex.expr.RdTmp.get_instance(3),
                                           pyvex.expr.Const(_u64(0)), pyvex.expr.Const(_u64(1)))),
        pyvex.stmt.WrTmp(8, ccall),
        pyvex.stmt.WrTmp(9, pyvex.expr.GetI(regarray, pyvex.expr.RdTmp.get_instance(3), 2)),
        pyvex.stmt.Put(pyvex.expr.RdTmp.get_instance(2), 48),
        pyvex.stmt.PutI(regarray, pyvex.expr.RdTmp.get_instance(3), pyvex.expr.RdTmp.get_instance(1), 2),
        pyvex.stmt.Store(pyvex.expr.RdTmp.get_instance(1), pyvex.expr.RdTmp.get_instance(2), "Iend_LE"),
        pyvex.stmt.StoreG("Iend_LE", pyvex.expr.RdTmp.get_instance(1), pyvex.expr.RdTmp.get_instance(2),
                          pyvex.expr.RdTmp.get_instance(3)),
        pyvex.stmt.LoadG("Iend_LE", "ILGop_8Uto32", 10, pyvex.expr.RdTmp.get_instance(1),
                         pyvex.expr.Const(_u64(0)), pyvex.expr.RdTmp.get_instance(3)),
        pyvex.stmt.CAS(pyvex.expr.RdTmp.get_instance(1), pyvex.expr.RdTmp.get_instance(2), None,
                       pyvex.expr.Const(_u64(3)), None, 11, 0xFFFFFFFF, "Iend_LE"),
        pyvex.stmt.LLSC(pyvex.expr.RdTmp.get_instance(1), pyvex.expr.RdTmp.get_instance(2), 12, "Iend_LE"),
        pyvex.stmt.MBE("Imbe_Fence"),
        pyvex.stmt.Dirty(pyvex.enums.IRCallee(0, "amd64g_dirtyhelper_RDTSC", 0xFFFF),
                         None, [pyvex.expr.Const(_u64(1))], 13, "Ifx_None", None, 0, 0),
        # Exit to a wide synthetic address, like a materialised VM branch.
        pyvex.stmt.Exit(pyvex.expr.RdTmp.get_instance(3), _u64(WIDE_B), "Ijk_Boring", 184),
    ]


def build_function(proj):
    arch = proj.arch
    model = proj.kb.cfgs.new_model("synthetic")
    import networkx

    model.graph = networkx.DiGraph()

    # tyenv includes the "tmp removed" sentinel pushan leaves behind.
    types = ["Ity_I64"] * 14
    types[4] = "tmp removed"
    types[5] = "tmp removed"
    tyenv = pyvex.block.IRTypeEnv(arch, types=types)

    irsb_a = pyvex.IRSB.empty_block(
        arch, WIDE_A, statements=exotic_statements(arch), tyenv=tyenv,
        nxt=pyvex.expr.Const(_u64(WIDE_B)), direct_next=True, jumpkind="Ijk_Boring", size=37,
    )
    irsb_b = pyvex.IRSB.empty_block(
        arch, WIDE_B, statements=[pyvex.stmt.IMark(WIDE_B, 1, 0)],
        tyenv=pyvex.block.IRTypeEnv(arch, types=["Ity_I64"]),
        nxt=pyvex.expr.Const(_u64(0x700018)), direct_next=False, jumpkind="Ijk_Call", size=1,
    )

    node_a = CFGENode(WIDE_A, 37, model, block_id=_block_id(0x400C88), irsb=irsb_a,
                      instruction_addrs=[0x400C88], byte_string=b"\x55\x48\x89\xe5")
    node_b = CFGENode(WIDE_B, 1, model, block_id=_block_id(0x400D34), irsb=irsb_b,
                      instruction_addrs=[0x400D34])

    func = Function(proj.kb.functions, WIDE_A, "SYNTH", None, is_simprocedure=False)
    func.calling_convention = proj.factory._default_cc(arch)
    func.prototype = parse_signature("int f(char *, int)", arch=arch)
    proj.kb.functions[func.addr] = func

    callee = proj.kb.functions.function(0x700018, "puts", create=True)
    callee.is_simprocedure = True
    callee.returning = True
    callee.prototype = parse_signature("int f(char *)", arch=arch).with_arch(arch)
    callee.calling_convention = proj.factory._default_cc(arch)

    # A function reachable only through the knowledge base, like pushan's `exit` special case.
    kb_only = proj.kb.functions.function(0x700048, "exit", create=True)
    kb_only.is_simprocedure = True
    kb_only.returning = True
    kb_only.calling_convention = proj.factory._default_cc(arch)

    func._transit_to(node_a, node_b)
    func._call_to(node_b, callee, node_a)
    func._return_from_call(callee, node_a)
    func.normalized = True
    func.startpoint = node_a
    func._ret_sites.add(node_b)

    proj.kb.callsite_prototypes.set_prototype(
        WIDE_B, proj.factory._default_cc(arch), parse_signature("int f(char *)", arch=arch), manual=True
    )
    proj.enc_stmt_addr_to_original = {
        WIDE_A: (0x400C88, 0, _block_id(0x400C88)),
        WIDE_B: (0x400D34, 0, _block_id(0x400D34)),
    }
    return func


def _block_id(addr):
    # BlockID moved between angr versions; the reader tolerates both, so should this.
    from angr.analyses.vm_deobfuscation.deobf_reader import _block_id_class

    cls = _block_id_class()
    return cls(addr, (None, None, 0, 0), "normal", vm_vpc=118)


def compare(original, rebuilt, problems):
    ga, gb = original.transition_graph, rebuilt.transition_graph
    if len(ga.nodes()) != len(gb.nodes()):
        problems.append(f"node count {len(gb.nodes())} != {len(ga.nodes())}")
    if len(ga.edges()) != len(gb.edges()):
        problems.append(f"edge count {len(gb.edges())} != {len(ga.edges())}")

    ea = sorted(f"{d.get('type')}:{s.addr:x}->{t.addr:x}" for s, t, d in ga.edges(data=True))
    eb = sorted(f"{d.get('type')}:{s.addr:x}->{t.addr:x}" for s, t, d in gb.edges(data=True))
    if ea != eb:
        problems.append(f"edges differ:\n  orig={ea}\n  new ={eb}")

    nodes_a = {n.addr: n for n in ga.nodes() if getattr(n, "irsb", None) is not None}
    nodes_b = {n.addr: n for n in gb.nodes() if getattr(n, "irsb", None) is not None}
    for addr, na in nodes_a.items():
        nb = nodes_b.get(addr)
        if nb is None:
            problems.append(f"node {addr:#x} missing")
            continue
        for attr in ("size", "no_ret", "thumb", "byte_string", "is_syscall", "function_address"):
            if getattr(na, attr) != getattr(nb, attr):
                problems.append(f"node {addr:#x}.{attr}: {getattr(nb, attr)!r} != {getattr(na, attr)!r}")
        if list(na.instruction_addrs) != list(nb.instruction_addrs):
            problems.append(f"node {addr:#x}: instruction_addrs differ")
        # str() of an IRSB renders every statement and expression, so it is a strong check.
        sa, sb = str(na.irsb), str(nb.irsb)
        if sa != sb:
            problems.append(f"node {addr:#x}: IRSB text differs\n  orig={sa[:400]}\n  new ={sb[:400]}")
        if list(na.irsb.tyenv.types) != list(nb.irsb.tyenv.types):
            problems.append(f"node {addr:#x}: tyenv differs")
        if na.irsb.jumpkind != nb.irsb.jumpkind:
            problems.append(f"node {addr:#x}: jumpkind differs")

    if original.startpoint.addr != rebuilt.startpoint.addr:
        problems.append("startpoint differs")
    if {n.addr for n in original._ret_sites} != {n.addr for n in rebuilt._ret_sites}:
        problems.append("ret_sites differ")
    if str(original.prototype) != str(rebuilt.prototype):
        problems.append(f"prototype {rebuilt.prototype} != {original.prototype}")


def main():
    problems = []

    proj = angr.Project(BINARY, auto_load_libs=False)
    func = build_function(proj)
    kwargs = {"calls_as_rets": {WIDE_A: "Ijk_Ret"}, "allow_global_dead_ass_elim": False,
              "ail_propagator_init_values": None}

    path = os.path.join(tempfile.mkdtemp(), "synthetic.json.gz")
    doc = dump_decompilation_input(func, proj, path, **kwargs)

    stmt_kinds = {s["t"] for n in doc["nodes"] for s in n["irsb"]["statements"]}
    expected = {"IMark", "NoOp", "AbiHint", "WrTmp", "Put", "PutI", "Store", "StoreG", "LoadG",
                "CAS", "LLSC", "MBE", "Dirty", "Exit"}
    missing = expected - stmt_kinds
    if missing:
        problems.append(f"writer did not emit {sorted(missing)}")
    if doc["callsite_prototypes"] == []:
        problems.append("callsite_prototypes not captured")
    if not doc["decompiler_kwargs"]["calls_as_rets"]:
        problems.append("calls_as_rets not captured")
    if not any(not c["in_graph"] for c in doc["callees"]):
        problems.append("kb-only callee (in_graph=False) not captured")

    # Reload into a fresh project so nothing is shared with the original objects.
    proj2 = angr.Project(BINARY, auto_load_libs=False)
    rebuilt, kwargs2 = load_decompilation_input(proj2, path, renumber_addrs=False)
    compare(func, rebuilt, problems)

    if kwargs2["calls_as_rets"] != kwargs["calls_as_rets"]:
        problems.append(f"calls_as_rets round-trip: {kwargs2['calls_as_rets']}")
    plugin = proj2.kb.callsite_prototypes
    # has_prototype() gained a kind= keyword defaulting to INFERRED; has_some_prototype() is the
    # version-neutral question we actually mean here.
    restored = plugin.has_some_prototype(WIDE_B) if hasattr(plugin, "has_some_prototype") \
        else plugin.has_prototype(WIDE_B)
    if not restored:
        problems.append("callsite prototype not restored")
    if proj2.kb.functions.function(0x700048) is None:
        problems.append("kb-only callee not restored")
    if proj2.enc_stmt_addr_to_original.get(WIDE_A, (None,))[0] != 0x400C88:
        problems.append("enc_addr_map not restored")

    # And once more with renumbering forced on, which is what a u64-address angr gets.
    proj3 = angr.Project(BINARY, auto_load_libs=False)
    renumbered, _ = load_decompilation_input(proj3, path, renumber_addrs=True)
    addrs = sorted(n.addr for n in renumbered.transition_graph.nodes() if getattr(n, "irsb", None))
    if any(a > 0xFFFF_FFFF_FFFF_FFFF for a in addrs):
        problems.append(f"renumbering left a wide address: {[hex(a) for a in addrs]}")
    if len(set(addrs)) != len(addrs):
        problems.append("renumbering collided two nodes onto one address")

    if problems:
        print(f"FAIL ({len(problems)} problems)")
        for p in problems:
            print("  -", p)
        return 1
    print(f"PASS: {len(stmt_kinds)} statement kinds round-tripped, "
          f"callsite prototypes / calls_as_rets / kb-only callees / renumbering all OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
