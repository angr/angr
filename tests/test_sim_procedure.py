import os
import angr
from angr.codenode import BlockNode, HookNode, SyscallNode

BIN_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")


def test_ret_float():
    class F1(angr.SimProcedure):
        def run(self):
            return 12.5

    p = angr.load_shellcode(b"X", arch="i386")

    p.hook(0x1000, F1(prototype="float (x)();"))
    p.hook(0x2000, F1(prototype="double (x)();"))

    s = p.factory.call_state(addr=0x1000, ret_addr=0, prototype="float(x)()")
    succ = s.step()
    assert len(succ.successors) == 1
    s2 = succ.flat_successors[0]
    assert not s2.regs.st0.symbolic
    assert s2.solver.eval(s2.regs.st0.raw_to_fp()) == 12.5

    s = p.factory.call_state(addr=0x2000, ret_addr=0, prototype="double(x)()")
    succ = s.step()
    assert len(succ.successors) == 1
    s2 = succ.flat_successors[0]
    assert not s2.regs.st0.symbolic
    assert s2.solver.eval(s2.regs.st0.raw_to_fp()) == 12.5

    p = angr.load_shellcode(b"X", arch="amd64")

    p.hook(0x1000, F1(prototype="float (x)();"))
    p.hook(0x2000, F1(prototype="double (x)();"))

    s = p.factory.call_state(addr=0x1000, ret_addr=0, prototype="float(x)()")
    succ = s.step()
    assert len(succ.successors) == 1
    s2 = succ.flat_successors[0]
    res = s2.registers.load("xmm0", 4).raw_to_fp()
    assert not res.symbolic
    assert s2.solver.eval(res) == 12.5

    s = p.factory.call_state(addr=0x2000, ret_addr=0, prototype="double(x)()")
    succ = s.step()
    assert len(succ.successors) == 1
    s2 = succ.flat_successors[0]
    res = s2.registers.load("xmm0", 8).raw_to_fp()
    assert not res.symbolic
    assert s2.solver.eval(res) == 12.5


def test_syscall_and_simprocedure():
    bin_path = os.path.join(BIN_PATH, "tests", "cgc", "CADET_00002")
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)

    # check syscall
    node = cfg.get_any_node(proj.loader.kernel_object.mapped_base + 1)
    func = proj.kb.functions[node.addr]

    assert node.is_simprocedure
    assert node.is_syscall
    assert not node.to_codenode().is_hook
    assert not proj.is_hooked(node.addr)
    assert func.is_syscall
    assert func.is_simprocedure
    assert type(proj.factory.snippet(node.addr)) == SyscallNode

    # check normal functions
    node = cfg.get_any_node(0x80480A0)
    func = proj.kb.functions[node.addr]

    assert not node.is_simprocedure
    assert not node.is_syscall
    assert not proj.is_hooked(node.addr)
    assert not func.is_syscall
    assert not func.is_simprocedure
    assert type(proj.factory.snippet(node.addr)) == BlockNode

    # check hooked functions
    proj.hook(0x80480A0, angr.SIM_PROCEDURES["libc"]["puts"]())
    cfg = proj.analyses.CFGFast(normalize=True)  # rebuild cfg to updated nodes
    node = cfg.get_any_node(0x80480A0)
    func = proj.kb.functions[node.addr]

    assert node.is_simprocedure
    assert not node.is_syscall
    assert proj.is_hooked(node.addr)
    assert not func.is_syscall
    assert func.is_simprocedure
    assert type(proj.factory.snippet(node.addr)) == HookNode


def test_inet_ntoa() -> None:
    """
    Test the inet_ntoa simprocedure for functionality
    """
    bin_path = os.path.join(BIN_PATH, "tests", "x86_64", "inet_ntoa")
    proj = angr.Project(bin_path, auto_load_libs=False, use_sim_procedures=True)
    initial_state = proj.factory.entry_state()
    simgr = proj.factory.simgr(initial_state)
    after = simgr.run()
    assert after.deadended[0].posix.dumps(1) == b"192.168.192.168\n"


if __name__ == "__main__":
    test_ret_float()
    test_syscall_and_simprocedure()
    test_inet_ntoa()
