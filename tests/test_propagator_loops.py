# pylint:disable=missing-class-docstring
import re
import unittest

import ailment
import angr
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.structuring.structurer_nodes import LoopNode


class TestPropagatorLoops(unittest.TestCase):
    @staticmethod
    def _test_loop_variant_common(code):
        def banner(s):
            print(s + "\n" + "=" * 40)

        banner("Input Assembly")
        print("\n".join(l.strip() for l in code.splitlines()))
        print("")
        p = angr.load_shellcode(code, "AMD64")
        p.analyses.CFGFast(normalize=True)
        f = p.kb.functions[0]
        banner("Raw AIL Nodes")
        nodes = sorted(list(f.nodes), key=lambda n: n.addr)
        am = ailment.Manager(arch=p.arch)
        for n in nodes:
            b = p.factory.block(n.addr, n.size)
            ab = ailment.IRSBConverter.convert(b.vex, am)
            print(ab)
        print("")
        banner("Optimized AIL Nodes")
        a = p.analyses.Clinic(f)
        nodes = sorted(list(a.graph.nodes), key=lambda n: n.addr)
        assert len(nodes) == 3
        for n in nodes:
            print(n)
        print("")
        banner("Decompilation")
        d = p.analyses.Decompiler(f)
        print(d.codegen.text)
        print("")
        # cond_node = nodes[1]
        # cond_stmt = None
        # for stmt in cond_node.statements:
        #   if type(stmt) is ailment.statement.ConditionalJump:
        #       cond_stmt = stmt
        #       break
        # assert(cond_stmt is not None)
        # print('Condition:' + str(cond_stmt))
        # print(cond_proc.claripy_ast_from_ail_condition(cond_stmt.condition))
        cond_proc = ConditionProcessor(p.arch)
        ri = p.analyses.RegionIdentifier(f, graph=a.graph, cond_proc=cond_proc, kb=p.kb)
        rs = p.analyses.RecursiveStructurer(ri.region, cond_proc=cond_proc, kb=p.kb, func=f)
        snodes = rs.result.nodes
        assert len(snodes) == 3
        assert isinstance(snodes[1], LoopNode)
        banner("Condition")
        print(str(snodes[1].condition))
        return snodes[1].condition

    def test_loop_counter_reg(self):
        cond = self._test_loop_variant_common(
            """
            push rbp
            push rbx
            mov ebx, 0xa
            loop:
            nop
            dec ebx
            jnz loop
            pop rbx
            pop rbp
            ret"""
        )
        # TODO: we should only get ir_X != 0 once we implement value numbering
        assert (
            re.match(r"\(ir_\d+ != 0x0<32>\)", str(cond)) is not None
            or re.match(r"\(cc_dep1<4> != 0x0<32>\)", str(cond)) is not None
        )

    def test_loop_counter_stack(self):
        cond = self._test_loop_variant_common(
            """
            push rbp
            mov rbp, rsp
            sub rsp, 8
            mov dword ptr [rsp], 0
            loop:
            nop
            add dword ptr [rsp], 1
            cmp dword ptr [rsp], 9
            jle loop
            leave
            ret"""
        )
        assert re.match(r"\(Load\(addr=stack_base-16, size=4, endness=Iend_LE\) <=s 0x9<32>\)", str(cond)) is not None


if __name__ == "__main__":
    unittest.main()
