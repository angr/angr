# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestHook(unittest.TestCase):
    def test_mips(self):
        MAIN_END = 0x4007D8
        INNER_LOOP = 0x40069C
        OUTER_LOOP = 0x40076C

        p = angr.Project(os.path.join(location, "mips", "test_loops"), auto_load_libs=False)
        output = []

        # hooking by a function decorator
        @p.hook(INNER_LOOP)
        def hook1(_):  # pylint:disable=unused-variable
            output.append(1)

        def hook2(state):
            output.append(2)
            num = state.solver.eval(state.regs.a1)
            string = b"%d " % num
            state.posix.get_fd(1).write_data(state.solver.BVV(string))

        # a manual hook
        p.hook(OUTER_LOOP, hook2, length=0x14)

        s = p.factory.simulation_manager(p.factory.entry_state()).explore(find=[MAIN_END])

        assert len(s.found) == 1
        assert s.found[0].posix.dumps(1) == b"".join(b"%d " % x for x in range(100)) + b"\n"
        assert output == [1] * 100 + [2] * 100
        # print 'Executed %d blocks' % len(s._f.trace)

    def test_zero_length_userhook(self):
        # If a user hook does not overwrite any instruction (length = 0),
        # we should not run the hook twice.
        # jumpkind Ijk_NoHook is used for exactly this purpose.

        class OneTimeHook:
            def __init__(self):
                self.ctr = 0

            def one_time_hook(self, _):
                self.ctr += 1
                if self.ctr > 1:
                    raise Exception("OneTimeHook is executed multiple times.")

        # Amd64
        # 0x0:	mov	qword ptr [1], rax
        # 0x8:	jmp	0x1b
        # 0xa:	mov	qword ptr [2], rax
        # 0x12:	mov	qword ptr [3], rax
        # 0x1a:	ret
        # 0x1b:	jmp	0xa
        shellcode = (
            b"\x48\x89\x04\x25\x01\x00\x00\x00\xeb\x11\x48\x89\x04\x25\x02\x00\x00\x00\x48"
            b"\x89\x04\x25\x03\x00\x00\x00\xc3\xeb\xed"
        )
        proj = angr.load_shellcode(shellcode, arch="amd64")

        proj.hook(0x8, hook=OneTimeHook().one_time_hook, length=0)
        s = proj.factory.simgr()
        s.run()

    def test_nonzero_length_userhook(self):
        # If a user hook overwrites any instruction (length > 0), we should allow the execution of another hook that
        # follows this hook immediately.

        class TwoTimesHook:
            def __init__(self):
                self.addrs = []

            def hook(self, state):
                self.addrs.append(state.addr)

            # Amd64
            # 0x0:	mov	qword ptr [1], rax
            # 0x8:	jmp	0x1b
            # 0xa:	mov	qword ptr [2], rax
            # 0x12:	mov	qword ptr [3], rax
            # 0x1a:	ret
            # 0x1b:	jmp	0xa

        shellcode = (
            b"\x48\x89\x04\x25\x01\x00\x00\x00\xeb\x11\x48\x89\x04\x25\x02\x00\x00\x00\x48"
            b"\x89\x04\x25\x03\x00\x00\x00\xc3\xeb\xed"
        )
        proj = angr.load_shellcode(shellcode, arch="amd64")

        hook = TwoTimesHook()
        proj.hook(0x8, hook=hook.hook, length=2)
        proj.hook(0xA, hook=hook.hook, length=7)
        s = proj.factory.simgr()
        s.run()

        assert hook.addrs == [0x8, 0xA]


if __name__ == "__main__":
    unittest.main()
