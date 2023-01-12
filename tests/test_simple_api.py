import os
import angr


def _bin(*s):
    return os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests", *s)


def test_fauxware():
    project = angr.Project(_bin("i386", "fauxware"), auto_load_libs=False)

    result = [0, 0]

    @project.hook(0x80485DB)
    def check_backdoor(state):  # pylint:disable=unused-variable
        result[0] += 1
        if b"SOSNEAKY" in state.posix.dumps(0):
            result[1] = True
            project.terminate_execution()

    pg = project.execute()
    assert len(pg.deadended) != 3  # should terminate early
    assert result[1]


if __name__ == "__main__":
    test_fauxware()
