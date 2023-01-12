import angr
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), "..", "..", "binaries", "tests", "")


def test_static_hooker():
    test_file = os.path.join(test_location, "x86_64", "static")
    p = angr.Project(test_file, auto_load_libs=False)
    sh = p.analyses.StaticHooker("libc.so.6")

    assert 4197616 in sh.results
    assert type(sh.results[4197616]) is angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]
    assert type(p.hooked_by(4197616)) is angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]


if __name__ == "__main__":
    test_static_hooker()
