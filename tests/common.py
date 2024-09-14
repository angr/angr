from __future__ import annotations
import os
import pickle
import sys
import logging
import subprocess
from functools import lru_cache
from collections.abc import Sequence
from tempfile import NamedTemporaryFile

from unittest import skipIf, skipUnless, skip, SkipTest

from angr import load_shellcode
from angr.analyses import CongruencyCheck
import angr.sim_options as so

l = logging.getLogger("angr.tests.common")

try:
    import tracer
except ImportError:
    tracer = None

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")
bin_priv_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries-private")

if not os.path.isdir(bin_location):
    raise Exception(
        "Can't find the angr/binaries repo for holding testcases. "
        "It should be cloned into the same folder as the rest of your angr modules."
    )


def broken(func):
    return skip(reason="Broken test method")(func)


def requires_binaries_private(func):
    return skipIf(
        not os.path.exists(
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "binaries-private"),
        ),
        "Skip this test since we do not have the binaries-private repo cloned on Travis CI.",
    )(func)


def slow_test(func):
    func.speed = "slow"
    slow_test_env = os.environ["SKIP_SLOW_TESTS"].lower() if "SKIP_SLOW_TESTS" in os.environ else ""
    return skipIf(slow_test_env == "true" or slow_test_env == "1", "Skipping slow test")(func)


def skip_if_not_linux(func):
    return skipUnless(sys.platform.startswith("linux"), "Skipping Linux Test Cases")(func)


TRACE_VERSION = 1


def do_trace(proj, test_name, input_data, **kwargs):
    """
    trace, magic, crash_mode, crash_addr = load_cached_trace(proj, "test_blurble")
    """
    fname = os.path.join(
        bin_location,
        "tests_data",
        "runner_traces",
        f"{test_name}_{os.path.basename(proj.filename)}_{proj.arch.name}.p",
    )

    if os.path.isfile(fname):
        try:
            with open(fname, "rb") as f:
                r = pickle.load(f)
                if type(r) is tuple and len(r) == 2 and r[1] == TRACE_VERSION:
                    return r[0]
        except (pickle.UnpicklingError, UnicodeDecodeError):
            print("Can't unpickle trace - rerunning")

    if tracer is None:
        raise SkipTest("Tracer is not installed and cached data is not present")

    runner = tracer.QEMURunner(project=proj, input=input_data, **kwargs)
    r = (runner.trace, runner.magic, runner.crash_mode, runner.crash_addr)
    with open(fname, "wb") as f:
        pickle.dump((r, TRACE_VERSION), f, -1)
    return r


@skipUnless(tracer, "tracer is not installed")
def load_cgc_pov(pov_file: str) -> tracer.TracerPoV:
    return tracer.TracerPoV(pov_file)


def compile_c(c_code: str, cflags: Sequence[str] | None, silent: bool = False) -> NamedTemporaryFile:
    # pylint:disable=consider-using-with
    """
    Compile `c_code` and return the file containing the compiled output
    """
    dst = None
    try:
        dst = NamedTemporaryFile(delete=False)
        dst.close()
        src = NamedTemporaryFile(mode="x", delete=False, suffix=".c")
        src.write(c_code)
        src.close()

        call_args = ["cc"] + (cflags or []) + ["-o", dst.name, src.name]
        l.debug("Compiling with: %s", " ".join(call_args))
        l.debug("Source:\n%s", c_code)
        out = subprocess.DEVNULL if silent else None
        subprocess.check_call(call_args, stderr=out, stdout=out)
        return dst
    except:
        if dst and os.path.exists(dst.name):
            os.remove(dst.name)
        raise
    finally:
        if src and os.path.exists(src.name):
            os.remove(src.name)


@lru_cache
def has_32_bit_compiler_support() -> bool:
    """
    Check if we are able to compile a 32-bit binary
    """
    try:
        binary = compile_c("#include <stdlib.h>\nint main() { return 0; }", ["-m32"], True)
        os.remove(binary.name)
        return True
    except subprocess.CalledProcessError:
        return False


def run_simple_unicorn_congruency_check(shellcode: bytes | str, arch: str = "AMD64", depth: int = 1):
    base = 0x100000
    p = load_shellcode(shellcode, arch, load_address=base, start_offset=base)
    ca = p.analyses[CongruencyCheck].prep()(throw=True)
    ca.set_state_options(
        left_add_options=so.unicorn,
        left_remove_options={
            so.LAZY_SOLVES,
            so.TRACK_MEMORY_MAPPING,
            so.COMPOSITE_SOLVER,
        },
        right_add_options={so.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        right_remove_options={
            so.LAZY_SOLVES,
            so.TRACK_MEMORY_MAPPING,
            so.COMPOSITE_SOLVER,
        },
    )
    ca.run(depth=depth)
