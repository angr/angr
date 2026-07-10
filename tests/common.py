from __future__ import annotations

import logging
import os
import pickle
import subprocess
import sys
from collections.abc import Iterable, Sequence
from functools import lru_cache
from tempfile import NamedTemporaryFile
from unittest import SkipTest, skip, skipIf, skipUnless

import networkx
from rich.console import Console
from rich.syntax import Syntax

import angr
import angr.sim_options as so
from angr import Project, load_shellcode
from angr.analyses import CongruencyCheck
from angr.misc.testing import is_testing

l = logging.getLogger("angr.tests.common")

try:
    import tracer
except ImportError:
    tracer = None

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")
bin_priv_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries-private")

WORKER = is_testing or bool(
    os.environ.get("WORKER", False)
)  # this variable controls whether we print the decompilation code or not

if not os.path.isdir(bin_location) and not os.getenv("CI", "") == "true":
    raise RuntimeError(
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
        dst = NamedTemporaryFile(delete=False)  # noqa: SIM115
        dst.close()
        src = NamedTemporaryFile(mode="x", delete=False, suffix=".c")  # noqa: SIM115
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


def run_simple_unicorn_congruency_check(thing: Project | bytes | str, arch: str = "AMD64", depth: int = 1):
    if isinstance(thing, Project):
        p = thing
    else:
        base = 0x100000
        p = load_shellcode(thing, arch, load_address=base, start_offset=base)
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


def print_decompilation_result(dec):
    if not WORKER:
        print("Decompilation result:")

        try:
            console = Console()
            syntax = Syntax(dec.codegen.text, "c", line_numbers=False)
            console.print(syntax)
        except Exception:  # pylint:disable=broad-exception-caught
            print(dec.codegen.text)


def set_decompiler_option(decompiler_options: list[tuple] | None, params: list[tuple]) -> list[tuple]:
    if decompiler_options is None:
        decompiler_options = []

    for param, value in params:
        for option in angr.analyses.decompiler.decompilation_options.options:
            if param == option.param:
                decompiler_options.append((option, value))

    return decompiler_options


def _merged_regions(addrs: Iterable[int], window: int) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    for addr in sorted(addrs):
        if regions and addr <= regions[-1][1]:
            regions[-1] = regions[-1][0], max(regions[-1][1], addr + window)
        else:
            regions.append((addr, addr + window))
    return regions


def load_project_with_scoped_cfg(
    bin_path: str,
    func_addr: int,
    extra_func_addrs: Sequence[int] = (),
    window: int = 0x2000,
    expand_call_tree: bool = True,
    project_kwargs: dict | None = None,
    cfg_kwargs: dict | None = None,
    run_ccc: bool = True,
    ccc_kwargs: dict | None = None,
) -> tuple[Project, angr.analyses.cfg.CFGFast]:
    """
    Build a Project whose CFG covers only the function under test instead of the whole binary.

    Most decompiler tests decompile a single function, but a whole-binary CFGFast plus
    CompleteCallingConventions can take minutes on large binaries while the decompilation itself takes
    less than a second. This helper restricts CFG recovery to regions around ``func_addr`` (plus
    ``extra_func_addrs``) and, when ``expand_call_tree`` is set, the transitive callees inside the main
    object, so callee analysis (e.g. register preservation of helpers like __chkstk) still matches the
    whole-binary result. CompleteCallingConventions then runs only on those functions.

    Call-tree discovery runs on throwaway knowledge bases so partial results never leak into the
    Project's real knowledge base.

    :param bin_path:          Path of the binary to load.
    :param func_addr:         Address of the function under test.
    :param extra_func_addrs:  Additional function addresses that must be present in the CFG.
    :param window:            Size in bytes of the region scanned after each function start; must cover
                              the function's full extent.
    :param expand_call_tree:  Also cover the transitive callees of the given functions.
    :param project_kwargs:    Extra keyword arguments for angr.Project.
    :param cfg_kwargs:        Overrides for the final CFGFast call.
    :param run_ccc:           Run CompleteCallingConventions, scoped to the covered functions.
    :param ccc_kwargs:        Extra keyword arguments for CompleteCallingConventions.
    :return:                  A (project, cfg) tuple.
    """
    proj = Project(bin_path, **(project_kwargs or {}))
    main_object = proj.loader.main_object
    roots = [func_addr, *extra_func_addrs]
    known: set[int] = set(roots)

    if expand_call_tree:
        for _ in range(8):
            tmp_kb = angr.KnowledgeBase(proj)
            proj.analyses[angr.analyses.CFGFast].prep(kb=tmp_kb)(
                normalize=True,
                regions=_merged_regions(known, window),
                start_at_entry=False,
                function_starts=sorted(known),
                symbols=False,
                force_smart_scan=False,
            )
            callees: set[int] = set()
            callgraph = tmp_kb.functions.callgraph
            for root in roots:
                if root in callgraph:
                    callees |= networkx.descendants(callgraph, root)
            new_addrs = {addr for addr in callees - known if main_object.contains_addr(addr)}
            if not new_addrs:
                break
            known |= new_addrs

    final_cfg_kwargs = {
        "normalize": True,
        "regions": _merged_regions(known, window),
        "start_at_entry": False,
        "function_starts": roots,
        "symbols": True,
        "force_smart_scan": False,
    }
    final_cfg_kwargs.update(cfg_kwargs or {})
    cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, **final_cfg_kwargs)

    if run_ccc:
        final_ccc_kwargs = {"prioritize_func_addrs": sorted(known), "skip_other_funcs": True}
        final_ccc_kwargs.update(ccc_kwargs or {})
        proj.analyses.CompleteCallingConventions(show_progressbar=not WORKER, **final_ccc_kwargs)

    return proj, cfg
