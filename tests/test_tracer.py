import os
import sys
import logging

import nose
import angr

from common import bin_location, do_trace, load_cgc_pov, slow_test

def tracer_cgc(filename, test_name, stdin, copy_states=False, follow_unsat=False):
    p = angr.Project(filename)
    p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

    trace, magic, crash_mode, crash_addr = do_trace(p, test_name, stdin)
    s = p.factory.entry_state(mode='tracing', stdin=angr.SimFileStream, flag_page=magic)
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, hierarchy=False, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace, crash_addr=crash_addr, keep_predecessors=1, copy_states=copy_states,
                                           follow_unsat=follow_unsat)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t


def trace_cgc_with_pov_file(binary: str, test_name: str, pov_file: str, output_initial_bytes: bytes, copy_states=False):
    nose.tools.assert_true(os.path.isfile(pov_file))
    pov = load_cgc_pov(pov_file)
    trace_result = tracer_cgc(binary, test_name, b''.join(pov.writes), copy_states)
    simgr = trace_result[0]
    simgr.run()
    nose.tools.assert_true("traced" in simgr.stashes)
    nose.tools.assert_equal(len(simgr.traced), 1)
    stdout_dump = simgr.traced[0].posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith(output_initial_bytes))


def tracer_linux(filename, test_name, stdin, add_options=None, remove_options=None):
    p = angr.Project(filename)

    trace, _, crash_mode, crash_addr = do_trace(p, test_name, stdin, ld_linux=p.loader.linux_loader_object.binary, library_path=set(os.path.dirname(obj.binary) for obj in p.loader.all_elf_objects), record_stdout=True)
    s = p.factory.full_init_state(mode='tracing', stdin=angr.SimFileStream, add_options=add_options, remove_options=remove_options)
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, hierarchy=False, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace, crash_addr=crash_addr)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t

def test_recursion():
    blob = bytes.fromhex("00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b1b1adb1b1b1b1b1b1118611981d8611")
    fname = os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests", "cgc", "NRFIN_00075")

    simgr, _ = tracer_cgc(fname, 'tracer_recursion', blob)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)
    nose.tools.assert_true(simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip))


@slow_test
def broken_cache_stall():
    # test a valid palindrome
    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00071")
    blob = bytes.fromhex("0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a332f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c")

    simgr, tracer = tracer_cgc(b, 'tracer_cache_stall', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.crashed[0]

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)

    # load it again
    simgr, tracer = tracer_cgc(b, 'tracer_cache_stall', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


def test_manual_recursion():

    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00071")
    blob = open(os.path.join(bin_location, 'tests_data', 'crash2731'), 'rb').read()

    simgr, tracer = tracer_cgc(b, 'tracer_manual_recursion', blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    nose.tools.assert_not_equal(crash_path, None)
    nose.tools.assert_not_equal(crash_state, None)


def test_cgc_se1_palindrome_raw():
    b = os.path.join(bin_location, "tests", "cgc", "sc1_0b32aa01_01")
    # test a valid palindrome

    simgr, _ = tracer_cgc(b, 'tracer_cgc_se1_palindrome_raw_nocrash', b'racecar\n')
    simgr.run()

    # make sure the heap base is correct and hasn't been altered from the default
    nose.tools.assert_true('traced' in simgr.stashes)
    nose.tools.assert_equal(simgr.traced[0].cgc.allocation_base, 0xb8000000)

    # make sure there is no crash state
    nose.tools.assert_false(simgr.crashed)

    # make sure angr modeled the correct output
    stdout_dump = simgr.traced[0].posix.dumps(1)
    nose.tools.assert_true(stdout_dump.startswith(b"\nWelcome to Palindrome Finder\n\n"
                                                  b"\tPlease enter a possible palindrome: "
                                                  b"\t\tYes, that's a palindrome!\n\n"
                                                  b"\tPlease enter a possible palindrome: "))
    # make sure there were no 'Nope's from non-palindromes
    nose.tools.assert_false(b"Nope" in stdout_dump)

    # now test crashing input
    simgr, _ = tracer_cgc(b, 'tracer_cgc_se1_palindrome_raw_yescrash', b'A'*129)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)


def test_symbolic_sized_receives():
    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00070")

    simgr, _ = tracer_cgc(b, 'tracer_symbolic_sized_receives', b'hello')
    simgr.run()

    nose.tools.assert_false(simgr.crashed)
    nose.tools.assert_true('traced' in simgr.stashes)

    simgr, _ = tracer_cgc(b, 'tracer_symbolic_sized_receives_nulls', b'\0'*20)
    simgr.run()

    nose.tools.assert_false(simgr.crashed)
    nose.tools.assert_true('traced' in simgr.stashes)


def test_allocation_base_continuity():
    correct_out = b'prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\nb7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\nb7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\ne: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\na: b7fef000\n'

    b = os.path.join(bin_location, "tests", "i386", "cgc_allocations")

    simgr, _ = tracer_cgc(b, 'tracer_allocation_base_continuity', b'')
    simgr.run()

    nose.tools.assert_equal(simgr.traced[0].posix.dumps(1), correct_out)


def test_crash_addr_detection():
    b = os.path.join(bin_location, "tests", "i386", "call_symbolic")

    simgr, _ = tracer_cgc(b, 'tracer_crash_addr_detection', b'A'*700)
    simgr.run()

    nose.tools.assert_true(simgr.crashed)
    nose.tools.assert_true(simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip))


def test_fauxware():
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    b = os.path.join(bin_location, "tests", "x86_64", "fauxware")
    simgr, _ = tracer_linux(b, 'tracer_fauxware', b'A'*18, remove_options={angr.options.CPUID_SYMBOLIC})
    simgr.run()

    nose.tools.assert_true('traced' in simgr.stashes)

def test_rollback_on_symbolic_conditional_exit():
    # Test if state is correctly rolled back to before start of block in case block cannot be executed in unicorn engine
    # because exit condition is symbolic
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00043")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00043_POV_00000.xml")
    output_initial_bytes = [b"Network type: Broadcast", b"Source Address: 0x962B175B", b"Network type: Endpoint",
                            b"Source Address: 0x321B00B0", b"Destination Address: 0xACF70019", b"Final Statistics:",
                            b"\tTotal Packets: 6", b"\tStart Time: 0x5552C470", b"\tEnd Time: 0x54CAF0B0",
                            b"\tLargest Packet: 0", b"\tSmallest Packet: 0", b"\tNumber of malformed packets: 0",
                            b"\tNumber of packets shown 6", b"Option Headers:",
                            b"This content has not been modified from the original",
                            b"Capturing Authority: Network Provider", b"Capture Date: bKQcAXJJEqCSPmrIlRy",
                            b"Capturing Authority: Employer\n"]
    trace_cgc_with_pov_file(binary, "tracer_rollback_on_symbolic_conditional_exit", pov_file, b'\n'.join(output_initial_bytes))

def test_floating_point_memory_reads():
    # Test float point memory reads in which bytes longer than architecture width are read in a single memory read hook
    # in unicorn. The other related case is when such reads are split across multiple reads. This is tested in
    # b01lersctf2020 little engine solver
    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00027")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00027_POV_00000.xml")
    output = b'\x00' * 36
    trace_cgc_with_pov_file(binary, "tracer_floating_point_memory_reads", pov_file, output)

def test_fdwait_fds():
    # Test fdwait working with appropriate bit order for read/write fds
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00029")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00029_POV_00000.xml")
    output = [b"For what material would you like to run this simulation?", b"  1. Air", b"  2. Aluminum",
              b"  3. Copper", b"  4. Custom\nSelection: "]
    trace_cgc_with_pov_file(binary, "tracer_floating_point_memory_reads", pov_file, b'\n'.join(output))

def test_skip_some_symbolic_memory_writes():
    # Test symbolic memory write skipping in SimEngineUnicorn during tracing
    # This test doesn't actually check if instruction was skipped. It checks if tracing is successful
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00023")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00023_POV_00000.xml")
    output_initial_bytes = [b"", b"C - Change Diver Info", b"L - Log a New Dive", b"D - Download Dive Data",
                            b"E - Edit Dives", b"P - Print Dive Logs", b"R - Remove Dives", b"S - Diver Statistics",
                            b"X - Exit Application", b":", b"", b"Dive Log is empty", b"", b"C - Change Diver Info",
                            b"L - Log a New Dive", b"D - Download Dive Data", b"E - Edit Dives",
                            b"P - Print Dive Logs", b"R - Remove Dives", b"S - Diver Statistics",
                            b"X - Exit Application", b":", b"", b"Dive Log is empty", b"", b"C - Change Diver Info",
                            b"L - Log a New Dive", b"D - Download Dive Data", b"E - Edit Dives", b"P - Print Dive Logs",
                            b"R - Remove Dives", b"S - Diver Statistics", b"X - Exit Application", b":",
                            (b"Dive Site: Date: Time: Location (area/city): Max Depth in ft: Avg Depth in ft: "
                             b"Dive Duration (mins): O2 Percentage: Pressure In (psi): Pressure Out (psi): "),
                            b"C - Change Diver Info", b"L - Log a New Dive", b"D - Download Dive Data", b"E - Edit Dives",
                            b"P - Print Dive Logs", b"R - Remove Dives", b"S - Diver Statistics", b"X - Exit Application", b":",
                            (b"Dive Site: Date: Time: Location (area/city): Max Depth in ft: Avg Depth in ft: "
                             b"Dive Duration (mins): O2 Percentage: Pressure In (psi): Pressure Out (psi): "),
                            b"C - Change Diver Info", b"L - Log a New Dive", b"D - Download Dive Data",
                            b"E - Edit Dives", b"P - Print Dive Logs", b"R - Remove Dives", b"S - Diver Statistics",
                            b"X - Exit Application", b":",
                            (b"First Name: Last Name: Street: City: State: Zip Code: Phone Number: PADI Diver Number: "
                             b"PADI Cert Date: "),
                            b"     Name: "]
    trace_cgc_with_pov_file(binary, "tracer_skip_some_symbolic_memory_writes", pov_file, b'\n'.join(output_initial_bytes))


def test_subregister_tainting():
    # Tests for subregister tainting: taint only bytes of subregister and not entire register
    binary = os.path.join(bin_location, "tests", "cgc", "KPRCA_00028")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00028_POV_00000.xml")
    output_initial_bytes = b"Welcome to the SLUR REPL. Type an expression to evaluate it.\n> "
    trace_cgc_with_pov_file(binary, "tracer_subregister_tainting", pov_file, output_initial_bytes)


def test_symbolic_memory_dependencies_liveness():
    # Tests for liveness of symbolic memory dependencies when re-executing symbolic instructions in SimEngineUnicorn
    # NRFIN_00036
    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00036")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00036_POV_00000.xml")
    output_initial_bytes = b"New budget created!\nNew budget created!\nNew budget created!\nNew budget created!\n"
    trace_cgc_with_pov_file(binary, "tracer_symbolic_memory_dependencies_liveness", pov_file, output_initial_bytes)

    # CROMU_00008
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00008")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00008_POV_00000.xml")
    output_initial_bytes = (b"> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): "
                            b"Date is: 12/21/1983 5:43:21\nData added, record 0\n"
                            b"> Enter search express (firstname or fn, lastname or ln, username or un, birthdate or bd,"
                            b" operators ==, !=, >, <, AND and OR):\n")
    trace_cgc_with_pov_file(binary, "tracer_symbolic_memory_dependencies_liveness", pov_file, output_initial_bytes)


def test_user_controlled_code_execution():
    # Test user controlled code execution where instruction pointer is concrete and code is symbolic
    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00034")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00034_POV_00000.xml")
    output_initial_bytes = b"\x00" * 8
    trace_cgc_with_pov_file(binary, "tracer_user_controlled_code_execution", pov_file, output_initial_bytes)


def run_all():
    def print_test_name(name):
        print('#' * (len(name) + 8))
        print('###', name, '###')
        print('#' * (len(name) + 8))

    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
