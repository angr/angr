import os
import sys
import logging

from common import bin_location, do_trace, load_cgc_pov, slow_test, skip_if_not_linux

import angr


def tracer_cgc(
    filename,
    test_name,
    stdin,
    copy_states=False,
    follow_unsat=False,
    read_strategies=None,
    write_strategies=None,
    add_options=None,
    remove_options=None,
    syscall_data=None,
):
    p = angr.Project(filename)
    p.simos.syscall_library.update(angr.SIM_LIBRARIES["cgcabi_tracer"])

    trace, magic, crash_mode, crash_addr = do_trace(p, test_name, stdin)
    s = p.factory.entry_state(
        mode="tracing",
        stdin=angr.SimFileStream,
        flag_page=magic,
        add_options=add_options,
        remove_options=remove_options,
    )
    if read_strategies is not None:
        s.memory.read_strategies = read_strategies
    if write_strategies is not None:
        s.memory.write_strategies = write_strategies
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, hierarchy=None, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(
        trace,
        crash_addr=crash_addr,
        keep_predecessors=1,
        copy_states=copy_states,
        follow_unsat=follow_unsat,
        syscall_data=syscall_data,
    )
    if add_options is not None and angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL in add_options:
        t.set_fd_data({0: stdin})

    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t


def trace_cgc_with_pov_file(
    binary: str,
    test_name: str,
    pov_file: str,
    output_initial_bytes: bytes,
    copy_states=False,
    read_strategies=None,
    write_strategies=None,
    add_options=None,
    remove_options=None,
    syscall_data=None,
):
    assert os.path.isfile(pov_file)
    pov = load_cgc_pov(pov_file)
    trace_result = tracer_cgc(
        binary,
        test_name,
        b"".join(pov.writes),
        copy_states,
        read_strategies=read_strategies,
        write_strategies=write_strategies,
        add_options=add_options,
        remove_options=remove_options,
        syscall_data=syscall_data,
    )
    simgr = trace_result[0]
    simgr.run()
    assert "traced" in simgr.stashes
    assert len(simgr.traced) == 1
    stdout_dump = simgr.traced[0].posix.dumps(1)
    assert stdout_dump.startswith(output_initial_bytes)


def tracer_linux(filename, test_name, stdin, add_options=None, remove_options=None):
    p = angr.Project(filename)

    trace, _, crash_mode, crash_addr = do_trace(
        p,
        test_name,
        stdin,
        ld_linux=p.loader.linux_loader_object.binary,
        library_path={os.path.dirname(obj.binary) for obj in p.loader.all_elf_objects},
        record_stdout=True,
    )
    s = p.factory.full_init_state(
        mode="tracing",
        stdin=angr.SimFileStream,
        add_options=add_options,
        remove_options=remove_options,
    )
    s.preconstrainer.preconstrain_file(stdin, s.posix.stdin, True)

    simgr = p.factory.simulation_manager(s, hierarchy=None, save_unconstrained=crash_mode)
    t = angr.exploration_techniques.Tracer(trace, crash_addr=crash_addr)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())

    return simgr, t


def test_recursion():
    blob = bytes.fromhex(
        "00aadd114000000000000000200000001d0000000005000000aadd2a1100001d0000000001e8030000aadd21118611b3b3b3b3b3e3b1b"
        "1b1adb1b1b1b1b1b1118611981d8611"
    )
    fname = os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests", "cgc", "NRFIN_00075")

    simgr, _ = tracer_cgc(fname, "tracer_recursion", blob)
    simgr.run()

    assert simgr.crashed
    assert simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip)


@slow_test
def broken_cache_stall():
    # test a valid palindrome
    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00071")
    blob = bytes.fromhex(
        "0c0c492a53acacacacacacacacacacacacac000100800a0b690e0aef6503697d660a0059e20afc0a0a332f7d66660a0059e20afc0a0a3"
        "32f7fffffff16fb1616162516161616161616166a7dffffff7b0e0a0a6603697d660a0059e21c"
    )

    simgr, tracer = tracer_cgc(b, "tracer_cache_stall", blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.crashed[0]

    assert crash_path is not None
    assert crash_state is not None

    # load it again
    simgr, tracer = tracer_cgc(b, "tracer_cache_stall", blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    assert crash_path is not None
    assert crash_state is not None


@skip_if_not_linux
def test_manual_recursion():
    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00071")
    with open(os.path.join(bin_location, "tests_data", "crash2731"), "rb") as fh:
        blob = fh.read()

    simgr, tracer = tracer_cgc(b, "tracer_manual_recursion", blob)
    simgr.run()

    crash_path = tracer.predecessors[-1]
    crash_state = simgr.one_crashed

    assert crash_path is not None
    assert crash_state is not None


def test_cgc_receive_unicorn_native_interface():
    """
    Test if unicorn native interface handles CGC receive syscall correctly. Receives with symbolic arguments also
    tested.
    """

    binary = os.path.join(bin_location, "tests", "cgc", "KPRCA_00038")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00038_POV_00000.xml")
    output_initial_bytes = b""
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
        angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS,
    }
    trace_cgc_with_pov_file(
        binary, "tracer_cgc_receive_unicorn_native_interface", pov_file, output_initial_bytes, add_options=add_options
    )


def test_cgc_receive_unicorn_native_interface_rx_bytes():
    """
    Test rx_bytes is correctly handled by unicorn native interface's CGC receive: update only if non-null
    """

    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00012")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00012_POV_00000.xml")
    output_initial_bytes = b""
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_cgc_receive_unicorn_native_interface_rx_bytes",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_cgc_random_syscall_handling_native_interface():
    """
    Test if random syscall is correctly handled in native interface. Random with symbolic arguments also tested.
    """

    binary = os.path.join(bin_location, "tests", "cgc", "KPRCA_00011")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00011_POV_00000.xml")
    output_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00011_stdout.txt")
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_CGC_RANDOM_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
        angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS,
    }

    rand_syscall_data = {
        "random": [
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
            (65, 1),
            (16705, 2),
            (16705, 2),
        ]
    }
    with open(output_file, "rb") as fh:
        output_bytes = fh.read()

    trace_cgc_with_pov_file(
        binary,
        "tracer_cgc_receive_unicorn_native_interface_rx_bytes",
        pov_file,
        output_bytes,
        add_options=add_options,
        syscall_data=rand_syscall_data,
    )


def test_cgc_se1_palindrome_raw():
    b = os.path.join(bin_location, "tests", "cgc", "sc1_0b32aa01_01")
    # test a valid palindrome

    simgr, _ = tracer_cgc(b, "tracer_cgc_se1_palindrome_raw_nocrash", b"racecar\n")
    simgr.run()

    # make sure the heap base is correct and hasn't been altered from the default
    assert "traced" in simgr.stashes
    assert simgr.traced[0].cgc.allocation_base == 0xB8000000

    # make sure there is no crash state
    assert not simgr.crashed

    # make sure angr modeled the correct output
    stdout_dump = simgr.traced[0].posix.dumps(1)
    assert stdout_dump.startswith(
        b"\nWelcome to Palindrome Finder\n\n"
        b"\tPlease enter a possible palindrome: "
        b"\t\tYes, that's a palindrome!\n\n"
        b"\tPlease enter a possible palindrome: "
    )
    # make sure there were no 'Nope's from non-palindromes
    assert b"Nope" not in stdout_dump

    # now test crashing input
    simgr, _ = tracer_cgc(b, "tracer_cgc_se1_palindrome_raw_yescrash", b"A" * 129)
    simgr.run()

    assert simgr.crashed


def test_d_flag_and_write_write_conflict_in_unicorn():
    """
    Check if d flag is handled correctly in unicorn native interface and write-write conflicts do not occur when
    re-executing symbolic instructions
    """

    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00008")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00008_POV_00000.xml")
    output_initial_bytes = (
        b"> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): "
        b"Date is: 12/21/1983 5:43:21\nData added, record 0\n"
        b"> Enter search express (firstname or fn, lastname or ln, username or un, birthdate or bd,"
        b" operators ==, !=, >, <, AND and OR):\n"
    )
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_d_flag_and_write_write_conflict_in_unicorn",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_empty_reexecute_block_remove_in_unicorn_native_interface():
    """
    Test if blocks with no symbolic instructions are removed from re-execution list in unicorn native interface.
    Re-execute instruction list of a block can become empty when all of them are removed when performing memory writes.
    See handle_write in unicorn native interface.
    """

    binary = os.path.join(bin_location, "tests", "cgc", "KPRCA_00052")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00052_POV_00000.xml")
    output_initial_bytes = (
        b"Enter system password: \nWelcome to the CGC Pizzeria order management system.\n1. Input Order\n"
        b"2. Update Order\n3. View One Orders\n4. View All Orders\n5. Delete Order\n6. Clear All Orders\n7. Logout\n"
        b"Choice: Enter Pickup Name: Choose what the kind of pizza\n1. Pizza Pie - The classic!\n"
        b"2. Pizza Sub - All the fun, on a bun\n3. Pizza Bowl - Our own twist\nChoice: Select Size\n1. Small\n"
        b"2. Medium\n3. Large\nChoice: Successfully added a new Pizza Pie!\nSelect an option:\n1. Add Toppings\n"
        b"2. Remove Toppings\n3. Add Sauce\n4. Remove Sauce\n5. Finished With Pizza\nChoice: Successfully added pizza!"
        b"\n1. Add another Pizza\n2. Quit\nChoice: 0. Cancel\n==================================================\n  "
        b"Item #1. Classic Pizza Pie, Size: SMALL\n    Selected Toppings\n\tNone\n    Sauce on the side\n\tNone\n"
        b"--------------------------------------\n\t\tCalories: 1000\n\t\tCarbs   : 222\n\nPizza length... = 1\n\t\t"
        b"Estimated wait time: 36 minute(s)\n==================================================\nChoice: "
        b"Removed Item #1\n1. Add another Pizza\n2. Quit\nChoice: Order successfully added!\n1. Input Order\n"
        b"2. Update Order\n3. View One Orders\n4. View All Orders\n5. Delete Order\n6. Clear All Orders\n7. Logout\n"
        b"Choice: 1 - pov: Ordered 0 pizza(s)\n==================================================\n"
        b"--------------------------------------\n\t\tCalories: 0\n\t\tCarbs   : 0\n\n"
    )
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_empty_reexecute_block_remove_in_unicorn_native_interface",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_symbolic_sized_receives():
    b = os.path.join(bin_location, "tests", "cgc", "CROMU_00070")

    simgr, _ = tracer_cgc(b, "tracer_symbolic_sized_receives", b"hello")
    simgr.run()

    assert not simgr.crashed
    assert "traced" in simgr.stashes

    simgr, _ = tracer_cgc(b, "tracer_symbolic_sized_receives_nulls", b"\0" * 20)
    simgr.run()

    assert not simgr.crashed
    assert "traced" in simgr.stashes


def test_allocation_base_continuity():
    correct_out = (
        b"prepare for a challenge\nb7fff000\nb7ffe000\nb7ffd000\nb7ffc000\nb7ffb000\nb7ffa000\nb7ff9000\nb7ff8000\n"
        b"b7ff7000\nb7ff6000\nb7ff5000\nb7ff4000\nb7ff3000\nb7ff2000\nb7ff1000\nb7ff0000\nb7fef000\nb7fee000\n"
        b"b7fed000\nb7fec000\ndeallocating b7ffa000\na: b7ffb000\nb: b7fff000\nc: b7ff5000\nd: b7feb000\ne: b7fe8000\n"
        b"e: b7fa8000\na: b7ffe000\nb: b7ffd000\nc: b7ff7000\nd: b7ff6000\ne: b7ff3000\ne: b7f68000\nallocate: 3\n"
        b"a: b7fef000\n"
    )

    b = os.path.join(bin_location, "tests", "i386", "cgc_allocations")

    simgr, _ = tracer_cgc(b, "tracer_allocation_base_continuity", b"")
    simgr.run()

    assert simgr.traced[0].posix.dumps(1) == correct_out


def test_crash_addr_detection():
    b = os.path.join(bin_location, "tests", "i386", "call_symbolic")

    simgr, _ = tracer_cgc(b, "tracer_crash_addr_detection", b"A" * 700)
    simgr.run()

    assert simgr.crashed
    assert simgr.crashed[0].solver.symbolic(simgr.crashed[0].regs.ip)


@skip_if_not_linux
def test_fauxware():
    b = os.path.join(bin_location, "tests", "x86_64", "fauxware")
    simgr, _ = tracer_linux(b, "tracer_fauxware", b"A" * 18, remove_options={angr.options.CPUID_SYMBOLIC})
    simgr.run()

    assert "traced" in simgr.stashes


def test_rollback_on_symbolic_conditional_exit():
    # Test if state is correctly rolled back to before start of block in case block cannot be executed in unicorn engine
    # because exit condition is symbolic
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00043")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00043_POV_00000.xml")
    output_initial_bytes = [
        b"Network type: Broadcast",
        b"Source Address: 0x962B175B",
        b"Network type: Endpoint",
        b"Source Address: 0x321B00B0",
        b"Destination Address: 0xACF70019",
        b"Final Statistics:",
        b"\tTotal Packets: 6",
        b"\tStart Time: 0x5552C470",
        b"\tEnd Time: 0x54CAF0B0",
        b"\tLargest Packet: 0",
        b"\tSmallest Packet: 0",
        b"\tNumber of malformed packets: 0",
        b"\tNumber of packets shown 6",
        b"Option Headers:",
        b"This content has not been modified from the original",
        b"Capturing Authority: Network Provider",
        b"Capture Date: bKQcAXJJEqCSPmrIlRy",
        b"Capturing Authority: Employer\n",
    ]
    trace_cgc_with_pov_file(
        binary,
        "tracer_rollback_on_symbolic_conditional_exit",
        pov_file,
        b"\n".join(output_initial_bytes),
    )


def test_floating_point_memory_reads():
    # Test float point memory reads in which bytes longer than architecture width are read in a single memory read hook
    # in unicorn. The other related case is when such reads are split across multiple reads. This is tested in
    # b01lersctf2020 little engine solver
    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00027")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00027_POV_00000.xml")
    output = b"\x00" * 36
    trace_cgc_with_pov_file(
        binary,
        "tracer_floating_point_memory_reads",
        pov_file,
        output,
        read_strategies=[angr.concretization_strategies.SimConcretizationStrategyAny(exact=True)],
        write_strategies=[angr.concretization_strategies.SimConcretizationStrategyAny(exact=True)],
    )


def test_fdwait_fds():
    # Test fdwait working with appropriate bit order for read/write fds
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00029")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00029_POV_00000.xml")
    output = [
        b"For what material would you like to run this simulation?",
        b"  1. Air",
        b"  2. Aluminum",
        b"  3. Copper",
        b"  4. Custom\nSelection: ",
    ]
    trace_cgc_with_pov_file(binary, "tracer_floating_point_memory_reads", pov_file, b"\n".join(output))


def test_non_zero_offset_subregister_dependency_saving_unicorn_native_interface():
    """
    Test if concrete register dependencies of symbolic instructions are saved correctly in unicorn native interface for
    re-executing
    """

    binary = os.path.join(bin_location, "tests", "cgc", "KPRCA_00028")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "KPRCA_00028_POV_00000.xml")
    output_initial_bytes = b"Welcome to the SLUR REPL. Type an expression to evaluate it.\n> "
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_non_zero_offset_subregister_dependency_saving_unicorn_native_interface",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_saving_dependencies_of_last_instruction_of_block_in_unicorn_native_interface():
    """
    Test if dependencies of last instruction in a basic block are saved in unicorn native interface
    """

    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00026")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00026_POV_00000.xml")
    output_initial_bytes = (
        b"Starting dissection...\n\n\n====New Packet====\n\n\n===rofl===\n\n\n===rachiometersuprachoroid===\n301478991"
        b"\nString display will be handled in v4.\n1\nString display will be handled in v4.\n0\n1\n"
        b"LV type will be handled in v4.\n3582705152\nString display will be handled in v4.\n"
        b"LV type will be handled in v4.\n190\n0\n===trolololo===\n"
    )
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_saving_dependencies_of_last_instruction_of_block_in_unicorn_native_interface",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


@slow_test
def test_sseround_register_dependency_unicorn_native_interface():
    """
    Test if value of SSEROUND VEX register is saved correctly when it is a dependency of an instruction that needs to be
    re-executed. Takes about 10 minutes.
    """

    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00021")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00021_POV_00000.xml")
    output_initial_bytes = b""
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_sseround_register_dependency_unicorn_native_interface",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_concretize_unsupported_vex_irops():
    # Test tracing with concretizing unsupported VEX IR Ops
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00020")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00020_POV_00000.xml")
    output = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x15"
        + b"\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00"
    )
    add_options = {
        angr.options.UNSUPPORTED_FORCE_CONCRETIZE,
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
    }
    trace_cgc_with_pov_file(binary, "tracer_concretize_unsupported_vex_ops", pov_file, output, add_options=add_options)


def test_skip_some_symbolic_memory_writes():
    # Test symbolic memory write skipping in SimEngineUnicorn during tracing
    # This test doesn't actually check if instruction was skipped. It checks if tracing is successful
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00023")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00023_POV_00000.xml")
    output_initial_bytes = [
        b"",
        b"C - Change Diver Info",
        b"L - Log a New Dive",
        b"D - Download Dive Data",
        b"E - Edit Dives",
        b"P - Print Dive Logs",
        b"R - Remove Dives",
        b"S - Diver Statistics",
        b"X - Exit Application",
        b":",
        b"",
        b"Dive Log is empty",
        b"",
        b"C - Change Diver Info",
        b"L - Log a New Dive",
        b"D - Download Dive Data",
        b"E - Edit Dives",
        b"P - Print Dive Logs",
        b"R - Remove Dives",
        b"S - Diver Statistics",
        b"X - Exit Application",
        b":",
        b"",
        b"Dive Log is empty",
        b"",
        b"C - Change Diver Info",
        b"L - Log a New Dive",
        b"D - Download Dive Data",
        b"E - Edit Dives",
        b"P - Print Dive Logs",
        b"R - Remove Dives",
        b"S - Diver Statistics",
        b"X - Exit Application",
        b":",
        (
            b"Dive Site: Date: Time: Location (area/city): Max Depth in ft: Avg Depth in ft: "
            b"Dive Duration (mins): O2 Percentage: Pressure In (psi): Pressure Out (psi): "
        ),
        b"C - Change Diver Info",
        b"L - Log a New Dive",
        b"D - Download Dive Data",
        b"E - Edit Dives",
        b"P - Print Dive Logs",
        b"R - Remove Dives",
        b"S - Diver Statistics",
        b"X - Exit Application",
        b":",
        (
            b"Dive Site: Date: Time: Location (area/city): Max Depth in ft: Avg Depth in ft: "
            b"Dive Duration (mins): O2 Percentage: Pressure In (psi): Pressure Out (psi): "
        ),
        b"C - Change Diver Info",
        b"L - Log a New Dive",
        b"D - Download Dive Data",
        b"E - Edit Dives",
        b"P - Print Dive Logs",
        b"R - Remove Dives",
        b"S - Diver Statistics",
        b"X - Exit Application",
        b":",
        (
            b"First Name: Last Name: Street: City: State: Zip Code: Phone Number: PADI Diver Number: "
            b"PADI Cert Date: "
        ),
        b"     Name: ",
    ]
    trace_cgc_with_pov_file(
        binary,
        "tracer_skip_some_symbolic_memory_writes",
        pov_file,
        b"\n".join(output_initial_bytes),
    )


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
    trace_cgc_with_pov_file(
        binary,
        "tracer_symbolic_memory_dependencies_liveness",
        pov_file,
        output_initial_bytes,
    )

    # CROMU_00008
    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00008")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00008_POV_00000.xml")
    output_initial_bytes = (
        b"> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): "
        b"Date is: 12/21/1983 5:43:21\nData added, record 0\n"
        b"> Enter search express (firstname or fn, lastname or ln, username or un, birthdate or bd,"
        b" operators ==, !=, >, <, AND and OR):\n"
    )
    trace_cgc_with_pov_file(
        binary,
        "tracer_symbolic_memory_dependencies_liveness",
        pov_file,
        output_initial_bytes,
    )


def test_symbolic_cgc_transmit_handling_in_native_interface():
    """
    Check if CGC transmit syscall with symbolic arguments is handled in native interface when tracing.
    """

    binary = os.path.join(bin_location, "tests", "cgc", "CROMU_00008")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "CROMU_00008_POV_00000.xml")
    output_initial_bytes = (
        b"> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): "
        b"Date is: 12/21/1983 5:43:21\nData added, record 0\n"
        b"> Enter search express (firstname or fn, lastname or ln, username or un, birthdate or bd,"
        b" operators ==, !=, >, <, AND and OR):\n"
    )
    add_options = {
        angr.options.UNICORN_HANDLE_CGC_RECEIVE_SYSCALL,
        angr.options.UNICORN_HANDLE_SYMBOLIC_ADDRESSES,
        angr.options.UNICORN_HANDLE_SYMBOLIC_CONDITIONS,
        angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS,
    }
    trace_cgc_with_pov_file(
        binary,
        "tracer_symbolic_cgc_transmit_handling_in_native_interface",
        pov_file,
        output_initial_bytes,
        add_options=add_options,
    )


def test_user_controlled_code_execution():
    # Test user controlled code execution where instruction pointer is concrete and code is symbolic
    binary = os.path.join(bin_location, "tests", "cgc", "NRFIN_00034")
    pov_file = os.path.join(bin_location, "tests_data", "cgc_povs", "NRFIN_00034_POV_00000.xml")
    output_initial_bytes = b"\x00" * 8
    trace_cgc_with_pov_file(binary, "tracer_user_controlled_code_execution", pov_file, output_initial_bytes)


def run_all():
    def print_test_name(name):
        print("#" * (len(name) + 8))
        print("###", name, "###")
        print("#" * (len(name) + 8))

    functions = globals()
    all_functions = {fn_name: fn_obj for (fn_name, fn_obj) in functions.items() if fn_name.startswith("test_")}
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], "__call__"):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()["test_" + sys.argv[1]]()
    else:
        run_all()
