from typing import Dict, Any, Tuple, List, Optional
import os

import angr


def find_base_addr_in_coredump(proj: 'angr.Project', so_filename: str) -> Optional[int]:
    coredump = proj.loader.main_object
    all_sections: Dict[int, Any] = dict((sec.vaddr, sec) for sec in coredump.sections)

    coredump_so_sections: Dict[int, Any] = {}
    for vaddr_start, _, file_offset, file_path in coredump.filename_lookup:
        if os.path.basename(file_path) == so_filename:
            coredump_so_sections[vaddr_start] = file_path, all_sections.get(vaddr_start, None)

    if not coredump_so_sections:
        return None

    so_baseaddr = min(coredump_so_sections)


    return so_baseaddr


def diff_coredump(core_dump_location: str, so_filename: str, so_path: str) -> List[Tuple[Any,bytes,bytes]]:
    """
    Diffing memory content of a core dump against a reference .so library file and reporting differences.

    :param core_dump_location:  The path to a core dump.
    :param so_filename:         The file name of the .so file at runtime.
    :param so_path:             The path to the reference .so file.
    :return:                    A list of tuple: <section that is modified, content in bytes at runtime, content in
                                bytes in the reference library file>.
    """

    proj = angr.Project(core_dump_location)

    # parse the main object (the core dump) to find relevant sections for the specified .so file
    coredump = proj.loader.main_object

    so_baseaddr = find_base_addr_in_coredump(proj, so_filename)
    print(f"[+] {so_filename} was loaded at base address {so_baseaddr:x}.")

    # load the original .so file at the given base address
    so_proj = angr.Project(so_path, auto_load_libs=False, main_opts={'base_addr': so_baseaddr})

    diffs = [ ]

    # compare code and data sections
    for section in so_proj.loader.main_object.sections:
        if section.memsize <= 0:
            # skip unmapped sections
            continue
        if section.is_executable:
            # code section
            # compare them byte-by-byte
            try:
                coredump_content = coredump.memory.load(section.vaddr - coredump.mapped_base, section.memsize)
            except KeyError:
                print(f"[.] Executable section {section} is not found in the core dump.")
                continue
            so_content = so_proj.loader.main_object.memory.load(section.vaddr - so_proj.loader.main_object.mapped_base,
                                                                section.memsize)
            if coredump_content != so_content:
                # found differences
                print(f"[-] Found byte-level differences in {section}.")
                diffs.append((section, coredump_content, so_content))
            else:
                print(f"[+] {section} is not modified during runtime.")
        elif section.is_readable and section.is_writable:
            # data section
            try:
                coredump_content = coredump.memory.load(section.vaddr - coredump.mapped_base, section.memsize)
            except KeyError:
                print(f"[.] Data section {section} is not found in the core dump.")
                continue
            so_content = so_proj.loader.main_object.memory.load(section.vaddr - so_proj.loader.main_object.mapped_base,
                                                                section.memsize)
            if coredump_content != so_content:
                # found differences
                if section.name in {'.got', '.got.plt', '.dynamic', '.bss'}:
                    # they will be modified during runtime.
                    continue
                print(f"[-] Found byte-level differences in {section}.")
                diffs.append((section, coredump_content, so_content))
            else:
                print(f"[+] {section} is not modified during runtime.")

    return diffs


def compare_src(a, base_addr_0: int, b, base_addr_1: int) -> bool:
    if type(a) is tuple and type(b) is tuple:
        a0, stmt_idx_0 = a
        a1, stmt_idx_1 = b

        return (a0 - base_addr_0, stmt_idx_0) == (a1 - base_addr_1, stmt_idx_1)
    else:
        return a == b


def compare_value(a, b):
    return a == b


def compare_state_graphs(graph0, base_addr_0: int, graph1, base_addr_1: int):
    """
    This method compares two generated state graphs and reasons about their differences.

    :param graph0:
    :param graph1:
    :return:
    """

    states_by_id_0 = {}
    for node in graph0.nodes():
        state_id = node[0][1]
        states_by_id_0[state_id] = node

    states_by_id_1 = {}
    for node in graph1.nodes():
        state_id = node[0][1]
        states_by_id_1[state_id] = node

    # compare states by their IDs
    if len(states_by_id_0) != len(states_by_id_1):
        print("[-] Graph 0 has %d states while Graph 1 has %d states." % (len(states_by_id_0), len(states_by_id_1)))

    # compare each state
    node_ids_0 = set(states_by_id_0.keys())
    node_ids_1 = set(states_by_id_1.keys())
    for idx in sorted(node_ids_0.intersection(node_ids_1)):
        s0 = states_by_id_0[idx]
        s1 = states_by_id_1[idx]

        abs_state_0 = dict(s0[1:])
        abs_state_1 = dict(s1[1:])

        if set(abs_state_0) != set(abs_state_1):
            print("[-] Graph 0 and Graph 1 have different keys: %s" % set(abs_state_0).difference(set(abs_state_1)))

        # check values of their common keys
        common_keys = set(abs_state_0).intersection(set(abs_state_1))
        for k in common_keys:
            if k == "td_src":
                r = compare_src(abs_state_0[k], base_addr_0, abs_state_1[k], base_addr_1)
            else:
                r = compare_value(abs_state_0[k], abs_state_1[k])
            if not r:
                print("[-] Graph 0, State %d, %s = %s; Graph 1, State %d, %s = %s" % (
                    idx,
                    k,
                    abs_state_0[k],
                    idx,
                    k,
                    abs_state_1[k]
                ))

        # finally, check their edges
        out_edges_0 = list(graph0.out_edges(s0, data=True))
        out_edges_1 = list(graph1.out_edges(s1, data=True))

        if len(out_edges_0) != len(out_edges_1):
            print("[-] Graph 0, State %d has %d successors; Graph 1, State %d has %d successors" % (
                idx,
                len(out_edges_0),
                idx,
                len(out_edges_1)
            ))

        # if there is only one edge, compare their edge data and successors...
        # TODO: Support multiple edges
        if len(out_edges_0) == len(out_edges_1) == 1:
            out_edge_0 = out_edges_0[0]
            out_edge_1 = out_edges_1[0]
            time_delta_0 = out_edge_0[2]['time_delta']
            time_delta_1 = out_edge_1[2]['time_delta']

            if time_delta_0 != time_delta_1:
                print("[-] Graph 0, State %d has time delta of %s; Graph 1, State %d has time delta of %s" % (
                idx,
                time_delta_0,
                idx,
                time_delta_1
            ))
