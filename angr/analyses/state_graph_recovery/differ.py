from typing import Dict, Any, Tuple, List
import os

import angr


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

    all_sections: Dict[int, Any] = dict((sec.vaddr, sec) for sec in coredump.sections)

    coredump_so_sections: Dict[int, Any] = {}
    for vaddr_start, _, file_offset, file_path in coredump.filename_lookup:
        if os.path.basename(file_path) == so_filename:
            coredump_so_sections[vaddr_start] = file_path, all_sections.get(vaddr_start, None)

    assert coredump_so_sections
    so_baseaddr = min(coredump_so_sections)
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
