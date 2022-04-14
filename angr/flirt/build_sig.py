# pylint:disable=consider-using-with
from typing import List, Dict
import json
import subprocess
import argparse
import tempfile
import os
import itertools
from collections import defaultdict

import angr


UNIQUE_STRING_COUNT = 20
# strings longer than MAX_UNIQUE_STRING_LEN will be truncated
MAX_UNIQUE_STRING_LEN = 70


def get_basic_info(ar_path: str) -> Dict[str,str]:
    """
    Get basic information of the archive file.
    """

    with tempfile.TemporaryDirectory() as tempdirname:
        cwd = os.getcwd()
        os.chdir(tempdirname)
        subprocess.call(["ar", "x", ar_path])

        # Load arch and OS information from the first .o file
        o_files = [ f for f in os.listdir(".") if f.endswith(".o") ]
        if o_files:
            proj = angr.Project(o_files[0], auto_load_libs=False)
            arch_name = proj.arch.name.lower()
            os_name = proj.simos.name.lower()

        os.chdir(cwd)

    return {
            'arch': arch_name,
            'platform': os_name,
            }


def get_unique_strings(ar_path: str) -> List[str]:
    """
    For Linux libraries, this method requires ar (from binutils), nm (from binutils), and strings.
    """
    # get symbols
    nm_output = subprocess.check_output(["nm", ar_path])
    nm_lines = nm_output.decode("utf-8").split("\n")
    symbols = set()
    for nm_line in nm_lines:
        symbol_types = "UuVvTtRrDdWwBbNn"
        for symbol_type in symbol_types:
            if f" {symbol_type} " in nm_line:
                # parse it
                symbol = nm_line[nm_line.find(f" {symbol_type}") + 3: ].strip(" ")
                if "." in symbol:
                    symbols |= set(symbol.split("."))
                else:
                    symbols.add(symbol)
                break

    # extract the archive file into a temporary directory
    all_strings = set()
    with tempfile.TemporaryDirectory() as tempdirname:
        cwd = os.getcwd()
        os.chdir(tempdirname)
        subprocess.call(["ar", "x", ar_path])

        for filename in os.listdir("."):
            if filename.endswith(".o"):
                strings = subprocess.check_output(["strings", "-n", "8", filename])
                strings = strings.decode("utf-8").split("\n")
                non_symbol_strings = set()
                for s in strings:
                    if s in symbols:
                        continue
                    if "." in s and any(subs in symbols for subs in s.split(".")):
                        continue
                    # C++ specific
                    if "::" in s:
                        continue
                    if "_" in s:
                        # make sure it's not a substring of any symbol
                        is_substring = False
                        for symbol in symbols:
                            if s in symbol:
                                is_substring = True
                                break
                        if is_substring:
                            continue
                    non_symbol_strings.add(s)
                all_strings |= non_symbol_strings

        os.chdir(cwd)

    grouped_strings = defaultdict(set)
    for s in all_strings:
        grouped_strings[s[:5]].add(s)
    sorted_strings = list(sorted(all_strings, key=len, reverse=True))

    ctr = 0
    picked = set()
    unique_strings = [ ]
    for s in sorted_strings:
        if s[:5] in picked:
            continue
        unique_strings.append(s[:MAX_UNIQUE_STRING_LEN])
        picked.add(s[:5])
        ctr += 1
        if ctr >= UNIQUE_STRING_COUNT:
            break
    return unique_strings


def run_pelf(pelf_path: str, ar_path: str, output_path: str):
    subprocess.check_call([pelf_path, "-r43:0:0", ar_path, output_path])


def run_sigmake(sigmake_path: str, sig_name: str, pat_path: str, sig_path: str):
    if " " not in sig_name:
        sig_name_arg = f"-n{sig_name}"
    else:
        sig_name_arg = f"-n\"{sig_name}\""

    proc = subprocess.Popen([sigmake_path, sig_name_arg, pat_path, sig_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            )
    _, stderr = proc.communicate()

    if b"COLLISIONS:" in stderr:
        return False
    return True


def process_exc_file(exc_path: str):
    """
    We are doing the stupidest thing possible: For each batch of conflicts, we pick the most likely
    result baed on a set of predefined rules.

    TODO: Add caller-callee-based de-duplication.
    """
    with open(exc_path, "r") as f:
        data = f.read()
        lines = data.split("\n")

    # parse groups
    ctr = itertools.count()
    idx = 0
    groups = defaultdict(dict)

    for line in lines:
        if line.startswith(";"):
            continue
        if not line:
            idx = next(ctr)
        else:
            # parse the function name
            func_name = line[:line.index("\t")].strip(" ")
            groups[idx][func_name] = line

    # for each group, decide the one to keep
    for idx in list(groups.keys()):
        g = groups[idx]

        if len(g) == 1:
            # don't pick anything. This is a weird case that I don't understand
            continue

        if all(func_name.endswith(".cold") for func_name in g):
            # .cold functions. doesn't matter what we pick
            continue

        non_cold_names = [ ]
        for func_name in g:
            if func_name.endswith(".cold"):
                continue
            non_cold_names.append(func_name)

        # sort it
        non_cold_names = list(sorted(non_cold_names, key=len))

        # pick the top one
        the_chosen_one = non_cold_names[0]
        line = g[the_chosen_one]
        g[the_chosen_one] = "+" + line

    # output
    with open(exc_path, "w") as f:
        for g in groups.values():
            for line in g.values():
                f.write(line + "\n")
            f.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ar_path", help="Path of the .a file to build signatures for")
    parser.add_argument("sig_name", help="Name of the signature (a string inside the signature file)")
    parser.add_argument("sig_path", help="File name of the generated signature")
    parser.add_argument("--compiler", help="Name of the compiler (e.g., gcc, clang). It will be stored in the meta "
                                           "data file.")
    parser.add_argument("--compiler_version", help="Version of the compiler (e.g., 6). It will be stored in the meta "
                                                   "data file.")
    # parser.add_argument("--platform", help="Name of the platform (e.g., windows/linux/macos). It will be stored in
    # the meta data file.")
    parser.add_argument("--os", help="Name of the operating system (e.g., ubuntu/debian). It will be stored in the "
                                     "meta data file.")
    parser.add_argument("--os_version", help="Version of the operating system (e.g., 20.04). It will be stored in the "
                                             "meta data file.")
    parser.add_argument("--pelf_path", help="Path of pelf")
    parser.add_argument("--sigmake_path", help="Path of sigmake")
    args = parser.parse_args()

    if args.pelf_path:
        pelf_path = args.pelf_path
    elif "pelf_path" in os.environ:
        pelf_path = os.environ['pelf_path']
    else:
        raise ValueError("pelf_path must be specified.")

    if args.sigmake_path:
        sigmake_path = args.sigmake_path
    elif "sigmake_path" in os.environ:
        sigmake_path = os.environ['sigmake_path']
    else:
        raise ValueError("sigmake_path must be specified.")

    compiler = args.compiler
    if compiler:
        compiler = compiler.lower()

    compiler_version = args.compiler_version
    if compiler_version:
        compiler_version = compiler_version.lower()

    os_name = args.os
    if os_name:
        os_name = os_name.lower()

    os_version = args.os_version
    if os_version:
        os_version = os_version.lower()

    # Get basic information
    # Get basic information
    basic_info = get_basic_info(args.ar_path)

    # Get unique strings from the library
    unique_strings = get_unique_strings(args.ar_path)

    # Build necessary file paths
    sig_path_basename = os.path.basename(args.sig_path)
    if "." in sig_path_basename:
        sig_dir = os.path.dirname(args.sig_path)
        filename = sig_path_basename[:sig_path_basename.rfind(".")]
        exc_path = os.path.join(
                sig_dir,
                filename + ".exc"
                )
        meta_path = os.path.join(
                sig_dir,
                filename + ".meta"
                )
    else:
        exc_path = args.sig_path + ".exc"
        meta_path = args.sig_path + ".meta"

    if os.path.isfile(exc_path):
        # Remove existing exc files (if there is one)
        os.remove(exc_path)

    # Make a temporary directory
    with tempfile.TemporaryDirectory() as tmpdirname:
        ar_path = args.ar_path
        basename = os.path.basename(ar_path)

        # sanitize basename since otherwise sigmake is not happy with it
        if basename.endswith(".a"):
            basename = basename[:-2]
        basename = basename.replace("+", "plus")

        # sanitize signame as well
        sig_name = args.sig_name
        sig_name = sig_name.replace("+", "plus")

        pat_path = os.path.join(tmpdirname, basename + ".pat")
        run_pelf(pelf_path, ar_path, pat_path)

        has_collision = not run_sigmake(sigmake_path, sig_name, pat_path, args.sig_path)
        if has_collision:
            process_exc_file(exc_path)
            # run sigmake again
            has_collision = not run_sigmake(sigmake_path, args.sig_name, pat_path, args.sig_path)

            assert not has_collision

    with open(meta_path, "w") as f:
        metadata = {
                'unique_strings': unique_strings,
                }
        metadata.update(basic_info)
        if compiler_version:
            metadata['compiler_version'] = compiler_version
        if compiler:
            metadata['compiler'] = compiler
        if os_name:
            metadata['os'] = os_name
        if os_version:
            metadata['os_version'] = os_version
        f.write(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
