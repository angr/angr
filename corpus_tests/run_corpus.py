import angr
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION
import argparse
import json
import logging
import os
import random
import re
import subprocess

"""
Run the angr decompiler on a set of binaries.
"""

STABLE_BINARY_FILE = 'stable.txt'

logging.basicConfig(level=logging.CRITICAL, force=True)


def analyze_binary(binary_path, name='cpu##'):
    """
    Run the binary through CFG generation and extract the decompilation from the Decompiler analysis.
    The intention of this analysis function is to use as little angr interfaces as possible since they may
    change over time. If they change, this script will need updating.
    """
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = {}

    function: angr.knowledge_plugins.functions.function.Function
    for function in cfg.functions.values():
        function.normalize()

        # Wrapping in a try/except because the decompiler sometimes fails
        try:
            decomp = project.analyses.Decompiler(
                func=function,
                cfg=cfg,
                # setting show_casts to false because of non-determinism
                options=[
                    (
                        PARAM_TO_OPTION["structurer_cls"],
                        "Phoenix",
                    ),
                    (
                        PARAM_TO_OPTION["show_casts"],
                        False,
                    ),
                ],
            )
        except Exception as e:
            print(f'{name}: Exception decompiling {function.name}: {e}')

        func_key = f"{function.addr}:{function.name}"

        if decomp.codegen:
            decompilation[func_key] = decomp.codegen.text
        else:
            decompilation[func_key] = None

    return decompilation


def write_snapshot_json_for_binary(binary, analysis, name):
    snapshots_binary = re.sub('^binaries/', 'snapshots/', binary)
    dir_path = os.path.dirname(snapshots_binary).replace('/', os.path.sep)
    os.makedirs(dir_path, exist_ok=True)
    snapshot_file_path = os.path.join(dir_path, f"{os.path.basename(binary)}.json")
    try:
        with open(snapshot_file_path, "w") as f:
            json.dump(analysis, f)
    except Exception as ex:
        print(f'{name}: Exception writing to "{snapshot_file_path}": {ex}')
        return False, snapshot_file_path
    return True, snapshot_file_path


def run_functions_decompilation(binary, name, write_empty_on_error, find_stable_decompilation):
    print(f'{name}: Performing decompilation of "{binary}".')
    analysis = None
    try:
        analysis = analyze_binary(binary, name=name)
        if find_stable_decompilation:
            print(f'{name}: Performing second decompilation of "{binary}" for stability check.')
            analysis_2 = analyze_binary(binary, name=name + '-2')
            if analysis == analysis_2:
                print(f'{name}: Decompilations of "{binary}" were the same; adding to "{STABLE_BINARY_FILE}".')
                with open(STABLE_BINARY_FILE, "at") as f:
                    f.write(binary + '\n')
            else:
                print(f'{name}: Decompilations of "{binary}" differed.')
    except Exception as ex:
        print(f'{name}: Exception anaylizing "{binary}": {ex}')
        if write_empty_on_error:
            print(f'{name}: Writing empty analysis record with exception text (due to "-E").')
            analysis = { "0:exception": f'{ex}' }
        else:
            return False
    result, snapshot_file_path = write_snapshot_json_for_binary(binary, analysis, name)
    if result:
        print(f'{name}: Wrote decompilation JSON to "{snapshot_file_path}".')
    return result


def divvy_up_work(files, args):
    cpus = os.cpu_count()
    cpus = 1 if cpus <= 1 else cpus - 1
    if cpus > len(files):
        cpus = len(files)
    print(f'main: Using {cpus} subprocesses to handle {len(files)} files.')
    files_per_cpu = [[] for _ in range(cpus)]
    cpu = 0
    for file in files:
        files_per_cpu[cpu].append(file)
        cpu = (cpu + 1) % cpus

    # Now kick off all subprocesses:
    commands = []
    processes = []
    for cpu in range(cpus):
        these_files = " ".join(files_per_cpu[cpu])
        options = ""
        if args.empty_json:
            options += " --empty-json"
        if args.find_stable:
            options += " --find-stable"
        command = f'. .venv/bin/activate; python3 run_corpus.py --name cpu{cpu:02d}{options} {these_files}'
        # print(f'main: command="{command}"')
        commands.append(command)
        process = subprocess.Popen(command, shell=True)
        processes.append(process)
        # break

    # Wait for all subprocesses:
    for process in processes:
        process.wait()

    print(f'main: all processes have completed running')


def file_is_binary(filename):
    exts = ('.json', '.txt', '.jpg', '.md')
    if filename.endswith(exts):
        return False
    try:
        if (os.stat(filename) & 0o111) == 0o000:
            return False
    except Exception:
        pass
    return True


def find_files(path):
    # Run the 'find <path> -type f' command
    result = subprocess.run(['find', path, '-type', 'f'], capture_output=True, text=True)
    
    # Check if the command was successful
    if result.returncode == 0:
        # Split the output by newlines to get a list of file paths
        files = result.stdout.splitlines()
        return files
    else:
        # Handle the error case
        raise Exception(f"Error running find command: {result.stderr}")


def main():
    parser = argparse.ArgumentParser(description='''
                                     Run binaries through angr and create
                                     JSON files with the decompiler output.
                                     ''')
    parser.add_argument('binaries', type=str, nargs='+',
                        help='''Path to binaries or directories of binaries.
                                All regular files will be decompiled.''')
    parser.add_argument('--main', '-m', action='store_true',
                        help='''Be the main process and divvy the work
                                among subprocesses.''')
    parser.add_argument('--name', '-n', type=str, default="main",
                        help='The name of this subprocess.')
    parser.add_argument('--empty-json', '-E', action='store_true',
                        help="""Write an empty JSON object (possibly with an "0:exception" field)
                                if no functions could be decompiled.""")
    parser.add_argument('--find-stable', '-f', action='store_true',
                        help=f"""Run 'angr' twice to see if the output changes.
                                Write stable binaries to '{STABLE_BINARY_FILE}'.""")
    args = parser.parse_args()

    files = []

    for file in args.binaries:
        if os.path.isfile(file):
            # print(f'adding file "{file}"')
            files.append(file)
        elif os.path.isdir(file):
            try:
                # print(f'adding files from dir "{file}"')
                files.extend(find_files(file))
            except Exception as ex:
                print(f'Exception caught collecting files:\n{ex}')
                exit(1)
        else:
            print(f'Unknown file type for "{file}"; skipping.')

    files = list(filter(file_is_binary, files))
    print(f'{args.name}: Handling {len(files)} files.')

    if len(files) == 0:
        print(f'{args.name}: Nothing to do.')
        exit(0)

    # Shuffle the order so each run has a different order.
    for i in range(len(files)):
        k = random.randrange(len(files))
        if k != i:
            files[i], files[k] = files[k], files[i]

    if args.main:
        divvy_up_work(files, args)
    else:
        successful = 0
        for file in files:
            try:
                if run_functions_decompilation(file, args.name,
                                               args.empty_json,
                                               args.find_stable):
                    successful += 1
                    if os.path.exists(file):
                        os.unlink(file)
            except Exception as ex:
                print(f'{args.name}: Exception caught analyzing "{file}":\n{ex}')
                print(f'{args.name}: Continuing...')
        print(f'{args.name}: Finished processing {successful} of {len(files)} files.')


if __name__ == "__main__":
    main()
