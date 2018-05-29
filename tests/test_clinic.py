
import os

import angr
import angr.analyses.decompiler


def main():
    binary_path = os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all')

    proj = angr.Project(binary_path, auto_load_libs=False)

    cfg = proj.analyses.CFG()

    main_func = cfg.kb.functions['main']

    clinic = proj.analyses.Clinic(main_func)

    print clinic.dbg_repr()


if __name__ == "__main__":
    main()
