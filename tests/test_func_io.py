
import angr


def test_smoketest():
    proj = angr.Project("../../binaries/tests/x86_64/types/input_n_output_O0", auto_load_libs=False)
    cfg = proj.analyses.CFG(normalize=True)
    proj.analyses.CompleteCallingConventions(recover_variables=True)

    for func in cfg.functions.values():
        if func.name.startswith("checksum"):
            print(repr(func), func.calling_convention)
            fp = proj.analyses.FunctionPrototype(func)
            print(fp.param_descriptors)


if __name__ == "__main__":
    test_smoketest()
