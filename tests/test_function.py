import os


import angr

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"
)


def test_function_serialization():

    p = angr.Project(
        os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False
    )
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions["main"]
    s = func_main.serialize()

    assert type(s) is bytes
    assert len(s) > 10

    f = angr.knowledge_plugins.Function.parse(s)
    assert func_main.addr == f.addr
    assert func_main.name == f.name
    assert func_main.is_prototype_guessed == f.is_prototype_guessed


def test_function_definition_application():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False
    )
    cfg = p.analyses.CFG()
    func_main = cfg.kb.functions["main"]  # type: angr.knowledge_plugins.Function

    func_main.apply_definition("int main(int argc, char** argv)")

    # Check prototype of function
    assert func_main.prototype.args == [
        angr.sim_type.SimTypeInt().with_arch(p.arch),
        angr.sim_type.SimTypePointer(
            angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar()).with_arch(p.arch)
        ).with_arch(p.arch),
    ]
    # Check that the default calling convention of the architecture was applied
    assert isinstance(
        func_main.calling_convention, angr.calling_conventions.DefaultCC[p.arch.name]
    )

    func_main.apply_definition("int main(int argc, char** argv)")


def test_function_instruction_addr_from_any_addr():

    p = angr.Project(
        os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False
    )
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions["main"]

    assert func_main.addr_to_instruction_addr(0x400739) == 0x400739
    assert func_main.addr_to_instruction_addr(0x40073A) == 0x400739
    assert func_main.addr_to_instruction_addr(0x40073D) == 0x400739
    assert func_main.addr_to_instruction_addr(0x400742) == 0x400742
    assert func_main.addr_to_instruction_addr(0x400743) == 0x400742


def test_function_instruction_size():

    p = angr.Project(
        os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False
    )
    cfg = p.analyses.CFG()

    func_main = cfg.kb.functions["main"]

    assert func_main.instruction_size(0x40071D) == 1
    assert func_main.instruction_size(0x40071E) == 3
    assert func_main.instruction_size(0x400721) == 4
    assert func_main.instruction_size(0x400725) == 3
    assert func_main.instruction_size(0x400728) == 4
    assert func_main.instruction_size(0x400739) == 5
    assert func_main.instruction_size(0x400742) == 5


if __name__ == "__main__":
    test_function_serialization()
    test_function_definition_application()
    test_function_instruction_addr_from_any_addr()
    test_function_instruction_size()
