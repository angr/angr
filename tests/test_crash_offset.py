import os
import subprocess
import tempfile
import contextlib
import unittest

import angr
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


def crash_offset(program_path, function_call):
    caller, callee, argument_index = function_call

    project = angr.Project(program_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)

    caller = project.kb.functions[caller]
    callee = project.kb.functions[callee]

    argument_register = project.arch.registers[callee.arguments[argument_index].reg_name]
    base_register = project.arch.registers[project.arch.register_names[project.arch.bp_offset]]

    callee_node = cfg.get_any_node(callee.addr)
    caller_node = next(iter(node for node in cfg.get_all_predecessors(callee_node) if node.name == caller.name))
    call_address = list(caller_node.instruction_addrs)[-1]

    rda = project.analyses.ReachingDefinitions(subject=caller, observation_points={("insn", call_address, OP_BEFORE)})
    definitions = rda.get_reaching_definitions_by_insn(call_address, OP_BEFORE)
    argument_value = definitions.registers.load(*argument_register).one_value()
    base_value = definitions.registers.load(*base_register).one_value()

    argument_offset = definitions.get_stack_offset(argument_value)
    base_offset = definitions.get_stack_offset(base_value)

    return base_offset - argument_offset + 8


@contextlib.contextmanager
def compiled_program(prefix_length, buffer_length, suffix_length):
    program_template = """
    #include <stdio.h>
    #include <unistd.h>

    int main()
    {{
        struct {{
            char prefix[{prefix_length}];
            char buffer[{buffer_length}];
            char suffix[{suffix_length}];
        }} stack;
        read(0, stack.buffer, {prefix_length} + {buffer_length} + {suffix_length} + 0x1000);
        return 0;
    }}
    """

    program_code = program_template.format(
        prefix_length=prefix_length, buffer_length=buffer_length, suffix_length=suffix_length
    )

    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        program_path = f.name
        f.write(program_code.encode())

    binary_path = tempfile.mktemp()

    subprocess.run(["gcc", program_path, "-o", binary_path, "-fno-stack-protector"])
    os.remove(program_path)

    try:
        yield binary_path
    finally:
        os.remove(binary_path)


class BufferOverflowTests(unittest.TestCase):
    """
    Testcases for buffer overflow detection
    """

    def setUp(self):
        self.length_combinations = [(10, 20, 30), (5, 25, 35), (15, 15, 35), (20, 10, 40)]

    def test_program_no_segfault(self):
        for prefix_length, buffer_length, suffix_length in self.length_combinations:
            with self.subTest(prefix_length=prefix_length, buffer_length=buffer_length, suffix_length=suffix_length):
                with compiled_program(prefix_length, buffer_length, suffix_length) as binary_path:
                    offset = crash_offset(binary_path, ("main", "read", 1))
                    payload = b"A" * offset
                    assert subprocess.run([binary_path], input=payload, stderr=subprocess.PIPE).returncode == 0

    def test_program_with_segfault(self):
        for prefix_length, buffer_length, suffix_length in self.length_combinations:
            with self.subTest(prefix_length=prefix_length, buffer_length=buffer_length, suffix_length=suffix_length):
                with compiled_program(prefix_length, buffer_length, suffix_length) as binary_path:
                    offset = crash_offset(binary_path, ("main", "read", 1))
                    payload = b"A" * (offset + 1)
                    assert subprocess.run([binary_path], input=payload, stderr=subprocess.PIPE).returncode == -11


if __name__ == "__main__":
    unittest.main()
