from __future__ import annotations
import random
import logging
import os

import claripy

from ... import sim_options as so
from ... import SIM_LIBRARIES
from ... import BP_BEFORE, BP_AFTER
from ...storage.file import SimFile, SimFileDescriptor
from ...state_plugins import SimSystemPosix
from ...errors import AngrCallableMultistateError, AngrCallableError, AngrError, SimError
from .custom_callable import IdentifierCallable


l = logging.getLogger(name=__name__)

flag_loc = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../example_flag_page"))
try:
    with open(flag_loc, "rb") as f:
        FLAG_DATA = f.read()
except OSError:
    FLAG_DATA = b"A" * 0x1000

assert len(FLAG_DATA) == 0x1000


class Runner:
    def __init__(self, project, cfg):
        # this is kind of fucked up
        project.simos.syscall_library.update(SIM_LIBRARIES["cgcabi_tracer"])

        self.project = project
        self.cfg = cfg
        self.base_state = None

    def _get_recv_state(self):
        try:
            options = set()
            options.add(so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
            options.add(so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
            options.add(so.TRACK_MEMORY_MAPPING)
            options.add(so.AVOID_MULTIVALUED_READS)
            options.add(so.AVOID_MULTIVALUED_WRITES)

            # try to enable unicorn, continue if it doesn't exist
            options.add(so.UNICORN)
            l.info("unicorn tracing enabled")

            remove_options = so.simplification | {so.LAZY_SOLVES} | so.resilience | {so.SUPPORT_FLOATING_POINT}
            add_options = options
            entry_state = self.project.factory.entry_state(add_options=add_options, remove_options=remove_options)

            # map the CGC flag page
            fake_flag_data = claripy.BVV(FLAG_DATA)
            entry_state.memory.store(0x4347C000, fake_flag_data)
            # map the place where I put arguments
            entry_state.memory.map_region(0x2000, 0x10000, 7)

            entry_state.unicorn._register_check_count = 100
            entry_state.unicorn._runs_since_symbolic_data = 100
            entry_state.unicorn._runs_since_unicorn = 100

            # cooldowns
            entry_state.unicorn.cooldown_symbolic_stop = 2
            entry_state.unicorn.cooldown_unsupported_stop = 2
            entry_state.unicorn.cooldown_nonunicorn_blocks = 1
            entry_state.unicorn.max_steps = 10000

            pg = self.project.factory.simulation_manager(entry_state)
            stop_addr = self.project.simos.syscall_from_number(2).addr
            num_steps = 0
            while len(pg.active) > 0:
                if pg.one_active.addr == stop_addr:
                    # execute until receive
                    break

                if len(pg.active) > 1:
                    pp = pg.one_active
                    pg = self.project.factory.simulation_manager(pp)
                pg.step()
                num_steps += 1
                if num_steps > 50:
                    break
            if len(pg.active) > 0:
                out_state = pg.one_active
            elif len(pg.deadended) > 0:
                out_state = pg.deadended[0]
            else:
                return self.project.factory.entry_state()
            out_state.scratch.clear()
            out_state.history.jumpkind = "Ijk_Boring"
            return out_state
        except SimError as e:
            l.warning("SimError in get recv state %s", e)
            return self.project.factory.entry_state()
        except AngrError as e:
            l.warning("AngrError in get recv state %s", e)
            return self.project.factory.entry_state()

    def setup_state(self, function, test_data, initial_state=None, concrete_rand=False):
        # FIXME fdwait should do something concrete...

        if initial_state is None:
            if self.base_state is None:
                self.base_state = self._get_recv_state()
            entry_state = self.base_state.copy()
        else:
            entry_state = initial_state.copy()

        stdin = SimFile("stdin", content=test_data.preloaded_stdin)
        stdout = SimFile("stdout")
        stderr = SimFile("stderr")
        fd = {0: SimFileDescriptor(stdin, 0), 1: SimFileDescriptor(stdout, 0), 2: SimFileDescriptor(stderr, 0)}
        entry_state.register_plugin("posix", SimSystemPosix(stdin=stdin, stdout=stdout, stderr=stderr, fd=fd))

        entry_state.options.add(so.STRICT_PAGE_ACCESS)

        # make sure unicorn will run
        for k in dir(entry_state.regs):
            r = getattr(entry_state.regs, k)
            if r.symbolic:
                setattr(entry_state.regs, k, 0)

        entry_state.unicorn._register_check_count = 100
        entry_state.unicorn._runs_since_symbolic_data = 100
        entry_state.unicorn._runs_since_unicorn = 100

        # cooldowns
        entry_state.unicorn.cooldown_symbolic_stop = 2
        entry_state.unicorn.cooldown_unsupported_stop = 2
        entry_state.unicorn.cooldown_nonunicorn_blocks = 1
        entry_state.unicorn.max_steps = 10000

        # syscall hook
        entry_state.inspect.b("syscall", BP_BEFORE, action=self.syscall_hook)

        if concrete_rand:
            entry_state.inspect.b("syscall", BP_AFTER, action=self.syscall_hook_concrete_rand)

        # solver timeout
        entry_state.solver._solver.timeout = 500

        return entry_state

    @staticmethod
    def syscall_hook(state):
        # FIXME maybe we need to fix transmit/receive to handle huge vals properly
        # kill path that try to read/write large amounts
        syscall_name = state.inspect.syscall_name
        if syscall_name == "transmit":
            count = state.solver.eval(state.regs.edx)
            if count > 0x10000:
                state.regs.edx = 0
                state.add_constraints(claripy.BoolV(False))
        if syscall_name == "receive":
            count = state.solver.eval(state.regs.edx)
            if count > 0x10000:
                state.regs.edx = 0
                state.add_constraints(claripy.BoolV(False))
        if syscall_name == "random":
            count = state.solver.eval(state.regs.ecx)
            if count > 0x1000:
                state.regs.ecx = 0
                state.add_constraints(claripy.BoolV(False))

    @staticmethod
    def syscall_hook_concrete_rand(state):
        # FIXME maybe we need to fix transmit/receive to handle huge vals properly
        # kill path that try to read/write large amounts
        syscall_name = state.inspect.syscall_name
        if syscall_name == "random":
            count = state.solver.eval(state.regs.ecx)
            if count > 100:
                return
            buf = state.solver.eval(state.regs.ebx)
            for i in range(count):
                a = random.randint(0, 255)
                state.memory.store(buf + i, claripy.BVV(a, 8))

    def get_base_call_state(self, function, test_data, initial_state=None, concrete_rand=False):
        curr_buf_loc = 0x2000
        mapped_input = []
        s = self.setup_state(function, test_data, initial_state, concrete_rand=concrete_rand)

        for i in test_data.input_args:
            if isinstance(i, (bytes, claripy.ast.BV)):
                s.memory.store(curr_buf_loc, i)
                mapped_input.append(curr_buf_loc)
                curr_buf_loc += max(len(i), 0x1000)
            else:
                if not isinstance(i, int):
                    raise Exception(f"Expected int/bytes got {type(i)}")
                mapped_input.append(i)

        cc = self.project.factory.cc()
        call = IdentifierCallable(
            self.project,
            function.startpoint.addr,
            concrete_only=True,
            cc=cc,
            base_state=s,
            max_steps=test_data.max_steps,
        )
        return call.get_base_state(*mapped_input)

    def test(self, function, test_data, concrete_rand=False, custom_offs=None):
        curr_buf_loc = 0x2000
        mapped_input = []
        s = self.setup_state(function, test_data, concrete_rand=concrete_rand)

        if custom_offs is None:
            for i in test_data.input_args:
                if isinstance(i, bytes):
                    s.memory.store(curr_buf_loc, i + b"\x00")
                    mapped_input.append(curr_buf_loc)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, int):
                        raise Exception(f"Expected int/str got {type(i)}")
                    mapped_input.append(i)
        else:
            for i, off in zip(test_data.input_args, custom_offs):
                if isinstance(i, bytes):
                    s.memory.store(curr_buf_loc, i + b"\x00")
                    mapped_input.append(curr_buf_loc + off)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, int):
                        raise Exception(f"Expected int/str got {type(i)}")
                    mapped_input.append(i)

        cc = self.project.factory.cc()
        try:
            call = IdentifierCallable(
                self.project,
                function.startpoint.addr,
                concrete_only=True,
                cc=cc,
                base_state=s,
                max_steps=test_data.max_steps,
            )
            result = call(*mapped_input)
            result_state = call.result_state
        except AngrCallableMultistateError as e:
            l.info("multistate error: %s", e)
            return False
        except AngrCallableError as e:
            l.info("other callable error: %s", e)
            return False

        # check matches
        outputs = []
        for i, out in enumerate(test_data.expected_output_args):
            if isinstance(out, bytes):
                if len(out) == 0:
                    raise Exception("len 0 out")
                outputs.append(result_state.memory.load(mapped_input[i], len(out)))
            else:
                outputs.append(None)

        tmp_outputs = outputs
        outputs = []
        for out in tmp_outputs:
            if out is None:
                outputs.append(None)
            elif result_state.solver.symbolic(out):
                l.info("symbolic memory output")
                return False
            else:
                outputs.append(result_state.solver.eval(out, cast_to=bytes))

        if outputs != test_data.expected_output_args:
            l.info("mismatch output")
            return False

        if result_state.solver.symbolic(result):
            l.info("result value sybolic")
            return False

        if test_data.expected_return_val is not None and test_data.expected_return_val < 0:
            test_data.expected_return_val &= 2**self.project.arch.bits - 1
        if (
            test_data.expected_return_val is not None
            and result_state.solver.eval(result) != test_data.expected_return_val
        ):
            l.info(
                "return val mismatch got %#x, expected %#x",
                result_state.solver.eval(result),
                test_data.expected_return_val,
            )
            return False

        if result_state.solver.symbolic(result_state.posix.stdout.size):
            l.info("symbolic stdout pos")
            return False

        if result_state.solver.eval(result_state.posix.stdout.size) == 0:
            stdout = ""
        else:
            stdout = result_state.posix.stdout.load(0, result_state.posix.stdout.size)
            if stdout.symbolic:
                l.info("symbolic stdout")
                return False
            stdout = result_state.solver.eval(stdout, cast_to=bytes)

        if stdout != test_data.expected_stdout:
            l.info("mismatch stdout")
            return False

        return True

    def get_out_state(self, function, test_data, initial_state=None, concrete_rand=False, custom_offs=None):
        curr_buf_loc = 0x2000
        mapped_input = []
        s = self.setup_state(function, test_data, initial_state, concrete_rand=concrete_rand)

        if custom_offs is None:
            for i in test_data.input_args:
                if isinstance(i, bytes):
                    s.memory.store(curr_buf_loc, i + b"\x00")
                    mapped_input.append(curr_buf_loc)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, int):
                        raise Exception(f"Expected int/bytes got {type(i)}")
                    mapped_input.append(i)

        else:
            for i, off in zip(test_data.input_args, custom_offs):
                if isinstance(i, bytes):
                    s.memory.store(curr_buf_loc, i + b"\x00")
                    mapped_input.append(curr_buf_loc + off)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, int):
                        raise Exception(f"Expected int/bytes got {type(i)}")
                    mapped_input.append(i)

        cc = self.project.factory.cc()
        try:
            call = IdentifierCallable(
                self.project,
                function.startpoint.addr,
                concrete_only=True,
                cc=cc,
                base_state=s,
                max_steps=test_data.max_steps,
            )
            _ = call(*mapped_input)
            result_state = call.result_state
        except AngrCallableMultistateError as e:
            l.info("multistate error: %s", e)
            return None
        except AngrCallableError as e:
            l.info("other callable error: %s", e)
            return None

        return result_state
