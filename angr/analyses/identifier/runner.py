
import random
import logging
import os

import claripy

from ...sim_type import SimTypeFunction, SimTypeInt
from ... import sim_options as so
from ... import SIM_PROCEDURES
from ... import BP_BEFORE, BP_AFTER
from ...storage.file import SimFile
from ...errors import AngrCallableMultistateError, AngrCallableError, AngrError, SimError
from .custom_callable import IdentifierCallable


l = logging.getLogger("identifier.runner")

flag_loc = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../example_flag_page'))
try:
    with open(flag_loc, "rb") as f:
        FLAG_DATA = f.read()
except IOError:
    FLAG_DATA = "A"*0x1000

assert len(FLAG_DATA) == 0x1000


class Runner(object):
    def __init__(self, project, cfg):

        # Lazy import
        try:
            from tracer.simprocedures import FixedOutTransmit, FixedInReceive
            self.FixedOutTransmit = FixedOutTransmit
            self.FixedInReceive = FixedInReceive
        except ImportError:
            l.critical('Cannot import CGC-specific SimProcedures from tracer. If you want to use identifier on CGC '
                       'binaries, please make sure tracer is installed.')
            raise

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

            remove_options = so.simplification | set(so.LAZY_SOLVES) | so.resilience_options | set(so.SUPPORT_FLOATING_POINT)
            add_options = options
            entry_state = self.project.factory.entry_state(
                    add_options=add_options,
                    remove_options=remove_options)

            # map the CGC flag page
            fake_flag_data = entry_state.se.BVV(FLAG_DATA)
            entry_state.memory.store(0x4347c000, fake_flag_data)
            # map the place where I put arguments
            entry_state.memory.mem.map_region(0x2000, 0x10000, 7)

            entry_state.unicorn._register_check_count = 100
            entry_state.unicorn._runs_since_symbolic_data = 100
            entry_state.unicorn._runs_since_unicorn = 100

            # cooldowns
            entry_state.unicorn.cooldown_symbolic_registers = 0
            entry_state.unicorn.cooldown_symbolic_memory = 0
            entry_state.unicorn.cooldown_nonunicorn_blocks = 1
            entry_state.unicorn.max_steps = 10000

            pg = self.project.factory.simgr(entry_state)
            stop_addr = self.project._simos.syscall_from_number(2).addr
            num_steps = 0
            while len(pg.active) > 0:
                if pg.one_active.addr == stop_addr:
                    # execute until receive
                    break

                if len(pg.active) > 1:
                    pp = pg.one_active
                    pg = self.project.factory.simgr(pp)
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
            l.warning("SimError in get recv state %s", e.message)
            return self.project.factory.entry_state()
        except AngrError as e:
            l.warning("AngrError in get recv state %s", e.message)
            return self.project.factory.entry_state()

    def setup_state(self, function, test_data, initial_state=None, concrete_rand=False):
        # FIXME fdwait should do something concrete...
        # FixedInReceive and FixedOutReceive always are applied
        SIM_PROCEDURES['cgc']['transmit'] = self.FixedOutTransmit
        SIM_PROCEDURES['cgc']['receive'] = self.FixedInReceive

        fs = {'/dev/stdin': SimFile(
            "/dev/stdin", "r",
            size=len(test_data.preloaded_stdin))}

        if initial_state is None:
            temp_state = self.project.factory.entry_state(fs=fs)
            if self.base_state is None:
                self.base_state = self._get_recv_state()
            entry_state = self.base_state.copy()
            entry_state.register_plugin("posix",temp_state.posix)
            temp_state.release_plugin("posix")
            entry_state.ip = function.startpoint.addr
        else:
            entry_state = initial_state.copy()

        # set stdin
        entry_state.cgc.input_size = len(test_data.preloaded_stdin)
        if len(test_data.preloaded_stdin) > 0:
            entry_state.posix.files[0].content.store(0, test_data.preloaded_stdin)

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
        entry_state.unicorn.cooldown_symbolic_registers = 0
        entry_state.unicorn.cooldown_symbolic_memory = 0
        entry_state.unicorn.cooldown_nonunicorn_blocks = 1
        entry_state.unicorn.max_steps = 10000

        # syscall hook
        entry_state.inspect.b(
            'syscall',
            BP_BEFORE,
            action=self.syscall_hook
        )

        if concrete_rand:
            entry_state.inspect.b(
                'syscall',
                BP_AFTER,
                action=self.syscall_hook_concrete_rand
            )

        # solver timeout
        entry_state.se._solver.timeout = 500

        return entry_state

    @staticmethod
    def syscall_hook(state):
        # FIXME maybe we need to fix transmit/receive to handle huge vals properly
        # kill path that try to read/write large amounts
        syscall_name = state.inspect.syscall_name
        if syscall_name == "transmit":
            count = state.se.any_int(state.regs.edx)
            if count > 0x10000:
                state.regs.edx = 0
                state.add_constraints(claripy.BoolV(False))
        if syscall_name == "receive":
            count = state.se.any_int(state.regs.edx)
            if count > 0x10000:
                state.regs.edx = 0
                state.add_constraints(claripy.BoolV(False))
        if syscall_name == "random":
            count = state.se.any_int(state.regs.ecx)
            if count > 0x1000:
                state.regs.ecx = 0
                state.add_constraints(claripy.BoolV(False))

    @staticmethod
    def syscall_hook_concrete_rand(state):
        # FIXME maybe we need to fix transmit/receive to handle huge vals properly
        # kill path that try to read/write large amounts
        syscall_name = state.inspect.syscall_name
        if syscall_name == "random":
            count = state.se.any_int(state.regs.ecx)
            if count > 100:
                return
            buf = state.se.any_int(state.regs.ebx)
            for i in range(count):
                a = random.randint(0, 255)
                state.memory.store(buf+i, state.se.BVV(a, 8))

    def get_base_call_state(self, function, test_data, initial_state=None, concrete_rand=False):
        curr_buf_loc = 0x2000
        mapped_input = []
        s = self.setup_state(function, test_data, initial_state, concrete_rand=concrete_rand)

        for i in test_data.input_args:
            if isinstance(i, (str, claripy.ast.BV)):
                s.memory.store(curr_buf_loc, i)
                mapped_input.append(curr_buf_loc)
                curr_buf_loc += max(len(i), 0x1000)
            else:
                if not isinstance(i, (int, long)):
                    raise Exception("Expected int/long got %s", type(i))
                mapped_input.append(i)

        inttype = SimTypeInt(self.project.arch.bits, False)
        func_ty = SimTypeFunction([inttype] * len(mapped_input), inttype)
        cc = self.project.factory.cc(func_ty=func_ty)
        call = IdentifierCallable(self.project, function.startpoint.addr, concrete_only=True,
                        cc=cc, base_state=s, max_steps=test_data.max_steps)
        return call.get_base_state(*mapped_input)

    def test(self, function, test_data, concrete_rand=False, custom_offs=None):
        curr_buf_loc = 0x2000
        mapped_input = []
        s = self.setup_state(function, test_data, concrete_rand=concrete_rand)

        if custom_offs is None:
            for i in test_data.input_args:
                if isinstance(i, str):
                    s.memory.store(curr_buf_loc, i + "\x00")
                    mapped_input.append(curr_buf_loc)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, (int, long)):
                        raise Exception("Expected int/long got %s", type(i))
                    mapped_input.append(i)
        else:
            for i, off in zip(test_data.input_args, custom_offs):
                if isinstance(i, str):
                    s.memory.store(curr_buf_loc, i + "\x00")
                    mapped_input.append(curr_buf_loc+off)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, (int, long)):
                        raise Exception("Expected int/long got %s", type(i))
                    mapped_input.append(i)

        inttype = SimTypeInt(self.project.arch.bits, False)
        func_ty = SimTypeFunction([inttype] * len(mapped_input), inttype)
        cc = self.project.factory.cc(func_ty=func_ty)
        try:
            call = IdentifierCallable(self.project, function.startpoint.addr, concrete_only=True,
                            cc=cc, base_state=s, max_steps=test_data.max_steps)
            result = call(*mapped_input)
            result_state = call.result_state
        except AngrCallableMultistateError as e:
            l.info("multistate error: %s", e.message)
            return False
        except AngrCallableError as e:
            l.info("other callable error: %s", e.message)
            return False

        # check matches
        outputs = []
        for i, out in enumerate(test_data.expected_output_args):
            if isinstance(out, str):
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
            elif result_state.se.symbolic(out):
                l.info("symbolic memory output")
                return False
            else:
                outputs.append(result_state.se.any_str(out))

        if outputs != test_data.expected_output_args:
            # print map(lambda x: x.encode('hex'), [a for a in outputs if a is not None]), map(lambda x: x.encode('hex'), [a for a in test_data.expected_output_args if a is not None])
            l.info("mismatch output")
            return False

        if result_state.se.symbolic(result):
            l.info("result value sybolic")
            return False

        if test_data.expected_return_val is not None and test_data.expected_return_val < 0:
            test_data.expected_return_val &= (2**self.project.arch.bits - 1)
        if test_data.expected_return_val is not None and \
                result_state.se.any_int(result) != test_data.expected_return_val:
            l.info("return val mismatch got %#x, expected %#x", result_state.se.any_int(result), test_data.expected_return_val)
            return False

        if result_state.se.symbolic(result_state.posix.files[1].pos):
            l.info("symbolic stdout pos")
            return False

        if result_state.se.any_int(result_state.posix.files[1].pos) == 0:
            stdout = ""
        else:
            stdout = result_state.posix.files[1].content.load(0, result_state.posix.files[1].pos)
            if stdout.symbolic:
                l.info("symbolic stdout")
                return False
            stdout = result_state.se.any_str(stdout)

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
                if isinstance(i, str):
                    s.memory.store(curr_buf_loc, i + "\x00")
                    mapped_input.append(curr_buf_loc)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, (int, long)):
                        raise Exception("Expected int/long got %s", type(i))
                    mapped_input.append(i)

        else:
            for i, off in zip(test_data.input_args, custom_offs):
                if isinstance(i, str):
                    s.memory.store(curr_buf_loc, i + "\x00")
                    mapped_input.append(curr_buf_loc+off)
                    curr_buf_loc += max(len(i), 0x1000)
                else:
                    if not isinstance(i, (int, long)):
                        raise Exception("Expected int/long got %s", type(i))
                    mapped_input.append(i)

        inttype = SimTypeInt(self.project.arch.bits, False)
        func_ty = SimTypeFunction([inttype] * len(mapped_input), inttype)
        cc = self.project.factory.cc(func_ty=func_ty)
        try:
            call = IdentifierCallable(self.project, function.startpoint.addr, concrete_only=True,
                            cc=cc, base_state=s, max_steps=test_data.max_steps)
            _ = call(*mapped_input)
            result_state = call.result_state
        except AngrCallableMultistateError as e:
            l.info("multistate error: %s", e.message)
            return None
        except AngrCallableError as e:
            l.info("other callable error: %s", e.message)
            return None

        return result_state
