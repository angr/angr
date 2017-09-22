import archinfo
import logging

from . import ExplorationTechnique

from ..errors import AngrExplorationTechniqueError
from .. import sim_options
from .. import BP_AFTER

from ..engines.vex.ccall import *

l = logging.getLogger('angr.exploration_techniques.arm_system_explorer')

# See ARMv7-M reference manual B1.5.2)
exception_numbers = {'Reset'        : 1,
                     'NMI'          : 2,
                     'HardFault'    : 3,
                     'MemManage'    : 4,
                     'BusFault'     : 5,
                     'UsageFault'   : 6,
                     'SVCall'       : 11,
                     'DebugMonitor' : 12,
                     'PendSV'       : 14,
                     'SysTick'      : 15,
}

memory_mapped_regs = {'NVIC'        : 0xE000E100,
                      'NVIC_IPR0'   : 0xE000E400,
                      'VTOR'        : 0xE000ED08,
                      'AIRCR'       : 0xE000ED0C,
                      'CCR'         : 0xE000ED14,
}

class AngrARMSystemExplorerError(AngrExplorationTechniqueError):
    def __str__(self):
        return "<OtiegnqwvkARMSystemExplorerError %s>" % self.message

class ARMSystemExplorer(ExplorationTechnique):
    """
    An exploration technique for (temporarily?) executing ARM system
    instructions.
    """

    def __init__(self, **kwargs):
        """
        Please use kwargs to pass in hardware initialization parameters (in
        other words, to emulate the processor reset with the provided parameters).
        Currently only the processor mode and the Vector Table Offset Register
        (VTOR) are needed.

        If no specific parameter is provided, setup() will emulate the reset
        behavior as in TakeReset() pseudocode described by ARMv7-M reference
        manual.

        If there are too many differences for other ARM architectures,
        we can think about subclassing (ARM hardware is known for being much
        more widely varying than x86 hardware).
        """

        super(ARMSystemExplorer, self).__init__()

        self._current_mode = kwargs.get('mode', 'Thread')

        self._vtor = kwargs.get('vtor', 0)
        self._vector_table = self._vtor & 0x00FFFF80

        self._frame_ptr = 'main'

        ext_ints = kwargs.get('external_interrupts', [])
        for i, interrupt in enumerate(ext_ints):
            exception_numbers[interrupt] = i + 16

    def setup(self, simgr):
        if len(simgr.active) != 1:
            msg = 'ARM system execution should begin at the entry point of the '
            msg += 'in order to initialize everything correctly.'
            raise AngrARMSystemExplorerError(msg)

        # The real hardware initialization starts here:
        self._take_reset(simgr.active[0])

    def step(self, simgr, stash, **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        if simgr.errored:
            print simgr.errored[0]
            s = simgr.errored[0].state
            # give it a size, otherwise VEX will set the size to 0 and capstone
            # will fail.
            b = s.block(size=4).capstone
            b.pp()
            insn = b.insns[0]
            getattr(self, '_hook_' + str(insn.mnemonic[:3]))(state=s, insn=insn)
            simgr.errored.pop(0)
            simgr.stashes = simgr._make_stashes_dict(**{'active':[s]})
        return simgr

    #
    # Hooks
    #

    @staticmethod
    def _hook_svc(state, insn):
        """
        This emulates the SVC instruction.

        :param state: the current state.
        :param insn : the SVC instruction.

        :type state : angr.sim_state.SimState
        :type insn  : angr.block.CapstoneInsn
        """

        state._ip += insn.size

        if not ARMSystemExplorer._condition_passed(state, insn):
            return

        self._exception_entry(state, exception='SVCall', ret_addr=state._ip)

    @staticmethod
    def _hook_cps(state, insn):
        """
        This emulates the CPS instruction.

        :param state: the current state.
        :param insn : the CPS instruction.

        :type state : angr.sim_state.SimState
        :type insn  : angr.block.CapstoneInsn
        """

        state._ip += insn.size

        if not ARMSystemExplorer._condition_passed(state, insn):
            return

    @staticmethod
    def _hook_msr(state, insn):
        """
        This emulates the MSR instruction.

        :param state: the current state.
        :param insn : the MSR instruction.

        :type state : angr.sim_state.SimState
        :type insn  : angr.block.CapstoneInsn
        """

        state._ip += insn.size

        if not ARMSystemExplorer._condition_passed(state, insn):
            return

        rn, sysm = [str(i).lower() for i in insn.op_str.split(', ')]
        val = 0
        privileged = ARMSystemExplorer._current_mode_is_privileged(state)

    @staticmethod
    def _hook_mrs(state, insn):
        """
        This emulates the MRS instruction.

        :param state: the current state.
        :param insn : the MRS instruction.

        :type state : angr.sim_state.SimState
        :type insn  : angr.block.CapstoneInsn
        """

        state._ip += insn.size

        if not ARMSystemExplorer._condition_passed(state, insn):
            return

        rd, sysm = [str(i).lower() for i in insn.op_str.split(', ')]
        val = 0
        privileged = ARMSystemExplorer._current_mode_is_privileged(state)

        # xPSR
        if sysm.endswith('psr'):
            if 'i' in sysm and privileged: # Exception number in Handler mode
                val |= state.regs.xpsr & 0x1FF
            if 'a' in sysm: # Flags
                val |= _get_flags(state)

        elif privileged:
            if sysm == 'basepri_mask':
                reg = state.regs.basepri
            else:
                reg = state.regs.__getattr__(sysm)

            # MSP/PSP
            if sysm.endswith('sp'):
                val = reg
            # PRIMASK/FAULTMASK
            elif sysm.endswith('mask'):
                val |= reg & 1
            # BASEPRI/BASEPRI_MAX
            elif sysm == 'basepri':
                val |= reg & 0xFF
            # CONTROL
            else:
                val |= reg & 3

        state.regs.__setattr__(rd, val)

    #
    # Helper methods
    #

    @staticmethod
    def _condition_passed(state, insn):
        """
        This uses the condition specifier and the condition flags to determine
        whether the instruction must be executed.

        :param state: the current state.
        :param insn : the current instruction.

        :type state : angr.sim_state.SimState
        :type insn  : angr.block.CapstoneInsn

        :returns    : True if the current instruction must be executed.

        :rtype      : bool
        """

        if state.thumb:
            # This part tries to emulate the STANDARD PREAMBLE in vex/priv/guest_arm_toIR.c
            cond_n_op = ((state.regs.itstate & 0xF0) ^ 0xE0) | state.regs.cc_op
        else:
            # Take out the condition field from the instruction ([31:28])
            cond_n_op = (insn.bytes[-1] & 0xF0) | state.regs.cc_op

        cond_t = armg_calculate_condition(state,
                                          cond_n_op,
                                          state.regs.cc_dep1,
                                          state.regs.cc_dep2,
                                          state.regs.cc_ndep)[0]
        return bool(state.se.eval(cond_t))

    @staticmethod
    def _lookup_sp(state):
        """
        The SP that is used by instructions which explicitly reference the SP
        is selected according to this method.

        :param state: the current state.

        :type state : angr.sim_state.SimState

        :returns    : MSP or PSP.

        :rtype      : str
        """

        if state.regs.control & 2:
            if self._current_mode == 'Thread':
                return 'psp'
            else:
                raise AngrARMSystemExplorerError('CONTROL[1] set in Handler mode is undefined.')
        return 'msp'

    def _current_mode_is_privileged(self, state):
        """
        This determines whether the current software execution is privileged.

        :param state: the current state.

        :type state : angr.sim_state.SimState

        :returns    : True if the current execution is privileged.

        :rtype      : bool
        """

        return self._current_mode == 'Handler' or not state.se.eval(state.regs.control) & 1

    def _take_reset(self, state):
        """
        Actions performed on hardware reset (aka hardware initialization).

        :param state: the entry state.

        :type state : angr.sim_state.SimState
        """

        state.regs.sp = state.memory.load(self._vector_table, size=4) & 0xFFFFFFFC
        state.regs.lr = state.se.BVV(0xFFFFFFFF, state.arch.bits)

        state.inspect.b('mem_write',
                        when=angr.BP_AFTER,
                        condition=lambda s: s.inspect.mem_write_address in memory_mapped_regs.values(),
                        action=self._write_memory_mapped_regs)

        # Program should start at reset service routine.
        tmp = state.memory.load(self._vector_table + 4, size=4)
        assert state._ip == tmp & 0xFFFFFFFE

        assert state.thumb == bool(tmp & 1)

        # Exception number cleared (IPSR[8:0] = 0).
        state.regs.xpsr &= 0x1FF

        # T (EPSR.T) bit set.
        state.regs.xpsr |= (1 << 24)

        # IT/ICI bits cleared (EPSR.IT[7:0] = 0).
        state.regs.xpsr &= 0xF3FF03F

        # Priority mask cleared.
        state.regs.primask &= 0xFFFFFFFE

        # Fault mask cleared.
        state.regs.faultmask &= 0xFFFFFFFE

        # Base priority disabled.
        state.regs.basepri &= 0xFFFFFF00

        # Current stack is Main, Thread is privileged.
        state.regs.control &= 0xFFFFFFFC
        state.regs.msp = state.regs.sp

        # Priorities
        # PRIGROUP field is cleared on reset.
        data = 0xFA050000
        if state.arch.memory_endness == archinfo.arch.Endness.BE:
            data |= (1 << 15)
        state.memory.store(memory_mapped_regs['AIRCR'], data, size=4)

        # Reset, NMI and HardFault execute at priorities of -3, -2 and -1 respectively.
        state.memory.store(memory_mapped_regs['NVIC_IPR0'], 0xFDFEFF00, size=4)

        # All other exception priorities are cleared on reset.
        # Let's make size multiples of 4 bytes.
        n = max(exception_numbers.values()) - 4
        size = (n / 4 + int(n % 4 != 0)) * 4
        addr = memory_mapped_regs['NVIC_IPR0'] + 32
        state.memory.store(addr, 0, size=size)

        # Stack alignment is undefined, let's clear it on reset.
        state.memory.store(memory_mapped_regs['CCR'], 0, size=4)

    def _exception_entry(self, state, exception, ret_addr):
        """
        Actions performed on exception entrance.

        :param state    : the entry state.
        :param exception: the exception.
        :param ret_addr : the return address from exception.

        :type state     : angr.sim_state.SimState
        :type exception : str
        :type ret_addr  : int
        """

        self._push_stack(state, ret_addr)
        self._exception_taken(state, exception)

    def _push_stack(self, state, ret_addr):
        """
        This performs stack alignment and saves data to the stack.

        :param state    : the entry state.
        :param ret_addr : the return address from exception.

        :type state     : angr.sim_state.SimState
        :type ret_addr  : int
        """

        sp_name = _lookup_sp(state)
        sp = state.regs.__getattr__(sp_name)

        ccr_stkalign = state.memory.load(memory_mapped_regs['CCR'], size=4)
        ccr_stkalign = (ccr_stkalign & (1 << 9)) >> 9

        if state.se.eval(((sp & (1 << 2)) >> 2) & ccr_stkalign):
            xpsr = state.regs.xpsr | (1 << 9)
        else:
            xpsr = state.regs.xpsr & ~(1 << 9)

        sp = (sp - 0x20) & ~(ccr_stkalign << 2)

        state.memory.store(sp       , state.regs.r0 , size=4)
        state.memory.store(sp + 0x4 , state.regs.r1 , size=4)
        state.memory.store(sp + 0x8 , state.regs.r2 , size=4)
        state.memory.store(sp + 0xC , state.regs.r3 , size=4)
        state.memory.store(sp + 0x10, state.regs.r12, size=4)
        state.memory.store(sp + 0x14, state.regs.lr , size=4)
        state.memory.store(sp + 0x18, ret_addr      , size=4)
        state.memory.store(sp + 0x1C, xpsr          , size=4)

        state.regs.__setattr__(sp_name, sp)
        state.regs.sp = sp
        self._frame_ptr = sp_name

        if self._current_mode == 'Handler':
            state.regs.lr = 0xFFFFFFF1
        elif state.regs.control & 2 == 0:
            state.regs.lr = 0xFFFFFFF9
        else:
            state.regs.lr = 0xFFFFFFFD

    def _exception_taken(state, exception):
        """
        Actions performed on exception entrance.

        :param state    : the entry state.
        :param exception: the exception.

        :type state     : angr.sim_state.SimState
        :type exception : str
        """

        number = exception_numbers[exception]
        tmp = state.memory.load(self._vector_table + 4 * number, size=4)
        state._ip = tmp & 0xFFFFFFFE
        state.regs.xpsr &= 0xFFFFFE00 # clear IPSR[8:0]
        state.regs.xpsr |= (number & 0x1FF) # set IPSR to the exception number

        tmp &= 1
        if tmp:
            state.regs.xpsr |= (1 << 24)
        else:
            state.regs.xpsr &= ~(1 << 24)

        state.regs.xpsr &= 0xF3FF03F

        state.regs.control &= ~2

    def _exception_return(self, state):
        """
        Actions performed on return from exception. Currently, we do not
        support nested and pending exceptions. If someone ever needs it, I can
        implement later.

        :param state    : the entry state.
        :param exception: the exception.

        :type state     : angr.sim_state.SimState
        :type exception : str
        """

        assert self._current_mode == 'Handler'

        exc_return = state.se.eval(self._ip) & 0xFFFFFFF
        sp_name = 'msp'

        # Return to Handler mode, exception return gets state from MSP, on return execution uses MSP.
        if exc_return & 0xF == 1:
            self._current_mode = 'Handler'
            state.regs.control &= ~2
        # Return to Thread mode, exception return gets state from MSP, on return execution uses MSP.
        elif exc_return & 0xF == 9:
            self._current_mode = 'Thread'
            state.regs.control &= ~2
        # Return to Thread mode, exception return gets state from PSP, on return execution uses PSP.
        elif exc_return & 0xF == 0xD:
            self._current_mode = 'Thread'
            state.regs.control |= 2
        else:
            raise AngrARMSystemExplorerError('Illegal EXC_RETURN')

        self._pop_stack(state, sp_name)

    #
    # Inspect methods
    #

    def _write_memory_mapped_regs(self, state):
        """
        This is what should be done when the program writes to different memory-mapped registers.
        """

        if ARMSystemExplorer._current_mode_is_privileged(state):
            addr = state.inspect.mem_write_addr
            if addr == memory_mapped_regs['VTOR']:
                self._vtor = state.se.eval(state.inspect.mem_write_expr)
                self._vector_table = self._vtor & 0x00FFFF80
