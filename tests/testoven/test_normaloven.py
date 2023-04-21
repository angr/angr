import os
import struct
from typing import TYPE_CHECKING#angr/analyses/state_graph_recovery

import networkx
import sys
import json
import claripy
import angr
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_MEMORY
from angr.analyses.state_graph_recovery import MinDelayBaseRule, RuleVerifier, IllegalNodeBaseRule
from angr.analyses.state_graph_recovery.apis import generate_patch, apply_patch, apply_patch_on_state, EditDataPatch

if TYPE_CHECKING:
    import networkx

import time

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')

class delay(angr.SimProcedure):
    def run(self, usec):
        # time_addr = 0x200001d8
        prev = self.state.memory.load(time_addr, 4, endness=self.arch.memory_endness)
        self.state.memory.store(time_addr, prev + usec, endness=self.arch.memory_endness)
        # print(self.state.solver.eval(self.state.memory.load(0x200002fc, 4, endness=self.arch.memory_endness)))
        return None

# def _hook_py_extensions(proj, cfg):
#     proj.hook(cfg.kb.functions['delayMicroseconds'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
#     proj.hook(cfg.kb.functions['delay'].addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

class readThermo(angr.SimProcedure):
    def run(self, this, unit):
        prev_temp = self.state.memory.load(temp_addr, 8, endness=self.arch.memory_endness)
        self.state.regs._r1 = prev_temp[63:32]
        self.state.regs._r0 = prev_temp[31:0]
        # import ipdb; ipdb.set_trace()
        return None

class doubleAdd(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("ADD")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = (var1 + var2).raw_to_bv()
        self.state.regs._r0 = result[31:0]
        self.state.regs._r1 = result[63:32]

        return None


class doubleSub(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("SUB")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = (var1 - var2).raw_to_bv()
        self.state.regs._r0 = result[31:0]
        self.state.regs._r1 = result[63:32]

        return None


class doubleMul(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("MUL")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = (var1 * var2).raw_to_bv()
        self.state.regs._r0 = result[31:0]
        self.state.regs._r1 = result[63:32]

        return None


class doubleDiv(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("DIV")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = (var1 / var2).raw_to_bv()
        self.state.regs._r0 = result[31:0]
        self.state.regs._r1 = result[63:32]

        return None


class doubleCMPEQ(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("CMPEQ")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = var1 == var2

        self.state.regs._r0 = claripy.If(result, claripy.BVV(1, 32), claripy.BVV(0, 32))
        return None


class doubleCMPLE(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("CMPLE")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = var1 <= var2

        self.state.regs._r0 = claripy.If(result, claripy.BVV(1, 32), claripy.BVV(0, 32))
        return None


class doubleCMPLT(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("CMPLT")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = var1 < var2

        self.state.regs._r0 = claripy.If(result, claripy.BVV(1, 32), claripy.BVV(0, 32))
        # self.state.solver.eval(result)
        return None


class doubleCMPGE(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("CMPGE")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = var1 >= var2
        self.state.regs._r0 = claripy.If(result, claripy.BVV(1, 32), claripy.BVV(0, 32))
        return None


class doubleCMPGT(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        # print("CMPGT")
        # import ipdb; ipdb.set_trace()
        a1 = self.state.regs._r0
        a2 = self.state.regs._r1
        a3 = self.state.regs._r2
        a4 = self.state.regs._r3
        var1 = a2.concat(a1).raw_to_fp()
        var2 = a4.concat(a3).raw_to_fp()
        result = var1 > var2
        self.state.regs._r0 = claripy.If(result, claripy.BVV(1, 32), claripy.BVV(0, 32))
        return None


def switch_on(state):
    # switch on
    # base_addr = int(data['variable_base_addr'], 16)
    # switch = next(x for x in data['variables'] if x['name'] == "SWITCH_BUTTON")
    # import ipdb; ipdb.set_trace()
    prev = state.memory.load(0x200002ec, 4, endness=state.arch.memory_endness)
    state.memory.store(0x200002ec, prev + 50, endness=state.arch.memory_endness)
    # switchstatus_addr = 0x20000208
    # debouncestate_addr = 0x20000140
    # switch_value_addr = base_addr + int(switch['address'], 16
    state.memory.store(0x41004420, claripy.BVV(0x80000, 32), endness='Iend_LE')
    # state.memory.store(debouncestate_addr, claripy.BVV(0, 8), endness=state.arch.memory_endness)


def test_normaloven():
    binary_path = '/home/bonnie/PLCRCA/normal_oven/arduino_build_normaloven/normal_oven.ino.elf'
    # variable_path = '/home/bonnie/PLCRCA/normal_oven/arduino_build_normaloven/normaloven.json'

    # binary_path = sys.argv[1]
    # variable_path = sys.argv[2]

    start_time = time.time()

    proj = angr.Project(binary_path, auto_load_libs=False)

    with open(variable_path) as f:
        data = json.load(f)

    global time_addr
    global temp_addr
    base_addr = int(data['variable_base_addr'], 16)
    time_addr = int(data['time_addr'], 16)
    temp_addr = int(data['temp_addr'], 16)

    cfg = proj.analyses.CFG()
    # _hook_py_extensions(proj, cfg)
    nnode = len(list(cfg.kb.functions['loop'].blocks))
    print(f"number of blocks: {nnode}")
    # proj.hook_symbol('delayMicroseconds', delay())
    proj.hook_symbol('delay', delay())
    proj.hook_symbol('_ZN8MAX3185516readThermocoupleE6unit_t', readThermo())
    # fp_cc = proj.factory.cc_from_arg_kinds((True, True, True, True), ret_fp=True)
    proj.hook_symbol('__aeabi_dadd', doubleAdd())
    proj.hook_symbol('__aeabi_dsub', doubleSub())
    proj.hook_symbol('__aeabi_dmul', doubleMul())
    proj.hook_symbol('__aeabi_ddiv', doubleDiv())
    proj.hook_symbol('__aeabi_dcmpeq', doubleCMPEQ())
    proj.hook_symbol('__aeabi_dcmple', doubleCMPLE())
    proj.hook_symbol('__aeabi_dcmplt', doubleCMPLT())
    proj.hook_symbol('__aeabi_dcmpge', doubleCMPGE())
    proj.hook_symbol('__aeabi_dcmpgt', doubleCMPGT())

    # run the state initializer
    func_loop = proj.kb.functions["loop"]
    blank = proj.factory.blank_state(addr=0x28ef, add_options={ZERO_FILL_UNCONSTRAINED_MEMORY})
    blank.memory.store(0x4000080c, claripy.BVV(0xd2, 32), endness=proj.arch.memory_endness)
    # blank.memory.store(0x42004018, claripy.BVV(1, 32), endness=proj.arch.memory_endness)
    # blank.memory.store(0x200001f8, claripy.BVV(0, 8), endness=proj.arch.memory_endness)
    simgr = proj.factory.simgr(blank)

    while simgr.active:

        # print(simgr.active)

        state = simgr.active[0]
        # print(state.memory.load(0x20000200, 1))
        # tickcount = state.memory.load(time_addr, size=4, endness=proj.arch.memory_endness)

        # jumpkind = state.history.jumpkind
        # print("state %d 0x%x %s" % (i, eachstate.addr, jumpkind))
        # print(tickcount)
        if state.addr == 0x21b9:
            print("IN LOOP !!!!!!!!!!!!!!")
            break

        simgr.step()

    # import ipdb; ipdb.set_trace()
    initial_state = simgr.active[0]
    print(initial_state)

    init_time = time.time()
    print("------------init time: %s ----------" % (init_time - start_time))

    # define abstract fields
    fields_desc = {
        'reflowState': (0x200000e8, "int", 1),
        'reflowStatus': (0x200000e9, "int", 1),
        'input': (0x200000d0, "double", 8)}


    fields = angr.analyses.state_graph_recovery.AbstractStateFields(fields_desc)
    func = cfg.kb.functions['loop']
    sgr = proj.analyses.StateGraphRecovery(func, fields, "arduino", time_addr, temp_addr, init_state=initial_state)
    # sgr = proj.analyses.StateGraphRecovery(func, fields, time_addr, temp_addr, init_state=initial_state)
    # state_graph = sgr.state_graph
    sgr_time = time.time()
    print("------------sgr time: %s ----------" % (sgr_time - init_time))

    # output the graph to a dot file
    from networkx.drawing.nx_agraph import write_dot
    write_dot(sgr.state_graph, "normaloven.dot")

    import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_normaloven()
