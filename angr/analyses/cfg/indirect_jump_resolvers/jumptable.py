
import logging
from collections import defaultdict

import pyvex

from ....errors import AngrError, SimError
from ....blade import Blade
from ....annocfg import AnnotatedCFG
from .... import sim_options as o
from .... import BP, BP_BEFORE
from ....exploration_techniques.slicecutor import Slicecutor
from ....exploration_techniques.explorer import Explorer
from .resolver import IndirectJumpResolver


l = logging.getLogger("angr.analyses.cfg.indirect_jump_resolvers.jumptable")


class UninitReadMeta(object):
    uninit_read_base = 0xc000000


class JumpTableResolver(IndirectJumpResolver):
    """
    A generic jump table resolver.

    This is a fast jump table resolution. For performance concerns, we made the following assumptions:
        - The final jump target comes from the memory.
        - The final jump target must be directly read out of the memory, without any further modification or altering.

    """
    def __init__(self, project):
        super(JumpTableResolver, self).__init__(project, timeless=False)

        self._bss_regions = None
        # the maximum number of resolved targets. Will be initialized from CFG.
        self._max_targets = None

        self._find_bss_region()

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        # TODO:

        if jumpkind != "Ijk_Boring":
            # Currently we only support boring ones
            return False

        return True

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        """
        Resolves jump tables.

        :param cfg: A CFG instance.
        :param int addr: IRSB address.
        :param int func_addr: The function address.
        :param pyvex.IRSB block: The IRSB.
        :return: A bool indicating whether the indirect jump is resolved successfully, and a list of resolved targets
        :rtype: tuple
        """

        project = self.project  # short-hand
        self._max_targets = cfg._indirect_jump_target_limit

        # Perform a backward slicing from the jump target
        b = Blade(cfg.graph, addr, -1,
            cfg=cfg, project=project,
            ignore_sp=False, ignore_bp=False,
            max_level=3, base_state=self.base_state)

        stmt_loc = (addr, 'default')
        if stmt_loc not in b.slice:
            return False, None

        load_stmt_loc, load_stmt = None, None
        stmts_to_remove = [stmt_loc]
        while True:
            preds = list(b.slice.predecessors(stmt_loc))
            if len(preds) != 1:
                return False, None
            block_addr, stmt_idx = stmt_loc = preds[0]
            block = project.factory.block(block_addr, backup_state=self.base_state).vex
            stmt = block.statements[stmt_idx]
            if isinstance(stmt, (pyvex.IRStmt.WrTmp, pyvex.IRStmt.Put)):
                if isinstance(stmt.data, (pyvex.IRExpr.Get, pyvex.IRExpr.RdTmp)):
                    # data transferring
                    stmts_to_remove.append(stmt_loc)
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.ITE):
                    # data transferring
                    #   t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                    # > t44 = ITE(t43,t16,0x0000c844)
                    stmts_to_remove.append(stmt_loc)
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.Load):
                    # Got it!
                    load_stmt, load_stmt_loc = stmt, stmt_loc
                    stmts_to_remove.append(stmt_loc)
            elif isinstance(stmt, pyvex.IRStmt.LoadG):
                # Got it!
                #
                # this is how an ARM jump table is translated to VEX
                # > t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                load_stmt, load_stmt_loc = stmt, stmt_loc
                stmts_to_remove.append(stmt_loc)

            break

        if load_stmt_loc is None:
            # the load statement is not found
            return False, None

        # skip all statements before the load statement
        b.slice.remove_nodes_from(stmts_to_remove)

        # Debugging output
        if l.level == logging.DEBUG:
            self._dbg_repr_slice(b)

        # Get all sources
        sources = [ n_ for n_ in b.slice.nodes() if b.slice.in_degree(n_) == 0 ]

        # Create the annotated CFG
        annotatedcfg = AnnotatedCFG(project, None, detect_loops=False)
        annotatedcfg.from_digraph(b.slice)

        # pylint: disable=too-many-nested-blocks
        for src_irsb, _ in sources:
            # Use slicecutor to execute each one, and get the address
            # We simply give up if any exception occurs on the way
            start_state = self._initial_state(src_irsb)

            # any read from an uninitialized segment should be unconstrained
            if self._bss_regions:
                bss_memory_read_bp = BP(when=BP_BEFORE, enabled=True, action=self._bss_memory_read_hook)
                start_state.inspect.add_breakpoint('mem_read', bss_memory_read_bp)

            start_state.regs.bp = start_state.arch.initial_sp + 0x2000

            init_registers_on_demand_bp = BP(when=BP_BEFORE, enabled=True, action=self._init_registers_on_demand)
            start_state.inspect.add_breakpoint('mem_read', init_registers_on_demand_bp)

            # Create the slicecutor
            simgr = self.project.factory.simulation_manager(start_state, resilience=True)
            simgr.use_technique(Slicecutor(annotatedcfg, force_taking_exit=True))
            simgr.use_technique(Explorer(find=load_stmt_loc[0]))

            # Run it!
            try:
                simgr.run()
            except KeyError as ex:
                # This is because the program slice is incomplete.
                # Blade will support more IRExprs and IRStmts
                l.debug("KeyError occurred due to incomplete program slice.", exc_info=ex)
                continue

            # Get the jumping targets
            for r in simgr.found:
                try:
                    succ = project.factory.successors(r)
                except (AngrError, SimError):
                    # oops there are errors
                    l.warning('Cannot get jump successor states from a path that has reached the target. Skip it.')
                    continue
                all_states = succ.flat_successors + succ.unconstrained_successors
                if not all_states:
                    l.warning("Slicecutor failed to execute the program slice. No output state is available.")
                    continue

                state = all_states[0]  # Just take the first state

                # Parse the memory load statement
                jump_addr = self._parse_load_statement(load_stmt, state)
                if jump_addr is None:
                    continue
                all_targets = [ ]
                total_cases = jump_addr._model_vsa.cardinality

                if total_cases > self._max_targets:
                    # We resolved too many targets for this indirect jump. Something might have gone wrong.
                    l.debug("%d targets are resolved for the indirect jump at %#x. It may not be a jump table",
                            total_cases, addr)
                    return False, None

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.solver.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr +
                    # (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                min_jump_target = state.solver.min(jump_addr)
                max_jump_target = state.solver.max(jump_addr)

                # Both the min jump target and the max jump target should be within a mapped memory region
                # i.e., we shouldn't be jumping to the stack or somewhere unmapped
                if not project.loader.find_segment_containing(min_jump_target) or \
                        not project.loader.find_segment_containing(max_jump_target):
                    l.debug("Jump table %#x might have jump targets outside mapped memory regions. "
                            "Continue to resolve it from the next data source.", addr)
                    continue

                for idx, a in enumerate(state.solver.eval_upto(jump_addr, total_cases)):
                    if idx % 100 == 0 and idx != 0:
                        l.debug("%d targets have been resolved for the indirect jump at %#x...", idx, addr)
                    target = cfg._fast_memory_load_pointer(a)
                    all_targets.append(target)
                    jump_table.append(target)

                l.info("Resolved %d targets from %#x.", len(all_targets), addr)

                # write to the IndirectJump object in CFG
                ij = cfg.indirect_jumps[addr]
                if total_cases > 1:
                    # It can be considered a jump table only if there are more than one jump target
                    ij.jumptable = True
                    ij.jumptable_addr = state.solver.min(jump_addr)
                    ij.resolved_targets = set(jump_table)
                    ij.jumptable_entries = jump_table
                else:
                    ij.jumptable = False
                    ij.resolved_targets = set(jump_table)

                return True, all_targets

        return False, None

    #
    # Private methods
    #

    def _find_bss_region(self):

        self._bss_regions = [ ]

        # TODO: support other sections other than '.bss'.
        # TODO: this is very hackish. fix it after the chaos.
        for section in self.project.loader.main_object.sections:
            if section.name == '.bss':
                self._bss_regions.append((section.vaddr, section.memsize))
                break

    def _bss_memory_read_hook(self, state):

        if not self._bss_regions:
            return

        read_addr = state.inspect.mem_read_address
        read_length = state.inspect.mem_read_length

        if not isinstance(read_addr, int) and read_addr.symbolic:
            # don't touch it
            return

        concrete_read_addr = state.solver.eval(read_addr)
        concrete_read_length = state.solver.eval(read_length)

        for start, size in self._bss_regions:
            if start <= concrete_read_addr < start + size:
                # this is a read from the .bss section
                break
        else:
            return

        if not state.memory.was_written_to(concrete_read_addr):
            # it was never written to before. we overwrite it with unconstrained bytes
            for i in range(0, concrete_read_length, self.project.arch.bytes):
                state.memory.store(concrete_read_addr + i, state.solver.Unconstrained('unconstrained', self.project.arch.bits))

                # job done :-)

    @staticmethod
    def _init_registers_on_demand(state):
        # for uninitialized read using a register as the source address, we replace them in memory on demand
        read_addr = state.inspect.mem_read_address
        cond = state.inspect.mem_read_condition

        if not isinstance(read_addr, int) and read_addr.uninitialized and cond is None:

            read_length = state.inspect.mem_read_length
            if not isinstance(read_length, int):
                read_length = read_length._model_vsa.upper_bound
            if read_length > 16:
                return
            new_read_addr = state.solver.BVV(UninitReadMeta.uninit_read_base, state.arch.bits)
            UninitReadMeta.uninit_read_base += read_length

            # replace the expression in registers
            state.registers.replace_all(read_addr, new_read_addr)

            state.inspect.mem_read_address = new_read_addr

            # job done :-)

    def _dbg_repr_slice(self, blade):

        stmts = defaultdict(set)

        for addr, stmt_idx in sorted(list(blade.slice.nodes())):
            stmts[addr].add(stmt_idx)

        for addr in sorted(stmts.keys()):
            stmt_ids = stmts[addr]
            irsb = self.project.factory.block(addr, backup_state=self.base_state).vex

            print("  ####")
            print("  #### Block %#x" % addr)
            print("  ####")

            for i, stmt in enumerate(irsb.statements):
                taken = i in stmt_ids
                s = "%s %x:%02d | " % ("+" if taken else " ", addr, i)
                s += "%s " % stmt.__str__(arch=self.project.arch, tyenv=irsb.tyenv)
                if taken:
                    s += "IN: %d" % blade.slice.in_degree((addr, i))
                print(s)

            # the default exit
            default_exit_taken = 'default' in stmt_ids
            s = "%s %x:default | PUT(%s) = %s; %s" % ("+" if default_exit_taken else " ", addr, irsb.offsIP, irsb.next,
                                                      irsb.jumpkind
                                                      )
            print(s)

    def _initial_state(self, src_irsb):

        state = self.project.factory.blank_state(
            addr=src_irsb,
            mode='static',
            add_options={
                o.DO_RET_EMULATION,
                o.TRUE_RET_EMULATION_GUARD,
                o.AVOID_MULTIVALUED_READS,
            },
            remove_options={
                               o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                               o.UNINITIALIZED_ACCESS_AWARENESS,
                           } | o.refs
        )

        return state

    @staticmethod
    def _parse_load_statement(load_stmt, state):
        """
        Parse a memory load VEX statement and get the jump target addresses.

        :param load_stmt:   The VEX statement for loading the jump target addresses.
        :param state:       The SimState instance (in static mode).
        :return:            A tuple of an abstract value (or a concrete value) representing the jump target addresses,
                            and a set of extra concrete targets. Return (None, None) if we fail to parse the statement.
        """

        # The jump table address is stored in a tmp. In this case, we find the jump-target loading tmp.
        load_addr_tmp = None

        if isinstance(load_stmt, pyvex.IRStmt.WrTmp):
            load_addr_tmp = load_stmt.data.addr.tmp
        elif isinstance(load_stmt, pyvex.IRStmt.LoadG):
            if type(load_stmt.addr) is pyvex.IRExpr.RdTmp:
                load_addr_tmp = load_stmt.addr.tmp
            elif type(load_stmt.addr) is pyvex.IRExpr.Const:
                # It's directly loading from a constant address
                # e.g.,
                #  4352c     SUB     R1, R11, #0x1000
                #  43530     LDRHI   R3, =loc_45450
                #  ...
                #  43540     MOV     PC, R3
                #
                # It's not a jump table, but we resolve it anyway
                # TODO: We should develop an ARM-specific indirect jump resolver in this case
                # Note that this block has two branches: One goes to 45450, the other one goes to whatever the original
                # value of R3 is. Some intensive data-flow analysis is required in this case.
                jump_target_addr = load_stmt.addr.con.value
                return state.solver.BVV(jump_target_addr, state.arch.bits)
        else:
            raise TypeError("Unsupported address loading statement type %s." % type(load_stmt))

        if load_addr_tmp not in state.scratch.temps:
            # the tmp variable is not there... umm...
            return None

        jump_addr = state.scratch.temps[load_addr_tmp]

        if isinstance(load_stmt, pyvex.IRStmt.LoadG):
            # LoadG comes with a guard. We should apply this guard to the load expression
            guard_tmp = load_stmt.guard.tmp
            guard = state.scratch.temps[guard_tmp] != 0
            jump_addr = state.memory._apply_condition_to_symbolic_addr(jump_addr, guard)

        return jump_addr
