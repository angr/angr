
import logging
from collections import defaultdict, OrderedDict

import pyvex

from ....errors import AngrError, SimError
from ....blade import Blade
from ....annocfg import AnnotatedCFG
from .... import sim_options as o
from .... import BP, BP_BEFORE
from ....exploration_techniques.slicecutor import Slicecutor
from ....exploration_techniques.explorer import Explorer
from .resolver import IndirectJumpResolver


l = logging.getLogger(name=__name__)


class UninitReadMeta:
    uninit_read_base = 0xc000000


class AddressTransferringTypes:
    Assignment = 0
    SignedExtension32to64 = 1
    UnsignedExtension32to64 = 2
    Truncation64to32 = 3


class JumpTargetBaseAddr:
    def __init__(self, stmt_loc, stmt, tmp, base_addr=None, tmp_1=None):
        self.stmt_loc = stmt_loc
        self.stmt = stmt
        self.tmp = tmp  # type:int
        self.tmp_1 = tmp_1
        self.base_addr = base_addr  # type:int

        assert base_addr is not None or tmp_1 is not None

    @property
    def base_addr_available(self):
        return self.base_addr is not None


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

        load_stmt_loc, load_stmt, load_size = None, None, None
        stmts_to_remove = [stmt_loc]
        stmts_adding_base_addr = [ ]  # type: list[JumpTargetBaseAddr]
        # All temporary variables that hold indirect addresses loaded out of the memory
        # Obviously, load_stmt.tmp must be here
        # if there are additional data transferring statements between the Load statement and the base-address-adding
        # statement, all_addr_holders will have more than one temporary variables
        #
        # Here is an example:
        #
        # IRSB 0x4c64c4
        #  + 06 | t12 = LDle:I32(t7)
        #  + 07 | t11 = 32Sto64(t12)
        #  + 10 | t2 = Add64(0x0000000000571df0,t11)
        #
        # all_addr_holders will be {(0x4c64c4, 11): AddressTransferringTypes.SignedExtension32to64,
        #           (0x4c64c4, 12); AddressTransferringTypes.Assignment,
        #           }
        all_addr_holders = OrderedDict()

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
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        all_addr_holders[(stmt_loc[0], stmt.tmp)] = AddressTransferringTypes.Assignment
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.ITE):
                    # data transferring
                    #   t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                    # > t44 = ITE(t43,t16,0x0000c844)
                    stmts_to_remove.append(stmt_loc)
                    if isinstance(stmt, pyvex.IRStmt.WrTmp):
                        all_addr_holders[(stmt_loc[0], stmt.tmp)] = AddressTransferringTypes.Assignment
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.Unop):
                    if stmt.data.op == 'Iop_32Sto64':
                        # data transferring with conversion
                        # t11 = 32Sto64(t12)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            all_addr_holders[(stmt_loc[0], stmt.tmp)] = AddressTransferringTypes.SignedExtension32to64
                        continue
                    elif stmt.data.op == 'Iop_64to32':
                        # data transferring with conversion
                        # t24 = 64to32(t21)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            all_addr_holders[(stmt_loc[0], stmt.tmp)] = AddressTransferringTypes.Truncation64to32
                        continue
                    elif stmt.data.op == 'Iop_32Uto64':
                        # data transferring with conversion
                        # t21 = 32Uto64(t22)
                        stmts_to_remove.append(stmt_loc)
                        if isinstance(stmt, pyvex.IRStmt.WrTmp):
                            all_addr_holders[(stmt_loc[0], stmt.tmp)] = AddressTransferringTypes.UnsignedExtension32to64
                        continue
                elif isinstance(stmt.data, pyvex.IRExpr.Binop) and stmt.data.op.startswith('Iop_Add'):
                    # GitHub issue #1289, a S390X binary
                    # jump_label = &jump_table + *(jump_table[index])
                    #       IRSB 0x4007c0
                    #   00 | ------ IMark(0x4007c0, 4, 0) ------
                    # + 01 | t0 = GET:I32(212)
                    # + 02 | t1 = Add32(t0,0xffffffff)
                    #   03 | PUT(352) = 0x0000000000000003
                    #   04 | t13 = 32Sto64(t0)
                    #   05 | t6 = t13
                    #   06 | PUT(360) = t6
                    #   07 | PUT(368) = 0xffffffffffffffff
                    #   08 | PUT(376) = 0x0000000000000000
                    #   09 | PUT(212) = t1
                    #   10 | PUT(ia) = 0x00000000004007c4
                    #   11 | ------ IMark(0x4007c4, 6, 0) ------
                    # + 12 | t14 = 32Uto64(t1)
                    # + 13 | t8 = t14
                    # + 14 | t16 = CmpLE64U(t8,0x000000000000000b)
                    # + 15 | t15 = 1Uto32(t16)
                    # + 16 | t10 = t15
                    # + 17 | t11 = CmpNE32(t10,0x00000000)
                    # + 18 | if (t11) { PUT(offset=336) = 0x4007d4; Ijk_Boring }
                    #   Next: 0x4007ca
                    #
                    #       IRSB 0x4007d4
                    #   00 | ------ IMark(0x4007d4, 6, 0) ------
                    # + 01 | t8 = GET:I64(r2)
                    # + 02 | t7 = Shr64(t8,0x3d)
                    # + 03 | t9 = Shl64(t8,0x03)
                    # + 04 | t6 = Or64(t9,t7)
                    # + 05 | t11 = And64(t6,0x00000007fffffff8)
                    #   06 | ------ IMark(0x4007da, 6, 0) ------
                    #   07 | PUT(r1) = 0x0000000000400a50
                    #   08 | PUT(ia) = 0x00000000004007e0
                    #   09 | ------ IMark(0x4007e0, 6, 0) ------
                    # + 10 | t12 = Add64(0x0000000000400a50,t11)
                    # + 11 | t16 = LDbe:I64(t12)
                    #   12 | PUT(r2) = t16
                    #   13 | ------ IMark(0x4007e6, 4, 0) ------
                    # + 14 | t17 = Add64(0x0000000000400a50,t16)
                    # + Next: t17
                    #
                    # Special case: a base address is added to the loaded offset before jumping to it.
                    if isinstance(stmt.data.args[0], pyvex.IRExpr.Const) and \
                            isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp):
                        stmts_adding_base_addr.append(JumpTargetBaseAddr(stmt_loc, stmt,
                                                                         stmt.data.args[1].tmp,
                                                                         base_addr=stmt.data.args[0].con.value)
                                                      )
                        stmts_to_remove.append(stmt_loc)
                    elif isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp) and \
                            isinstance(stmt.data.args[1], pyvex.IRExpr.Const):
                        stmts_adding_base_addr.append(JumpTargetBaseAddr(stmt_loc, stmt,
                                                                         stmt.data.args[0].tmp,
                                                                         base_addr=stmt.data.args[1].con.value)
                                                      )
                        stmts_to_remove.append(stmt_loc)
                    elif isinstance(stmt.data.args[0], pyvex.IRExpr.RdTmp) and \
                            isinstance(stmt.data.args[1], pyvex.IRExpr.RdTmp):
                        # one of the tmps must be holding a concrete value at this point
                        stmts_adding_base_addr.append(JumpTargetBaseAddr(stmt_loc, stmt,
                                                                         stmt.data.args[0].tmp,
                                                                         tmp_1=stmt.data.args[1].tmp)
                                                      )
                        stmts_to_remove.append(stmt_loc)
                    else:
                        # not supported
                        pass
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.Load):
                    # Got it!
                    load_stmt, load_stmt_loc, load_size = stmt, stmt_loc, \
                                                          block.tyenv.sizeof(stmt.tmp) // self.project.arch.byte_width
                    stmts_to_remove.append(stmt_loc)
            elif isinstance(stmt, pyvex.IRStmt.LoadG):
                # Got it!
                #
                # this is how an ARM jump table is translated to VEX
                # > t16 = if (t43) ILGop_Ident32(LDle(t29)) else 0x0000c844
                load_stmt, load_stmt_loc, load_size = stmt, stmt_loc, \
                                                      block.tyenv.sizeof(stmt.dst) // self.project.arch.byte_width
                stmts_to_remove.append(stmt_loc)

            break

        if load_stmt_loc is None:
            # the load statement is not found
            return False, None

        if len(stmts_adding_base_addr) > 1:
            # there are more than one statement that is trying to mess with the loaded address. unsupported for now.
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
            # Keep IP symbolic to avoid unnecessary concretization
            start_state.options.add(o.KEEP_IP_SYMBOLIC)
            start_state.options.add(o.NO_IP_CONCRETIZATION)
            # be quiet!!!!!!
            start_state.options.add(o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
            start_state.options.add(o.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

            # any read from an uninitialized segment should be unconstrained
            if self._bss_regions:
                bss_memory_read_bp = BP(when=BP_BEFORE, enabled=True, action=self._bss_memory_read_hook)
                start_state.inspect.add_breakpoint('mem_read', bss_memory_read_bp)

            # FIXME:
            # this is a hack: for certain architectures, we do not initialize the base pointer, since the jump table on
            # those architectures may use the bp register to store value
            if not self.project.arch.name in {'S390X'}:
                start_state.regs.bp = start_state.arch.initial_sp + 0x2000

            init_registers_on_demand_bp = BP(when=BP_BEFORE, enabled=True, action=self._init_registers_on_demand)
            start_state.inspect.add_breakpoint('mem_read', init_registers_on_demand_bp)

            # Create the slicecutor
            simgr = self.project.factory.simulation_manager(start_state, resilience=True)
            slicecutor = Slicecutor(annotatedcfg, force_taking_exit=True)
            simgr.use_technique(slicecutor)
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
                    whitelist = annotatedcfg.get_whitelisted_statements(r.addr)
                    last_stmt = annotatedcfg.get_last_statement_index(r.addr)
                    succ = project.factory.successors(r, whitelist=whitelist, last_stmt=last_stmt)
                except (AngrError, SimError):
                    # oops there are errors
                    l.warning('Cannot get jump successor states from a path that has reached the target. Skip it.')
                    continue
                all_states = succ.flat_successors + succ.unconstrained_successors
                if not all_states:
                    l.warning("Slicecutor failed to execute the program slice. No output state is available.")
                    continue

                state = all_states[0]  # Just take the first state

                # Parse the memory load statement and get the memory address of where the jump table is stored
                jumptable_addr = self._parse_load_statement(load_stmt, state)
                if jumptable_addr is None:
                    continue

                # sanity check and necessary pre-processing
                if stmts_adding_base_addr:
                    assert len(stmts_adding_base_addr) == 1  # Making sure we are only dealing with one operation here
                    jump_base_addr = stmts_adding_base_addr[0]
                    if jump_base_addr.base_addr_available:
                        addr_holders = { (jump_base_addr.stmt_loc[0], jump_base_addr.tmp) }
                    else:
                        addr_holders = { (jump_base_addr.stmt_loc[0], jump_base_addr.tmp),
                                         (jump_base_addr.stmt_loc[0], jump_base_addr.tmp_1)
                                         }
                    if len(set(all_addr_holders.keys()).intersection(addr_holders)) != 1:
                        # for some reason it's trying to add a base address onto a different temporary variable that we
                        # are not aware of. skip.
                        continue

                    if not jump_base_addr.base_addr_available:
                        # we need to decide which tmp is the address holder and which tmp holds the base address
                        addr_holder = next(iter(set(all_addr_holders.keys()).intersection(addr_holders)))
                        if jump_base_addr.tmp_1 == addr_holder[1]:
                            # swap the two tmps
                            jump_base_addr.tmp, jump_base_addr.tmp_1 = jump_base_addr.tmp_1, jump_base_addr.tmp
                        # Load the concrete base address
                        jump_base_addr.base_addr = state.solver.eval(state.scratch.temps[jump_base_addr.tmp_1])

                all_targets = [ ]
                total_cases = jumptable_addr._model_vsa.cardinality

                if total_cases > self._max_targets:
                    # We resolved too many targets for this indirect jump. Something might have gone wrong.
                    l.debug("%d targets are resolved for the indirect jump at %#x. It may not be a jump table. Try the "
                            "next source, if there is any.",
                            total_cases, addr)
                    continue

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.solver.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr +
                    # (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                min_jumptable_addr = state.solver.min(jumptable_addr)
                max_jumptable_addr = state.solver.max(jumptable_addr)

                # The beginning of the jump table and the end of the jump table should be within a mapped memory region
                if not cfg.project.loader.find_object_containing(min_jumptable_addr) or \
                        not cfg.project.loader.find_object_containing(max_jumptable_addr):
                    l.debug("Indirect jump at block %#x seems to be referencing a jumptable outside mapped memory"
                            "regions. Attempt to resolve it from the next data source.", addr)
                    continue

                # Load the jump table from memory
                for idx, a in enumerate(state.solver.eval_upto(jumptable_addr, total_cases)):
                    if idx % 100 == 0 and idx != 0:
                        l.debug("%d targets have been resolved for the indirect jump at %#x...", idx, addr)
                    target = cfg._fast_memory_load_pointer(a, size=load_size)
                    all_targets.append(target)

                # Adjust entries inside the jump table
                if stmts_adding_base_addr:
                    stmt_adding_base_addr = stmts_adding_base_addr[0]
                    base_addr = stmt_adding_base_addr.base_addr
                    conversion_ops = list(reversed(list(v for v in all_addr_holders.values()
                                                   if v is not AddressTransferringTypes.Assignment)))
                    if conversion_ops:
                        invert_conversion_ops = [ ]
                        for conversion_op in conversion_ops:
                            if conversion_op is AddressTransferringTypes.SignedExtension32to64:
                                lam = lambda a: (a | 0xffffffff00000000) if a >= 0x80000000 else a
                            elif conversion_op is AddressTransferringTypes.UnsignedExtension32to64:
                                lam = lambda a: a
                            elif conversion_op is AddressTransferringTypes.Truncation64to32:
                                lam = lambda a: a & 0xffffffff
                            else:
                                raise NotImplementedError("Unsupported conversion operation.")
                            invert_conversion_ops.append(lam)
                        all_targets_copy = all_targets
                        all_targets = [ ]
                        for target_ in all_targets_copy:
                            for lam in invert_conversion_ops:
                                target_ = lam(target_)
                            all_targets.append(target_)
                    mask = (2 ** self.project.arch.bits) - 1
                    all_targets = [(target + base_addr) & mask for target in all_targets]

                # Finally... all targets are ready
                for target in all_targets:
                    jump_table.append(target)

                l.info("Resolved %d targets from %#x.", len(all_targets), addr)

                # write to the IndirectJump object in CFG
                ij = cfg.indirect_jumps[addr]
                if total_cases > 1:
                    # It can be considered a jump table only if there are more than one jump target
                    ij.jumptable = True
                    ij.jumptable_addr = state.solver.min(jumptable_addr)
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

    def _dbg_repr_slice(self, blade, in_slice_stmts_only=False):

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
                stmt_taken = i in stmt_ids
                display = stmt_taken if in_slice_stmts_only else True
                if display:
                    s = "%s %x:%02d | " % ("+" if stmt_taken else " ", addr, i)
                    s += "%s " % stmt.__str__(arch=self.project.arch, tyenv=irsb.tyenv)
                    if stmt_taken:
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
        :return:            An abstract value (or a concrete value) representing the jump target addresses. Return None
                            if we fail to parse the statement.
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
