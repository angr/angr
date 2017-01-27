
import logging

from cle import CLEError
from archinfo.arch_soot import SootAddressDescriptor, SootAddressTerminator, SootMethodDescriptor

from ...state_plugins.inspect import BP_BEFORE, BP_AFTER
from ...errors import SimTranslationError
from ... import sim_options as o
from ..engine import SimEngine
from .statements import translate_stmt, SimSootStmt_Return, SimSootStmt_ReturnVoid
from .exceptions import BlockTerminationNotice, IncorrectLocationException

l = logging.getLogger('angr.engines.soot.engine')


class SimEngineSoot(SimEngine):
    """
    Execution engine based on Soot.
    """

    def __init__(self, project=None, **kwargs):
        super(SimEngineSoot, self).__init__()

        self.project = project

    def lift(self, addr=None, the_binary=None, **kwargs):
        assert isinstance(addr, SootAddressDescriptor)

        method, label = addr.method, addr.stmt_idx

        try:
            methods = the_binary.get_method(method)
            method = next(methods)
        except CLEError as ex:
            raise SimTranslationError("CLE error: " + ex.message)

        if label is None:
            return method.blocks[0] if method.blocks else None
        else:
            return method.block_by_label.get(label, None)

    def _check(self, state, *args, **kwargs):
        return state.regs._ip_binary is not None and isinstance(state._ip, SootAddressDescriptor)

    def _process(self, state, successors, *args, **kwargs):
        addr = state._ip

        if isinstance(addr, SootAddressTerminator):
            successors.processed = True
            return

        if self.project.use_sim_procedures:
            procedure = self._get_sim_procedure(addr)
            if procedure is not None:
                self.project.factory.procedure_engine._process(state, successors, procedure)
                return

        l.debug("Executing new block %s" % (addr))
        #if self._is_method_beginning(addr):
        #    # At the beginning of a method, move some essential variables from regs to callstack
        #    # These variables will be used again at return sites
        #    self.handle_method_beginning(state)

        binary = state.regs._ip_binary

        try:
            method = next(binary.get_method(addr.method))
        except CLEError:
            l.warning("We ended up in non-loaded Java code %s" % addr)
            successors.processed = False
            # This means we are executing code that it is not in CLE, typically library code.
            # We may want soot -> pysoot -> cle to export at least the method names of the libraries
            # (soot has a way to deal with this), as of now we just "simulate" a returnvoid.
            # Note that if we have sim procedure, we should not even reach this point.
            ret_state = state.copy()
            self.prepare_return_state(ret_state)
            successors.add_successor(ret_state, state.callstack.ret_addr, ret_state.se.true, 'Ijk_Ret')
            successors.processed = True
        else:
            block = method.blocks[addr.block_idx]
            starting_stmt_idx = addr.stmt_idx
            self._handle_block(state, successors, block, starting_stmt_idx, method)

        successors.processed = True

    def _handle_block(self, state, successors, block, starting_stmt_idx, method=None):
        stmt = None
        stmt_idx = starting_stmt_idx

        for tindex, stmt in enumerate(block.statements[starting_stmt_idx:]):
            stmt_idx = starting_stmt_idx + tindex
            state._inspect('statement', BP_BEFORE, statement=stmt_idx)

            terminate = self._handle_statement(state, successors, stmt_idx, stmt)
            state._inspect('statement', BP_AFTER)

            if terminate:
                break

        else:
            if stmt is None:
                l.warning("Executed empty bb, maybe pc is broken")
            else:
                if method is not None:
                    last_addr = state.addr.copy()
                    last_addr.stmt_idx = stmt_idx
                    next_addr = self._get_next_linear_instruction(state, last_addr)
                    l.debug("Advancing execution linearly to %s" % next_addr)
                    if next_addr is not None:
                        successors.add_successor(state.copy(), next_addr, state.se.true, 'Ijk_Boring')

    def _handle_statement(self, state, successors, stmt_idx, stmt):

        #if "fail" in state.addr.method.name:
        #    import ipdb; ipdb.set_trace()

        # Initialize state registers
        state.scratch.jump = False
        state.scratch.jump_targets_with_conditions = None
        state.scratch.invoke = False
        state.scratch.invoke_expr = None
        state.scratch.invoke_return_target = None
        state.scratch.invoke_return_variable = None

        l.info("Executing statement %s [%s]", stmt, state.addr)

        s_stmt = translate_stmt(stmt, state)
        # print state.memory.stack

        if state.scratch.invoke:
            # Create a new exit
            l.debug("Adding an invoke exit.")

            invoke_state = state.copy()

            last_addr = state.addr.copy()
            last_addr.stmt_idx = stmt_idx
            self._prepare_call_state(invoke_state, last_addr)

            # Build the call target
            call_target = SootAddressDescriptor(state.scratch.invoke_target, 0, 0)

            #invoke_state.regs._invoke_return_variable = invoke_state.scratch.invoke_return_variable
            #invoke_state.regs._invoke_return_target = invoke_state.scratch.invoke_return_target
            #invoke_state.regs._invoke_expr = invoke_state.scratch.invoke_expr
            successors.add_successor(invoke_state, call_target, state.se.true, 'Ijk_Call', )

            # We terminate the execution since Soot does not guarantee that a block terminates with an Invoke
            return True

        elif state.scratch.jump:
            for target, condition in state.scratch.jump_targets_with_conditions:
                if target is None:
                    last_addr = state.addr.copy()
                    last_addr.stmt_idx = stmt_idx
                    computed_target = self._get_next_linear_instruction(state, last_addr)
                else:
                    computed_target = target
                l.warning("Possible jump: %s -> %s" % (state._ip, computed_target))
                print "---", target, computed_target, condition
                successors.add_successor(state.copy(), computed_target, condition, 'Ijk_Boring')

            return True

        elif type(s_stmt) is SimSootStmt_Return:
            l.debug("Adding a return exit.")
            ret_state = state.copy()
            self.prepare_return_state(ret_state, s_stmt.return_value)
            successors.add_successor(ret_state, state.callstack.ret_addr, ret_state.se.true, 'Ijk_Ret')
            successors.processed = True

            return True

        elif type(s_stmt) is SimSootStmt_ReturnVoid:
            l.debug("Adding a return-void exit.")
            ret_state = state.copy()
            self.prepare_return_state(ret_state)
            successors.add_successor(ret_state, state.callstack.ret_addr, ret_state.se.true, 'Ijk_Ret')
            successors.processed = True

            return True

        return False

    def _get_sim_procedure(self, addr):

        # Delayed import
        from ...procedures import SIM_PROCEDURES

        if addr in self.project._sim_procedures:
            return self.project._sim_procedures[addr]

        method = addr.method
        class_name = method.class_name
        method_prototype = "%s(%s)" % (method.name, ",".join(method.params))

        if class_name in SIM_PROCEDURES and \
                method_prototype in SIM_PROCEDURES[class_name]:
            procedure_cls = SIM_PROCEDURES[class_name][method_prototype]
        else:
            return None

        # Lazy-initialize it
        proc = procedure_cls(project=self.project)
        self.project._sim_procedures[addr] = proc

        return proc

    @staticmethod
    def _is_method_beginning(addr):
        return addr.block_idx == 0 and addr.stmt_idx == 0

    @staticmethod
    def _get_next_linear_instruction(state, addr):
        method = next(state.regs._ip_binary.get_method(addr.method))
        current_bb = method.blocks[addr.block_idx]
        new_stmt_idx = addr.stmt_idx + 1
        if new_stmt_idx < len(current_bb.statements):
            return SootAddressDescriptor(addr.method, addr.block_idx, new_stmt_idx)
        else:
            new_bb_idx = addr.block_idx + 1
            if new_bb_idx < len(method.blocks):
                return SootAddressDescriptor(addr.method, new_bb_idx, 0)
            else:
                l.warning("falling into a non existing bb: %d in %s" %
                          (new_bb_idx, SootMethodDescriptor.from_method(method)))
                raise IncorrectLocationException()

    def _prepare_call_state(self, state, last_addr):

        # Calculate the return target
        ret_target = self._get_next_linear_instruction(state, last_addr)
        l.debug("Computed linear return address %s" % ret_target)

        # Push a new callstack frame
        state.callstack.push(state.callstack.copy())
        state.callstack.ret_addr = ret_target
        state.callstack.invoke_return_variable = state.scratch.invoke_return_variable

        old_ret_addr = state.callstack.next.ret_addr
        l.debug("Callstack push [%s] -> [%s]" % (old_ret_addr, state.callstack.ret_addr))

        # Create a new stack frame
        state.memory.push_stack_frame()

    @staticmethod
    def prepare_return_state(state, ret_value=None):
        """
        Prepare the state for the return site.

        :param state:       The state to prepare for returning.
        :param ret_value:   The value to return from the current method.
        :return:            None
        """

        ret_var = state.callstack.invoke_return_variable
        state.memory.pop_stack_frame()
        state.callstack.pop()

        if ret_var is not None and ret_value is not None:
            # Write the return value to the return variable in the previous stack frame
            state.memory.store(ret_var, ret_value)

    @staticmethod
    def terminate_execution(statement, state, successors):
        l.debug("Returning with an empty stack: ending execution")
        # this code is coming by sim_procedure.exit()
        state.options.discard(o.AST_DEPS)
        state.options.discard(o.AUTO_REFS)
        exit_code = 0
        if type(statement) is SimSootStmt_Return:
            exit_code = statement.return_value
            # TODO symbolic exit code?
            exit_code = state.se.BVV(exit_code, state.arch.bits)
        state.history.add_event('terminate', exit_code=exit_code)
        successors.add_successor(state, state.regs.ip, state.se.true, 'Ijk_Exit')
        successors.processed = True
        raise BlockTerminationNotice()
