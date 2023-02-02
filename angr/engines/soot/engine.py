import logging

from archinfo.arch_soot import (
    ArchSoot,
    SootAddressDescriptor,
    SootAddressTerminator,
    SootArgument,
    SootMethodDescriptor,
)

from ... import sim_options as o
from ...errors import SimEngineError, SimTranslationError
from cle import CLEError
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE
from ...sim_type import SimTypeFunction, parse_type
from ..engine import SuccessorsMixin
from ..procedure import ProcedureMixin
from .exceptions import BlockTerminationNotice, IncorrectLocationException
from .statements import SimSootStmt_Return, SimSootStmt_ReturnVoid, translate_stmt
from .values import SimSootValue_Local, SimSootValue_ParamRef

l = logging.getLogger("angr.engines.soot.engine")

# pylint: disable=arguments-differ


class SootMixin(SuccessorsMixin, ProcedureMixin):
    """
    Execution engine based on Soot.
    """

    def lift_soot(self, addr=None, the_binary=None, **kwargs):  # pylint: disable=unused-argument, no-self-use
        assert isinstance(addr, SootAddressDescriptor)

        method, stmt_idx = addr.method, addr.stmt_idx

        try:
            method = the_binary.get_soot_method(method, params=method.params)
        except CLEError as ex:
            raise SimTranslationError(f"CLE error: {ex}")

        if stmt_idx is None:
            return method.blocks[0] if method.blocks else None
        else:
            # try:
            #    _, block = method.block_by_label.floor_item(stmt_idx)
            # except KeyError:
            #    return None
            # return block
            # TODO: Re-enable the above code once bintrees are used

            # FIXME: stmt_idx does not index from the start of the method but from the start
            #        of the block therefore it always returns the block with label 0 independently
            #        of where we are
            # block = method.block_by_label.get(stmt_idx, None)
            # if block is not None:
            #     return block
            # Slow path
            for block_idx, block in enumerate(method.blocks):
                # if block.label <= stmt_idx < block.label + len(block.statements):
                if block_idx == addr.block_idx:
                    return block
            return None

    def process_successors(self, successors, **kwargs):
        state = self.state
        if not isinstance(state._ip, SootAddressDescriptor):
            return super().process_successors(successors, **kwargs)
        addr = state._ip

        if isinstance(addr, SootAddressTerminator):
            successors.processed = True
            return

        if self.project.use_sim_procedures:
            procedure = self._get_sim_procedure(addr)
            if procedure is not None:
                self.process_procedure(state, successors, procedure)
                return

        binary = state.regs._ip_binary
        method = binary.get_soot_method(addr.method, none_if_missing=True)

        # TODO make the skipping of code in "android.*" classes optional
        if addr.method.class_name.startswith("android.") or not method:
            # This means we are executing code that is not in CLE, typically library code.
            # We may want soot -> pysoot -> cle to export at least the method names of the libraries
            # (soot has a way to deal with this), as of now we just "simulate" a return.
            # Note: If we have a sim procedure, we should not reach this point.
            l.warning("Try to execute non-loaded code %s. Execute unconstrained SimProcedure.", addr)
            # STEP 1: Get unconstrained SimProcedure
            procedure = self.get_unconstrained_simprocedure()
            # STEP 2: Pass Method descriptor as Parameter

            # check if there are already params in the stack
            param_idx = 0
            param_ref = state.javavm_memory.load(SimSootValue_ParamRef(param_idx, None), none_if_missing=True)
            while param_ref is not None:
                param_idx += 1
                param_ref = state.javavm_memory.load(SimSootValue_ParamRef(param_idx, None), none_if_missing=True)

            # store all function arguments in memory, starting from the last param index
            state.memory.store(SimSootValue_ParamRef(param_idx, None), addr.method)
            # STEP 4: Execute unconstrained procedure
            self.process_procedure(state, successors, procedure)
            # self._add_return_exit(state, successors)
            return

        block = method.blocks[addr.block_idx]
        starting_stmt_idx = addr.stmt_idx
        if starting_stmt_idx == 0:
            l.debug("Executing new block %s \n\n%s\n", addr, block)
        else:
            # l.debug("Continue executing block %s", addr)
            l.debug("Continue executing block %s \n\n%s\n", addr, block)
        self._handle_soot_block(state, successors, block, starting_stmt_idx, method)

        successors.processed = True

    def _handle_soot_block(self, state, successors, block, starting_stmt_idx, method=None):
        stmt = stmt_idx = None
        for tindex, stmt in enumerate(block.statements[starting_stmt_idx:]):
            stmt_idx = starting_stmt_idx + tindex
            state._inspect("statement", BP_BEFORE, statement=stmt_idx)
            terminate = self._handle_soot_stmt(state, successors, stmt_idx, stmt)
            state._inspect("statement", BP_AFTER)
            if terminate:
                break
        else:
            if stmt is None:
                l.warning("Executed empty bb, maybe pc is broken")
                return
            if method is not None:
                next_addr = self._get_next_linear_instruction(state, stmt_idx)
                l.debug("Advancing execution linearly to %s", next_addr)
                if next_addr is not None:
                    successors.add_successor(state.copy(), next_addr, state.solver.true, "Ijk_Boring")

    def _handle_soot_stmt(self, state, successors, stmt_idx, stmt):
        # execute statement
        try:
            l.debug("Executing statement: %s", stmt)
            s_stmt = translate_stmt(stmt, state)
        except SimEngineError as e:
            l.error("Skipping statement: %s", e)
            return False

        # add invoke exit
        if s_stmt.has_invoke_target:
            invoke_state = state.copy()
            # parse invoke expression
            invoke_expr = s_stmt.invoke_expr
            method = invoke_expr.method
            args = invoke_expr.args
            ret_var = invoke_expr.ret_var if hasattr(invoke_expr, "ret_var") else None
            # setup callsite
            ret_addr = self._get_next_linear_instruction(state, stmt_idx)
            if "NATIVE" in method.attrs:
                # the target of the call is a native function
                # => we need to setup a native call-site
                l.debug("Native invoke: %r", method)
                addr = self.project.simos.get_addr_of_native_method(method)
                if not addr:
                    # native function could not be found
                    # => skip invocation and continue execution linearly
                    return False
                invoke_state = self._setup_native_callsite(invoke_state, addr, method, args, ret_addr, ret_var)
            else:
                l.debug("Invoke: %r", method)
                self.setup_callsite(invoke_state, args, ret_addr, ret_var)
                addr = SootAddressDescriptor(method, 0, 0)
            # add invoke state as the successor and terminate execution
            # prematurely, since Soot does not guarantee that an invoke stmt
            # terminates a block
            successors.add_successor(invoke_state, addr, state.solver.true, "Ijk_Call")
            return True

        # add jmp exit
        elif s_stmt.has_jump_targets:
            for target, condition in s_stmt.jmp_targets_with_conditions:
                if not target:
                    target = self._get_next_linear_instruction(state, stmt_idx)
                l.debug("Possible jump: %s -> %s", state._ip, target)
                successors.add_successor(state.copy(), target, condition, "Ijk_Boring")
            return True

        # add return exit
        elif isinstance(s_stmt, (SimSootStmt_Return, SimSootStmt_ReturnVoid)):
            l.debug("Return exit")
            self._add_return_exit(state, successors, s_stmt.return_value)
            return True

        # go on linearly
        else:
            return False

    @classmethod
    def _add_return_exit(cls, state, successors, return_val=None):
        ret_state = state.copy()
        cls.prepare_return_state(ret_state, return_val)
        successors.add_successor(ret_state, state.callstack.ret_addr, ret_state.solver.true, "Ijk_Ret")
        successors.processed = True

    def _get_sim_procedure(self, addr):
        # Delayed import
        from ...procedures import SIM_PROCEDURES

        if addr in self.project._sim_procedures:
            return self.project._sim_procedures[addr]

        method = addr.method
        class_name = method.class_name
        method_prototype = "{}({})".format(method.name, ",".join(method.params))

        if class_name in SIM_PROCEDURES and method_prototype in SIM_PROCEDURES[class_name]:
            procedure_cls = SIM_PROCEDURES[class_name][method_prototype]
        else:
            return None

        # Lazy-initialize it
        proc = procedure_cls(project=self.project)
        self.project._sim_procedures[addr] = proc

        return proc

    def get_unconstrained_simprocedure(self):
        # Delayed import
        from ...procedures import SIM_PROCEDURES

        # TODO: fix method prototype
        procedure_cls = SIM_PROCEDURES["angr.unconstrained"]["unconstrained()"]

        # Lazy-initialize it
        proc = procedure_cls(project=self.project)

        return proc

    @staticmethod
    def _is_method_beginning(addr):
        return addr.block_idx == 0 and addr.stmt_idx == 0

    @staticmethod
    def _get_next_linear_instruction(state, stmt_idx):
        addr = state.addr.copy()
        addr.stmt_idx = stmt_idx
        method = state.regs._ip_binary.get_soot_method(addr.method)
        current_bb = method.blocks[addr.block_idx]
        new_stmt_idx = addr.stmt_idx + 1
        if new_stmt_idx < len(current_bb.statements):
            return SootAddressDescriptor(addr.method, addr.block_idx, new_stmt_idx)
        else:
            new_bb_idx = addr.block_idx + 1
            if new_bb_idx < len(method.blocks):
                return SootAddressDescriptor(addr.method, new_bb_idx, 0)
            else:
                l.warning(
                    "falling into a non existing bb: %d in %s",
                    new_bb_idx,
                    SootMethodDescriptor.from_soot_method(method),
                )
                raise IncorrectLocationException()

    @classmethod
    def setup_callsite(cls, state, args, ret_addr, ret_var=None):
        # push new callstack frame
        state.callstack.push(state.callstack.copy())
        state.callstack.ret_addr = ret_addr
        state.callstack.invoke_return_variable = ret_var
        # push new memory stack frame
        state.javavm_memory.push_stack_frame()
        # setup arguments
        if args:
            cls.setup_arguments(state, list(args))

    @staticmethod
    def setup_arguments(state, args):
        # if available, store the 'this' reference
        if len(args) > 0 and args[0].is_this_ref:
            this_ref = args.pop(0)
            local = SimSootValue_Local("this", this_ref.type)
            state.javavm_memory.store(local, this_ref.value)
        # store all function arguments in memory
        for idx, arg in enumerate(args):
            param_ref = SimSootValue_ParamRef(idx, arg.type)
            state.javavm_memory.store(param_ref, arg.value)

    @staticmethod
    def prepare_return_state(state, ret_value=None):
        # pop callstack
        ret_var = state.callstack.invoke_return_variable
        procedure_data = state.callstack.procedure_data
        state.callstack.pop()

        # pass procedure data to the current callstack (if available)
        # => this should get removed by the corresponding sim procedure
        state.callstack.procedure_data = procedure_data

        # pop memory frame
        state.memory.pop_stack_frame()

        # save return value
        if ret_value is not None:
            l.debug("Assign %r := %r", ret_var, ret_value)
            if ret_var is not None:
                # usually the return value is read from the previous stack frame
                state.memory.store(ret_var, ret_value)
            else:
                # however if we call a method from outside (e.g. project.state_call),
                # no previous stack frame exist and the return variable is not set
                # => for this cases, we store the value in the registers, so it can
                #    still be accessed
                state.regs.invoke_return_value = ret_value

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
            exit_code = state.solver.BVV(exit_code, state.arch.bits)
        state.history.add_event("terminate", exit_code=exit_code)
        successors.add_successor(state, state.regs.ip, state.solver.true, "Ijk_Exit")
        successors.processed = True
        raise BlockTerminationNotice()

    #
    # JNI Native Interface
    #

    @staticmethod
    def prepare_native_return_state(native_state):
        """
        Hook target for native function call returns.

        Recovers and stores the return value from native memory and toggles the
        state, s.t. execution continues in the Soot engine.
        """

        javavm_simos = native_state.project.simos
        ret_state = native_state.copy()

        # set successor flags
        ret_state.regs._ip = ret_state.callstack.ret_addr
        ret_state.scratch.guard = ret_state.solver.true
        ret_state.history.jumpkind = "Ijk_Ret"

        # if available, lookup the return value in native memory
        ret_var = ret_state.callstack.invoke_return_variable
        if ret_var is not None:
            # get return symbol from native state
            native_cc = javavm_simos.get_native_cc()
            ret_symbol = (
                native_cc.return_val(javavm_simos.get_native_type(ret_var.type)).get_value(native_state).to_claripy()
            )
            # convert value to java type
            if ret_var.type in ArchSoot.primitive_types:
                # return value has a primitive type
                # => we need to manually cast the return value to the correct size, as this
                #    would be usually done by the java callee
                ret_value = javavm_simos.cast_primitive(ret_state, ret_symbol, to_type=ret_var.type)
            else:
                # return value has a reference type
                # => ret_symbol is a opaque ref
                # => lookup corresponding java reference
                ret_value = ret_state.jni_references.lookup(ret_symbol)

        else:
            ret_value = None

        # teardown return state
        SootMixin.prepare_return_state(ret_state, ret_value)

        # finally, delete all local references
        ret_state.jni_references.clear_local_references()

        return [ret_state]

    @classmethod
    def _setup_native_callsite(cls, state, native_addr, java_method, args, ret_addr, ret_var):
        # Step 1: setup java callsite, but w/o storing arguments in memory
        cls.setup_callsite(state, None, ret_addr, ret_var)

        # Step 2: add JNI specific arguments to *args list

        # get JNI environment pointer
        jni_env = SootArgument(state.project.simos.jni_env, "JNIEnv")

        # get reference to the current object or class
        if args and args[0].is_this_ref:
            # instance method call
            # => pass 'this' reference to native code
            ref = args.pop(0)
        else:
            # static method call
            # => pass 'class' reference to native code
            class_ = state.javavm_classloader.get_class(java_method.class_name, init_class=True)
            ref = SootArgument(class_, "Class")

        # add to args
        final_args = [jni_env, ref] + args

        # Step 3: generate C prototype from java_method
        voidp = parse_type("void*")
        arg_types = [voidp, voidp] + [state.project.simos.get_native_type(ty) for ty in java_method.params]
        ret_type = state.project.simos.get_native_type(java_method.ret)
        prototype = SimTypeFunction(args=arg_types, returnty=ret_type)

        # Step 3: create native invoke state
        return state.project.simos.state_call(
            native_addr, *final_args, base_state=state, prototype=prototype, ret_type=java_method.ret
        )
