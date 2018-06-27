
import logging

from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootAddressTerminator, SootClassDescriptor,
                                SootMethodDescriptor)
from cle import CLEError

from ... import sim_options as o
from ...errors import SimEngineError, SimTranslationError
from ...sim_type import SimTypeReg
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..engine import SimEngine
from .exceptions import BlockTerminationNotice, IncorrectLocationException
from .expressions import (SimSootExpr_SpecialInvoke, SimSootExpr_VirtualInvoke,
                          translate_expr)
from .statements import (SimSootStmt_Return, SimSootStmt_ReturnVoid,
                         translate_stmt)
from .values import (SimSootValue_Local, SimSootValue_ParamRef,
                     SimSootValue_ThisRef, translate_value)

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

        method, stmt_idx = addr.method, addr.stmt_idx

        try:
            method = the_binary.get_method(method)
        except CLEError as ex:
            raise SimTranslationError("CLE error: " + ex.message)

        if stmt_idx is None:
            return method.blocks[0] if method.blocks else None
        else:
            #try:
            #    _, block = method.block_by_label.floor_item(stmt_idx)
            #except KeyError:
            #    return None
            #return block
            # TODO: Re-enable the above code once bintrees are used


            # FIXME: stmt_idx does not index from the start of the method but from the start
            #        of the block therefore it always returns the block with label 0 indipendently
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

    def _check(self, state, *args, **kwargs):
        return isinstance(state._ip, SootAddressDescriptor)

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
            method = binary.get_soot_method(addr.method)
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
                return
            if method is not None:
                next_addr = self._get_next_linear_instruction(state, stmt_idx)
                l.debug("Advancing execution linearly to %s" % next_addr)
                if next_addr is not None:
                    successors.add_successor(state.copy(), next_addr, state.se.true, 'Ijk_Boring')

    def _handle_statement(self, state, successors, stmt_idx, stmt):

        # reset state registers
        state.scratch.jump = False
        state.scratch.jump_targets_with_conditions = None
        state.scratch.invoke = False
        state.scratch.invoke_expr = None
        state.scratch.invoke_return_target = None
        state.scratch.invoke_return_variable = None

        try:
            l.info("Executing statement %s [%s]", stmt, state.addr)
            s_stmt = translate_stmt(stmt, state)
        except SimEngineError as e:
            l.error("Skipping statement: " + str(e))
            return

        if state.scratch.invoke:
            l.debug("Invoke exit: %r" % state.scratch.invoke_target)
            invoke_state = state.copy()
            ret_addr = self._get_next_linear_instruction(state, stmt_idx)
            # load arguments from memory
            args = self._get_args(invoke_state, invoke_state.scratch.invoke_expr)
            # setup callsite
            invoke_target = state.scratch.invoke_target
            if 'NATIVE' in invoke_target.attrs:
                # the target of the call is a native function
                # => we need to setup a native call-site
                l.debug("Invoke has a native target.")
                invoke_addr = self.project.simos.get_addr_of_native_method(invoke_target)
                invoke_state = self._setup_native_callsite(ret_addr, args, invoke_addr, 
                                                           invoke_state, invoke_target)
            else:
                self.setup_callsite(invoke_state, ret_addr, args)
                invoke_addr = SootAddressDescriptor(invoke_target, 0, 0)
            # add invoke state as a successor and terminate execution prematurely, because 
            # Soot does not guarantee that an invoke terminates a block
            successors.add_successor(invoke_state, invoke_addr, state.se.true, 'Ijk_Call', )
            return True

        elif state.scratch.jump:
            for target, condition in state.scratch.jump_targets_with_conditions:
                if target is None:
                    computed_target = self._get_next_linear_instruction(state, stmt_idx)
                else:
                    computed_target = target
                l.debug("Possible jump: %s -> %s" % (state._ip, computed_target))
                successors.add_successor(state.copy(), computed_target, condition, 'Ijk_Boring')
            return True

        elif isinstance(s_stmt, (SimSootStmt_Return, SimSootStmt_ReturnVoid)):
            l.debug("Return exit") 
            ret_state = state.copy()
            return_val = s_stmt.return_value if type(s_stmt) is SimSootStmt_Return else None
            self.prepare_return_state(ret_state, return_val)
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
                l.warning("falling into a non existing bb: %d in %s" %
                          (new_bb_idx, SootMethodDescriptor.from_soot_method(method)))
                raise IncorrectLocationException()

    @staticmethod
    def setup_callsite(state, ret_addr, args):
        # push new callstack frame
        state.callstack.push(state.callstack.copy())
        state.callstack.ret_addr = ret_addr
        state.callstack.invoke_return_variable = state.scratch.invoke_return_variable
        # push new memory stack frame
        state.javavm_memory.push_stack_frame()
        # setup arguments
        if args:
            # if available, store the 'this' reference
            this_ref, this_ref_type = args.pop(0)
            if this_ref != None:
                local = SimSootValue_Local('this', this_ref_type)
                state.javavm_memory.store(local, this_ref)
            # store all function arguments in memory
            for idx, (value, value_type) in enumerate(args):
                param_ref = SimSootValue_ParamRef(idx, value_type)
                state.javavm_memory.store(param_ref, value)

    @staticmethod
    def _get_args(state, invoke_expr):
        # for instance method calls, get the "this" reference
        is_instance_method = hasattr(invoke_expr, 'base')
        if is_instance_method:
            this_ref = state.memory.load(translate_value(invoke_expr.base, state))
        else:
            this_ref = None
        this_ref_type = this_ref.type if this_ref else None
        args = [ (this_ref, this_ref_type) ]
        # translate and load all function arguments
        for arg in invoke_expr.args:
            arg_cls_name = arg.__class__.__name__
            if "Constant" not in arg_cls_name:
                arg_value = state.memory.load(translate_value(arg, state))
            else:
                arg_value = translate_expr(arg, state).expr
            args += [ (arg_value, arg.type) ]
        return args

    @staticmethod
    def prepare_return_state(state, ret_value=None):
        """
        Prepare the state for the return site.

        :param state:       The state to prepare for returning.
        :param ret_value:   The value to return from the current method.
        :return:            None
        """
        ret_var = state.callstack.invoke_return_variable
        procedure_data = state.callstack.procedure_data

        # pop callstack and memory frame
        state.callstack.pop()
        state.memory.pop_stack_frame()
        
        # pass procedure data to the current callstack (if available)
        # => this should get removed by the corresponding sim procedure
        state.callstack.procedure_data = procedure_data

        # save return value
        if ret_value is not None:
            l.debug("Assigning %r to return variable %r" % (ret_value, ret_var))
            if ret_var is not None:
                # usually the return value is read from the previous stack frame
                state.memory.store(ret_var, ret_value)
            else:
                # however if we call a method from outside (e.g. project.state_call),
                # no previous stack frame exist and no return variable is set
                # => for this cases, we store the value in the registers, so can
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
            exit_code = state.se.BVV(exit_code, state.arch.bits)
        state.history.add_event('terminate', exit_code=exit_code)
        successors.add_successor(state, state.regs.ip, state.se.true, 'Ijk_Exit')
        successors.processed = True
        raise BlockTerminationNotice()

    #
    # JNI Native Interface
    #

    @staticmethod
    def prepare_native_return_state(native_state):
        """
        Hook target for native function call returns. Recovers and store the 
        return value from native memory and toggles the state, s.t. execution
        continues in the Soot engine.
        """

        javavm_simos = native_state.project.simos
        ret_state = native_state.copy()

        # set successor flags
        ret_state.regs._ip = ret_state.callstack.ret_addr
        ret_state.scratch.guard = ret_state.se.true
        ret_state.history.jumpkind = 'Ijk_Ret'
        
        # if available, lookup the return value in native memory
        ret_var = ret_state.callstack.invoke_return_variable
        if ret_var is not None:
            # get return symbol from native state
            native_cc = javavm_simos.get_native_cc()
            ret_symbol = native_cc.get_return_val(native_state).to_claripy()
            # convert value to java type 
            if ret_var.type in ArchSoot.primitive_types:
                # return value has a primitive type
                # => we need to manually cast the return value to the correct size, as this
                #    would be usually done by the java callee
                ret_value = javavm_simos.cast_primitive(ret_symbol, to_type=ret_var.type)
            else:
                # return value has a reference type
                # => ret_symbol is a opaque ref 
                # => lookup corresponding java reference
                ret_value = ret_state.jni_references.lookup(ret_symbol)

        else:
            ret_value = None

        # teardown return state
        SimEngineSoot.prepare_return_state(ret_state, ret_value)
        
        # finally, delete all local references
        ret_state.jni_references.clear_local_references()

        return [ret_state]

    @classmethod
    def _setup_native_callsite(cls, ret_addr, args, invoke_addr, invoke_state, invoke_target):

        # Step 1: setup java callsite, but w/o storing the arguments memory
        cls.setup_callsite(invoke_state, ret_addr, args=None)

        # Step 2: setup native arguments
        javavm_simos = invoke_state.project.simos
        native_args = []

        # JNI enviroment pointer
        jni_env = javavm_simos.jni_env
        jni_env_type = javavm_simos.get_native_type('reference')
        native_args += [(jni_env, jni_env_type)]

        # handle to the current object or class
        this, _ = args.pop(0)
        if this != None:
            # instance method call => pass 'this' reference to native code
            this_ref = invoke_state.jni_references.create_new_reference(java_ref=this)
            this_ref_type = javavm_simos.get_native_type('reference')
            native_args += [(this_ref, this_ref_type)]

        else:
            # static method call => pass 'class' reference to native code
            class_name = state.scratch.invoke_expr.class_name
            class_ = invoke_state.javavm_classloader.get_class(class_name, init_class=True)
            class_ref = invoke_state.jni_references.create_new_reference(java_ref=class_)
            class_ref_type = javavm_simos.get_native_type('reference')
            native_args += [(class_ref, class_ref_type)]

        # function arguments
        for arg_value, arg_type in args:
            
            if arg_type in ['float', 'double']:
                # argument has a primitive floating-point type
                raise NotImplementedError('No support for native floating-point arguments.')

            elif arg_type in ArchSoot.primitive_types:
                # argument has a primitive integral type
                native_arg_value = arg_value
                native_arg_type = javavm_simos.get_native_type(arg_type)

            else:
                # argument has a relative type
                # => we map the Java reference to an opaque reference, which then can be used by the
                #    native code to access the Java object through the JNI interface.
                opaque_ref = invoke_state.jni_references.create_new_reference(java_ref=arg_value)
                native_arg_value = opaque_ref
                native_arg_type = javavm_simos.get_native_type('reference')

            native_args += [(native_arg_value, native_arg_type)]

        # Step 3: set return type
        ret_type = javavm_simos.get_native_type(invoke_target.ret)
        
        # Step 4: create native invoke state
        invoke_state = javavm_simos.state_call(invoke_addr, *native_args, 
                                               base_state=invoke_state, 
                                               ret_type=ret_type)

        return invoke_state
