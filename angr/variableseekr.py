import itertools
import logging
from collections import defaultdict

from simuvex import SimIRSB, SimProcedure

l = logging.getLogger(name="angr.variableseekr")

class Variable(object):
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, custom_name=None, type_=None):
        self._idx = idx
        self._irsb_addr = irsb_addr
        self._ins_addr = ins_addr
        self._stmt_id = stmt_id
        self._size = size
        self._custom_name = custom_name
        self._type = type_

        # A model used to model the possible value range of this variable
        self._model = None

    @property
    def irsb_addr(self):
        return self._irsb_addr

    @property
    def stmt_id(self):
        return self._stmt_id

    @property
    def name(self):
        return "var_%d" % self._idx

    @property
    def type(self):
        return self._type

    @property
    def decl(self):
        if self._type is not None:
            return "{} {}".format(self._type, self)
        else:
            return str(self)

    @property
    def model(self):
        return self._model

    @model.setter
    def model(self, value):
        self._model = value

    @property
    def upper_bound(self):
        if self._model is not None:
            return self._model.upper_bound
        else:
            return None

    @property
    def lower_bound(self):
        if self._model is not None:
            return self._model.lower_bound
        else:
            return None

    @property
    def stride(self):
        if self._model is not None:
            return self._model.stride
        else:
            return None

    def __repr__(self):
        if self._custom_name is not None:
            return self._custom_name
        else:
            return self.name

class DummyVariable(Variable):
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr):
        Variable.__init__(self, idx, size, irsb_addr, stmt_id, ins_addr)

    @property
    def name(self):
        return "dummy_var_%d" % self._idx

class RegisterVariable(Variable):
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, offset, custom_name=None, type_=None):
        Variable.__init__(self, idx, size, irsb_addr, stmt_id, ins_addr, custom_name, type_)
        self._offset = offset

    @property
    def name(self):
        return 'reg_var_%d' % self._idx

class StackVariable(Variable):
    '''
    _offset refers to the offset from stack base
    '''
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, offset, addr, type_=None):
        if type(size) not in [int, long]:
            import ipdb; ipdb.set_trace()
        Variable.__init__(self, idx, size, irsb_addr, stmt_id, ins_addr, type_)
        self._offset = offset
        self._addr = addr

    @property
    def idx(self):
        return self._idx

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    def detail_str(self):
        '''
        FIXME: This is a temporary fix for simuvex Issue #31
        '''
        if type(self._size) in [int, long]:
            s = 'StackVar %d [%s|%d] <irsb 0x%x, stmt %d> (%s-%s,%s)' % (self._idx, hex(self._offset), self._size, self._irsb_addr, self._stmt_id, self.lower_bound, self.upper_bound, self.stride)
        else:
            s = 'StackVar %d [%s|%s] <irsb 0x%x, stmt %d> (%s-%s,%s)' % (self._idx, hex(self._offset), self._size, self._irsb_addr, self._stmt_id, self.lower_bound, self.upper_bound, self.stride)
        return s

class VariableManager(object):
    def __init__(self, func_addr):
        self._func_addr = func_addr
        self._var_list = []
        self._stmt_to_var_map = {} # Maps a tuple of (irsb_addr, stmt_id) to the corresponding variable
        self._stack_variable_map = defaultdict(dict) # Maps stack offset to a stack variable

    def add(self, var):
        self._var_list.append(var)

        tpl = (var.irsb_addr, var.stmt_id)
        self._stmt_to_var_map[tpl] = var
        if isinstance(var, StackVariable):
            self._stack_variable_map[var.offset][tpl] = var

    def add_ref(self, var, irsb_addr, stmt_id):
        tpl = (irsb_addr, stmt_id)
        self._stmt_to_var_map[tpl] = var

    def get(self, irsb_addr, stmt_id):
        tpl = (irsb_addr, stmt_id)
        if tpl in self._stmt_to_var_map:
            return self._stmt_to_var_map[tpl]
        else:
            return None

    def get_stack_variable(self, offset, irsb_addr, stmt_id):
        tpl = (irsb_addr, stmt_id)
        if offset in self._stack_variable_map and \
                tpl in self._stack_variable_map[offset]:
            return self._stack_variable_map[offset][tpl]
        else:
            return None

    def get_stack_variables(self, offset):
        if offset in self._stack_variable_map and \
                len(self._stack_variable_map[offset]):
            return self._stack_variable_map[offset].values()
        else:
            return None

    @property
    def variables(self):
        return self._var_list

class VariableSeekr(object):
    def __init__(self, project, cfg, vfg):
        self._cfg = cfg
        self._vfg = vfg
        self._project = project

        # A shortcut to arch
        self._arch = project.arch

        self._variable_managers = {}

    def construct(self, func_start=None):
        self._do_work(func_start)

    def _variable_manager(self, function_start):
        if function_start not in self._variable_managers:
            variable_manager = VariableManager(function_start)
            self._variable_managers[function_start] = variable_manager

            return variable_manager
        else:
            return self._variable_managers[function_start]

    def _do_work(self, func_start):
        function_manager = self._cfg.function_manager
        functions = function_manager.functions

        if func_start not in functions:
            raise AngrInvalidArgumentError('No such function exists in FunctionManager: function 0x%x.', func_start)

        func = functions[func_start]

        var_idx = itertools.count()


        initial_run = self._vfg.get_any_irsb(func_start) # FIXME: This is buggy

        if initial_run is None:
            raise AngrInvalidArgumentError('No such SimRun exists in VFG: 0x%x.', func_start)

        run_stack = [initial_run]
        processed_runs = set()
        processed_runs.add(initial_run)

        while len(run_stack) > 0:
            current_run = run_stack.pop()

            if isinstance(current_run, SimIRSB):
                irsb = current_run

                memory = irsb.exits()[0].state.memory
                events = memory.state.log.events_of_type('uninitialized')
                print events
                for _, region in memory.regions.iteritems():
                    if region.is_stack:
                        for tpl, aloc in region.alocs.items():
                            irsb_addr, stmt_id = tpl
                            variable_manager = self._variable_manager(region.related_function_addr)
                            if variable_manager.get_stack_variable(aloc.offset, irsb_addr, stmt_id) is None:
                                stack_var = StackVariable(var_idx.next(), aloc.size, irsb_addr, stmt_id, 0, aloc.offset, 0)
                                variable_manager.add(stack_var)

            elif isinstance(current_run, SimProcedure):
                pass
                # simproc = current_run
                # for ref in simproc.refs():
                #     handler_name = '_handle_reference_%s' % type(ref).__name__
                #     if hasattr(self, handler_name):
                #         getattr(self, handler_name)(func, var_idx,
                #                                     variable_manager,
                #                                     regmap,
                #                                     temp_var_map,
                #                                     simproc,
                #                                     simproc.addr, -1,
                #                                     concrete_sp, ref)

            # Successors
            successors = self._vfg.get_successors(current_run, excluding_fakeret=False)
            for suc in successors:
                if suc not in processed_runs and suc.addr in func.basic_blocks:
                    run_stack.append(suc)
                    processed_runs.add(suc)

        # Post-processing
        if func.bp_on_stack:
            # base pointer is pushed on the stack. To be consistent with IDA,
            # we wanna adjust the offset of each stack variable
            for var in variable_manager.variables:
                if isinstance(var, StackVariable):
                    var.offset += self._arch.bits / 8

    def _collect_tmp_deps(self, tmp_tuple, temp_var_map):
        '''
        Return all registers that a tmp relies on
        '''
        reg_deps = set()
        for tmp_dep in tmp_tuple:
            if tmp_dep in temp_var_map:
                reg_deps |= temp_var_map[tmp_dep]
        return reg_deps

    def _try_concretize(self, se, exp):
        '''
        FIXME: This ia a temporary fix for simuvex Issue #31
        '''
        if type(exp) in [int, long]:
            return exp
        else:
            # Try to concretize it
            if se.symbolic(exp):
                return exp
            else:
                return se.any_int(exp)


    def _handle_reference_SimMemRead(self, func, var_idx, variable_manager, regmap, temp_var_map, current_run, ins_addr, stmt_id, concrete_sp, ref):
        addr = ref.addr
        if not addr.symbolic:
            concrete_addr = current_run.initial_state.se.any_int(addr)
            offset = concrete_addr - concrete_sp
            if abs(offset) < STACK_SIZE:
                # Let's see if this variable already exists
                existing_var = variable_manager.get_stack_variable(offset)
                if existing_var is not None:
                    # We found it!
                    # Add a reference to that variable
                    variable_manager.add_ref(existing_var, current_run.addr, stmt_id)
                else:
                    # This is a variable that is read before created/written
                    l.debug("Stack variable %d has never been written before.", offset)
                    size_ = self._try_concretize(current_run.initial_state.se, ref.size)
                    stack_var = StackVariable(var_idx.next(), size_, current_run.addr, stmt_id, ins_addr, offset, concrete_addr)
                    variable_manager.add(stack_var)
                    if offset > 0:
                        func.add_argument_stack_variable(offset)

    def _handle_reference_SimTmpWrite(self, func, var_idx, variable_manager, regmap, temp_var_map, current_run, ins_addr, stmt_id, concrete_sp, ref):
        tmp_var_id = ref.tmp
        temp_var_map[tmp_var_id] = set(ref.data_reg_deps)
        for tmp_dep in ref.data_tmp_deps:
            if tmp_dep in temp_var_map:
                temp_var_map[tmp_var_id] |= temp_var_map[tmp_dep]

    def _handle_reference_SimMemWrite(self, func, var_idx, variable_manager, regmap, temp_var_map, current_run, ins_addr, stmt_id, concrete_sp, ref):
        addr = ref.addr

        if not addr.symbolic:
            concrete_addr = current_run.initial_state.se.any_int(addr)
            offset = concrete_addr - concrete_sp
            if abs(offset) < STACK_SIZE:
                # What will be written?
                # If the value is the stack pointer, we don't treat it as a variable.
                # Instead, we'll report this fact to func.
                reg_deps = self._collect_tmp_deps(ref.data_tmp_deps, temp_var_map)
                reg_deps |= set(ref.data_reg_deps)
                if len(reg_deps) == 1 and self._arch.bp_offset in reg_deps:
                    # Report to func
                    func.bp_on_stack = True
                    return

                # As this is a write, it must be a new
                # variable (although it might be
                # overlapping with another variable).
                size_ = self._try_concretize(current_run.initial_state.se, ref.size)
                stack_var = StackVariable(var_idx.next(), size_, current_run.addr, stmt_id, ins_addr, offset, concrete_addr)
                variable_manager.add(stack_var)

    def _handle_reference_SimRegRead(self, func, var_idx, variable_manager, regmap, temp_var_map, current_run, ins_addr, stmt_id, concrete_sp, ref):
        if ref.offset in [self._arch.sp_offset, self._arch.ip_offset]:
            # Ignore stack pointer
            return
        if not regmap.contains(ref.offset):
            # The register has never been written before
            func.add_argument_register(ref.offset)

    def _handle_reference_SimRegWrite(self, func, var_idx, variable_manager, regmap, temp_var_map, current_run, ins_addr, stmt_id, concrete_sp, ref):
        if ref.offset in [self._arch.sp_offset, self._arch.ip_offset]:
            # Ignore stack pointers and program counter
            return
        regmap.assign(ref.offset, 1)

    def get_variable_manager(self, func_addr):
        if func_addr in self._variable_managers:
            return self._variable_managers[func_addr]
        else:
            return None

from .errors import AngrInvalidArgumentError
