import itertools
import logging

from simuvex import SimIRSB, SimProcedure
from simuvex.s_ref import SimMemRead, SimMemWrite, SimRegRead, SimRegWrite

from .regmap import RegisterMap

l = logging.getLogger(name="angr.variableseekr")

class Variable(object):
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, custom_name=None):
        self._idx = idx
        self._irsb_addr = irsb_addr
        self._ins_addr = ins_addr
        self._stmt_id = stmt_id
        self._size = size
        self._custom_name = custom_name

    @property
    def irsb_addr(self):
        return self._irsb_addr

    @property
    def stmt_id(self):
        return self._stmt_id

    @property
    def name(self):
        return "var_%d" % self._idx

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
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, offset, custom_name=None):
        Variable.__init__(self, idx, size, irsb_addr, stmt_id, ins_addr, custom_name)
        self._offset = offset

    @property
    def name(self):
        return 'reg_var_%d' % self._idx

class StackVariable(Variable):
    '''
    _offset refers to the offset from stack base
    '''
    def __init__(self, idx, size, irsb_addr, stmt_id, ins_addr, offset):
        Variable.__init__(self, idx, size, irsb_addr, stmt_id, ins_addr)
        self._offset = offset

    @property
    def idx(self):
        return self._idx

    @property
    def offset(self):
        return self._offset

    def detail_str(self):
        s = 'StackVar %d [%s|%d] <ins 0x%08x>' % (self._idx, hex(self._offset), self._size, self._ins_addr)
        return s

class VariableManager(object):
    def __init__(self, func_addr):
        self._func_addr = func_addr
        self._var_list = []
        self._stmt_to_var_map = {} # Maps a tuple of (irsb_addr, stmt_id) to the corresponding variable
        self._stack_variable_map = {} # Maps stack offset to a stack variable

    def add(self, var):
        self._var_list.append(var)

        tpl = (var.irsb_addr, var.stmt_id)
        self._stmt_to_var_map[tpl] = var
        if isinstance(var, StackVariable):
            self._stack_variable_map[var.offset] = var

    def get(self, irsb_addr, stmt_id):
        tpl = (irsb_addr, stmt_id)
        if tpl in self._stmt_to_var_map:
            return self._stmt_to_var_map[tpl]
        else:
            return None

    def get_stack_variable(self, offset):
        if offset in self._stack_variable_map:
            return self._stack_variable_map[offset]
        else:
            return None

    @property
    def variables(self):
        return self._var_list

STACK_SIZE = 0x100000

class VariableSeekr(object):
    def __init__(self, cfg):
        self._cfg = cfg

        self._variable_managers = {}

        self._do_work()

    def _do_work(self):
        function_manager = self._cfg.get_function_manager()
        functions = function_manager.functions

        for func_addr, func in functions.items():
            var_idx = itertools.count()
            variable_manager = VariableManager(func_addr)

            initial_run = self._cfg.get_any_irsb(func_addr)
            run_stack = [initial_run]
            processed_runs = set()
            processed_runs.add(initial_run)

            sp_value = initial_run.initial_state.sp_value()
            assert(not sp_value.is_symbolic())
            concrete_sp = sp_value.any()

            regmap = RegisterMap()

            while len(run_stack) > 0:
                current_run = run_stack.pop()

                if isinstance(current_run, SimIRSB):
                    irsb = current_run
                    stmt_id = 0
                    for stmt_id in range(len(irsb.statements)):
                        stmt = irsb.statements[stmt_id]
                        for ref in stmt.refs:
                            handler_name = '_handle_reference_%s' % type(ref).__name__
                            if hasattr(self, handler_name):
                                getattr(self, handler_name)(func, var_idx, variable_manager, regmap, irsb, stmt.imark.addr, stmt_id, concrete_sp, ref)
                elif isinstance(current_run, SimProcedure):
                    simproc = current_run
                    for ref in simproc.refs():
                        handler_name = '_handle_reference_%s' % type(ref).__name__
                        if hasattr(self, handler_name):
                            getattr(self, handler_name)(func, var_idx, variable_manager, regmap, simproc, simproc.addr, -1, concrete_sp, ref)

                # Successors
                successors = self._cfg.get_successors(current_run, excluding_fakeret=False)
                for suc in successors:
                    if suc not in processed_runs and suc.addr in func.basic_blocks:
                        run_stack.append(suc)
                        processed_runs.add(suc)

            self._variable_managers[func_addr] = variable_manager

    def _handle_reference_SimMemRead(self, func, var_idx, variable_manager, regmap, current_run, ins_addr, stmt_id, concrete_sp, ref):
        addr = ref.addr
        if not addr.is_symbolic():
            concrete_addr = addr.any()
            offset = concrete_addr - concrete_sp
            if abs(offset) < STACK_SIZE:
                # Let's see if this variable already exists
                existing_var = variable_manager.get_stack_variable(offset)
                if existing_var is not None:
                    # We found it!
                    pass
                else:
                    # This is a variable that is read before created/written
                    stack_var = StackVariable(var_idx.next(), ref.size, current_run.addr, stmt_id, ins_addr, offset)
                    variable_manager.add(stack_var)
                    if offset > 0:
                        func.add_argument_stack_variable(offset)

    def _handle_reference_SimMemWrite(self, func, var_idx, variable_manager, regmap, current_run, ins_addr, stmt_id, concrete_sp, ref):
        addr = ref.addr
        if not addr.is_symbolic():
            concrete_addr = addr.any()
            offset = concrete_addr - concrete_sp
            if abs(offset) < STACK_SIZE:
                # As this is a write, it must be a new
                # variable (although it might be
                # overlapping with another variable).
                stack_var = StackVariable(var_idx.next(), ref.size, current_run.addr, stmt_id, ins_addr, offset)
                variable_manager.add(stack_var)

    def _handle_reference_SimRegRead(self, func, var_idx, variable_manager, regmap, current_run, ins_addr, stmt_id, concrete_sp, ref):
        if not regmap.contains(ref.offset):
            # The register has never been written before
            func.add_argument_register(ref.offset)

    def _handle_reference_SimRegWrite(self, func, var_idx, variable_manager, regmap, current_run, ins_addr, stmt_id, concrete_sp, ref):
        regmap.assign(ref.offset, 1)

    def get_variable_manager(self, func_addr):
        if func_addr in self._variable_managers:
            return self._variable_managers[func_addr]
        else:
            return None
