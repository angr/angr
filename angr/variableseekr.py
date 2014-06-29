import itertools

from simuvex import SimIRSB, SimProcedure
from simuvex.s_ref import SimMemRead, SimMemWrite

class Variable(object):
    def __init__(self, idx, size, assignment_addr):
        self._idx = idx
        self._assignment_addr = assignment_addr
        self._size = size

class StackVariable(Variable):
    '''
    _offset refers to the offset from stack base
    '''
    def __init__(self, idx, size, assignment_addr, offset):
        Variable.__init__(self, idx, size, assignment_addr)
        self._offset = offset

    @property
    def idx(self):
        return self._idx

    @property
    def offset(self):
        return self._offset

    def __repr__(self):
        s = 'StackVar %d [%s|%d] <ins 0x%08x>' % (self._idx, hex(self._offset), self._size, self._assignment_addr)
        return s

class VariableSeekr(object):
    def __init__(self, cfg):
        self._cfg = cfg

        self._do_work()

    def _do_work(self):
        function_manager = self._cfg.get_function_manager()
        functions = function_manager.functions

        for func_addr, func in functions.items():
            var_idx = itertools.count()
            variables = []
            print func

            initial_run = self._cfg.get_any_irsb(func_addr)
            run_stack = [initial_run]
            processed_runs = set()
            processed_runs.add(initial_run)

            sp_value = initial_run.initial_state.sp_value()
            assert(not sp_value.is_symbolic())
            concrete_sp = sp_value.any()

            while len(run_stack) > 0:
                current_run = run_stack.pop()

                if isinstance(current_run, SimIRSB):
                    irsb = current_run
                    for stmt in irsb.statements:
                        if len(stmt.refs) > 0:
                            real_ref = stmt.refs[-1]
                            if type(real_ref) == SimMemWrite:
                                addr = real_ref.addr
                                if not addr.is_symbolic():
                                    concrete_addr = addr.any()
                                    offset = concrete_addr - concrete_sp
                                    stack_var = StackVariable(var_idx.next(), real_ref.size, stmt.imark.addr, offset)
                                    variables.append(stack_var)
                        for ref in stmt.refs:
                            if type(ref) == SimMemRead:
                                addr = ref.addr
                                if not addr.is_symbolic():
                                    concrete_addr = addr.any()
                elif isinstance(current_run, SimProcedure):
                    pass

                # Successors
                successors = self._cfg.get_all_successors(current_run)
                for suc in successors:
                    if suc not in processed_runs and suc.addr in func.basic_blocks:
                        run_stack.append(suc)
                        processed_runs.add(suc)

            print variables
