from simuvex import SimIRSB, SimProcedure
from simuvex.s_ref import SimMemRead, SimMemWrite

class VariableSeekr(object):
    def __init__(self, cfg):
        self._cfg = cfg

        self._do_work()

    def _do_work(self):
        function_manager = self._cfg.get_function_manager()
        functions = function_manager.functions

        for func_addr, func in functions.items():
            print func

            initial_run = self._cfg.get_any_irsb(func_addr)
            run_stack = [initial_run]
            processed_runs = set()
            processed_runs.add(initial_run)

            while len(run_stack) > 0:
                current_run = run_stack.pop()

                if isinstance(current_run, SimIRSB):
                    irsb = current_run
                    for stmt in irsb.statements:
                        if len(stmt.refs) > 0:
                            real_ref = stmt.refs[-1]
                            if type(real_ref) == SimMemRead:
                                addr = real_ref.addr
                                if not addr.is_symbolic():
                                    concrete_addr = addr.any()
                                    print hex(concrete_addr)
                            elif type(real_ref) == SimMemWrite:
                                addr = real_ref.addr
                                if not addr.is_symbolic():
                                    concrete_addr = addr.any()
                                    stmt.stmt.pp()
                                    print ""
                                    print real_ref
                                    print "%s, %d" % (hex(concrete_addr), real_ref.size)
                elif isinstance(current_run, SimProcedure):
                    pass

                # Successors
                successors = self._cfg.get_all_successors(current_run)
                for suc in successors:
                    if suc not in processed_runs:
                        run_stack.append(suc)
                        processed_runs.add(suc)
