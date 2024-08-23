from __future__ import annotations
import angr


class _dl_rtld_lock_recursive(angr.SimProcedure):
    # pylint: disable=arguments-differ, unused-argument
    def run(self, lock):
        # For future reference:
        # ++((pthread_mutex_t *)(lock))->__data.__count;
        return


class _dl_rtld_unlock_recursive(angr.SimProcedure):
    def run(self):
        return
