import angr

class InitializeCriticalSectionAndSpinCount(angr.SimProcedure):
    def run(self, lpCriticalSection, dwSpinCount):
        return 1

class InitializeCriticalSectionEx(angr.SimProcedure):
    def run(self, lpCriticalSection, dwSpinCount, Flags):
        return 1
