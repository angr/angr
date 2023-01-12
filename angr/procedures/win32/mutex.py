import angr


class CreateMutexA(angr.SimProcedure):
    def run(self, lpMutexAttributes, bInitialOwner, lpName):
        return 1


class CreateMutexEx(CreateMutexA):
    pass
