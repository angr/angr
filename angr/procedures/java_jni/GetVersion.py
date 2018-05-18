from angr import SimProcedure

class GetVersion(SimProcedure):

    def run(self):
        # return JNI version 1.8
        return 0x00010008