import angr


class rewind(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):
        fseek = angr.SIM_PROCEDURES["libc"]["fseek"]
        self.inline_call(fseek, file_ptr, 0, 0)

        return None
