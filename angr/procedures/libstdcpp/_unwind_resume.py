import angr

######################################
# __unwind_resume
######################################


class _Unwind_Resume(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self):
        pass
