import angr

######################################
# htons (yes, really)
######################################


class htons(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, to_convert):
        if self.state.arch.memory_endness == "Iend_LE":
            return to_convert[15:0].reversed.zero_extend(len(to_convert) - 16)
        else:
            return to_convert
