import simuvex

######################################
# fopen
######################################

def mode_to_flag(mode):
    #TODO improve this: handle mode = strings
    return {
        "r"  : simuvex.Flags.O_RDONLY, 
        "r+" : simuvex.Flags.O_RDWR,
        "w"  : simuvex.Flags.O_WRTONLY | simuvex.Flags.O_CREAT,
        "w+" : simuvex.Flags.O_RDWR | simuvex.Flags.O_CREAT,
        "a"  : simuvex.Flags.O_WRTONLY | simuvex.Flags.O_CREAT | simuvex.O_APPEND,
        "a+" : simuvex.Flags.O_RDWR | simuvex.Flags.O_CREAT | simuvex.O_APPEND
        }[mode]

class fopen(simuvex.SimProcedure):
	def __init__(self):
		# TODO: Symbolic path and errors
		plugin = self.state.get_plugin('posix')
		path = self.get_arg_value(0)
		mode = self.get_arg_value(1)                
                
                flags = mode_to_flag(mode.expr)
                fd = plugin.open(path.expr, flags)
                #TODO: handle append
                file_ptr = plugin.get_file(fd)
		self.exit_return(simuvex.SimValue(file_ptr).expr)
