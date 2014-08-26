# angr

A tool to get you VEXed!

## Dependencies

Things available from public repos:
- idalink (http://github.com/zardus/idalink)
- pyvex (http://github.com/zardus/pyvex)
- simuvex (https://git.seclab.cs.ucsb.edu/gitlab/yans/simuvex)
- cooldict (https://github.com/zardus/cooldict)

And other things from seclab repos available @
https://git.seclab.cs.ucsb.edu/gitlab/groups/angr

# Installation

The easiest way to install angr is to fetch and run angr_setup @
https://git.seclab.cs.ucsb.edu/gitlab/angr/angr_setup.


## Loader

Angr uses CLE to load binaries. CLE exports the abstraction of the memory of a
process in the form of a python dictionnary {address:data}. Loading and
relocating stripped binaries is supported.

# Usage

You can use angr as follows.

Loading a binary using IDA as a backend (force_ida set to True): 

	import angr
    p = angr.Project("path/to/binary_file", load_libs=False,
    use_sim_procedures=True, default_analysis_mode='symbolic', force_ida = True)

    You can optionally pecify the architecture of the binary (using its Simuvex
    name, see simuvex/simuvex/s_arch.py), and it will override the automatic
    detection, but it is not advised to do so unless you have a good reason.

Loading a binary using CLE's native backend (default):

    p = angr.Project("path/to/binary_file", use_sim_procedures=True,
    default_analysis_mode='symbolic')

In both cases, this will create a new project and load the binary into memory. 

For more internal details about loading, see CLE's documentation.

# Options to Project

    - load_libs:  this will also load all shared objects into memory (e.g., libc.so.6).

    - skip_libs: list of libraries to skip (from loading)

    - use_sim_procedures defines whether symbolic procedures should be used
      instead of complex (to execute symbolically) external library functions.
      Sim procedures are a replacement for library functions and are meant to
      reproduce the same symbolic behavior as the real library functions. (See
      simuvex documentation for more).

    - default_analysis_mode: symbolic, static or concrete are available.

    - exclude_sim_procedures: list of SimProcedures to exclude


# Examples

Now, to actually execute (symbolically) the first basic block from the entry
point of the program:

    run = p.sim_run(p.initial_exit(), mode='symbolic')

This returns a simuvex SimRun object (supporting refs() and exits()),
automatically choosing whether to create a SimIRSB or a SimProcedure.

Note that the term "exit" in Angr has a special meaning, and corresponds to the
beginning of a basic block, e.g., the entry point is an exit.

To build the CFG of the binary to analyze:

     cfg = p.construct_cfg()
        graph = cfg.get_graph()
        print "CFG nodes:\n---"
        print graph.nodes()
        print"---"



## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
