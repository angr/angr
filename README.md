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

Angr lets you choose between two loaders : CLE and IDA:

    - CLE loads ELF binaries and their dependencies and performs relocations.
      The addresses obtained using CLE are the same as if you run the binary
      into qemu-{arch} (e.g., qemu-x86_64) as provided by the qemu-user
      package. Loading and relocating stripped binaries is supported.

    - IDA loads the binary, and optionaly its dependencies. Relocations are
      performed by Angr at arbitrary addresses. Loading of stripped binaries is
      supported by IDA, but relocation of stripped binaries is not supported by
      the framework in this case.

## Usage examples

You can use angr as follows.

Loading a binary using IDA:

	import angr
    p = angr.Project("path/to/binary_file", load_libs=False,
    use_sim_procedures=True, default_analysis_mode='symbolic')

Loading a binary using CLE:

    p = angr.Project("path/to/binary_file", use_sim_procedures=True,
    default_analysis_mode='symbolic')

in other words, this is done by adding "use_cle=True" to the parameters of
Project. 


In both cases, this will create a new project and load the binary into memory.

    - load_libs: 

        -IDA: defines whether the shared libraries against which the binary was
        linked should also be loaded (e.g. libc6). Libraries have to be in the
        same directory as the binary to analyze. Note that the binary cannot be
        opened simultaneously by seveal instances of IDA, you will have to make
        copies.
      
        -CLE: this switch has no effect. It will always load external
        libraries. Libraries can be anywhere in the system as long as they
        reside in a standard location or are reachable from LD_LIBRARY_PATH.
        Binaries can safely be opened by multiple instances of CLE or other
        programs.  At the moment, CLE will fail if it cannot load shared
        libraries. TODO: the load_libs switch should make loading the libs
        optional or mandatory (i.e respectively warning or exception if the
        libs are not found).


    - use_sim_procedures defines whether symbolic procedures should be used
      instead of complex (to execute symbolically) external library functions.
      Sim procedures are a replacement for library functions and are meant to
      reproduce the same symbolic behavior as the real library functions. (See
      simuvex documentation for more).

    - default_analysis_mode: symbolic, static or concrete are available.


Now, to actually execute (symbolically) the first basic block from the entry
point of the program:

    run = p.sim_run(p.initial_exit(), mode='symbolic')

This returns a simuvex SimRun object (supporting refs() and exits()),
automatically choosing whether to create a SimIRSB or a SimProcedure.

Note that the term "exit" in Angr has a special meaning, and corresponds to the
beginning of a basic block, e.g., the entry point is an exit.


## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
