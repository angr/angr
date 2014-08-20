# angr

A tool to get you VEXed!

## Dependencies

- idalink (http://github.com/zardus/idalink)
- pyvex (http://github.com/zardus/pyvex)
- simuvex (https://git.seclab.cs.ucsb.edu/gitlab/yans/simuvex)
- cooldict (https://github.com/zardus/cooldict)

## Usage examples

You can use angr as follows:

    import angr
    p = angr.Project("path/to/binary_file", load_libs=False, use_sim_procedures=True, default_analysis_mode='symbolic')

This will create a new project and load the binary into memory.

    - load_libs defines whether the shared libraries against which the binary
      was linked should also be loaded (e.g. libc6).

    - use_sim_procedures defines whether symbolic procedures should be used
      instead of complex (to execute symbolically) external library functions.
      Sim procedures are a replacement for library functions and are meant to
      reproduce the same symbolic behavior as the real library functions. (See
      simuvex documentation for more).

    - default_analysis_mode: symbolic, static or concrete are available.

Now, to actually execute (symbolically) the first basic block from the entry point of the program:

    run = p.sim_run(p.entry, mode='symbolic')

This returns a simuvex SimRun object (supporting refs() and exits()), automatically choosing whether to create a SimIRSB or a SimProcedure.

Other usage examples are:

### Slicing

Angr can give you very granular program slices, if you want them. For example:

	import angr
	p = angr.Project("angr/tests/fauxware/fauxware-amd64", load_libs=False, default_analysis_mode="symbolic", use_sim_procedures=True)

	# make a slice to 0x4006ED
	a = p.slice_to(0x4006ED)

	# run the slice, finding ways to get to 0x4006ED
	e = angr.surveyors.Slicecutor(p, a, p.initial_exit(), targets=[0x4006ED]).run() # run the slice

## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
