# angr

A tool to get you VEXed!

## Dependencies

- idalink (http://github.com/zardus/idalink)
- pyvex (http://github.com/zardus/pyvex)
- simuvex (https://git.seclab.cs.ucsb.edu/gitlab/yans/simuvex)
- cooldict (https://github.com/zardus/cooldict)

## Usage

First, a directory needs to be created with the binary to analyze and any dependencies (libraries) that'll be analyzed along with it:

	mkdir project
	cp some_binary project/

Here is a sample Angr session for your convenience:

	import angr

	p = angr.Project("project/some_binary", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True)
	TODO: expand!


Something like that.

## Resources

Some interesting resources.

- http://osll.spb.ru/projects/llvm
- https://github.com/bitblaze-fuzzball/fuzzball/blob/master/libasmir/src/vex/Notes
