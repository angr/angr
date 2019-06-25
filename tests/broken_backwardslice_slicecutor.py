import os
import angr
import nose

import logging
l = logging.getLogger(name=__name__)

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
arches = ['x86_64', 'i386']

def main():
	test_backwardslice_slicecutor()

def test_backwardslice_slicecutor():
	for arch in arches:
		run_backwardslice_slicecutor(arch)

def run_backwardslice_slicecutor(arch):
	test_file = os.path.join(test_location, arch, 'test_backwardslice_slicecutor')
	proj = angr.Project(test_file, auto_load_libs=False)
	cfg = proj.analyses.CFGEmulated(context_sensitivity_level=2, keep_state=True, normalize=True, state_add_options=angr.sim_options.refs)

	main_func = cfg.functions.function(name='main')
	main_node = cfg.model.get_any_node(addr=main_func.addr)
	target_func = cfg.functions.function(name='f_target')
	target_call_site = get_call_site(main_func, target_func)
	target_call_node = cfg.model.get_any_node(addr=target_call_site)
	target_call_block = target_call_node.block

	# Backward slice
	cdg = proj.analyses.CDG(cfg, start=main_func.addr)
	ddg = proj.analyses.DDG(cfg, start=main_func.addr)
	bs_targets = []
	for stmt_idx in range(len(target_call_block.vex.statements)):
		bs_targets.append((target_call_node, stmt_idx)) # Every statement in the call site
	bs = proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=bs_targets)
	acfg = bs.annotated_cfg()
	#print(bs.dbg_repr())

	# Symbolic execution
	start_state = proj.factory.blank_state(addr=main_func.addr)
	# Confirm we are actually starting in a state with whitelisted statements.
	if not (acfg.get_whitelisted_statements(addr=start_state.addr) == None or len(acfg.get_whitelisted_statements(addr=start_state.addr)) > 0):
		l.error("Attempting to start the Slicecutor in a block that's not part of the slice. Preemptively stopping test case.")
		return
		
	simgr = proj.factory.simgr(start_state)
	slicecutor = angr.exploration_techniques.Slicecutor(acfg)
	simgr.use_technique(slicecutor)
	simgr.explore(find=target_call_site)
	# Confirm all stashes have been emptied due to error
	if all([len(stash) == 0 for stash in simgr.stashes.values()]):
		for errored in simgr.errored:
			error = errored.error
			nose.tools.assert_not_regex(str(error), r'VEX temp variable \d+ does not exist.', msg="Occurred at: block: 0x{:x}, stmt_idx: {}".format(error.bbl_addr, error.stmt_idx))			
		

def get_call_site(caller_func, callee_func):
    for call_site_addr in caller_func.get_call_sites():
    	if caller_func.get_call_target(call_site_addr) == callee_func.addr:
    		return call_site_addr
    return None

if __name__ == "__main__":
	main()
