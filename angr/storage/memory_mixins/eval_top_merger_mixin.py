from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from angr.storage.memory_mixins.memory_mixin import MemoryMixin
import time
def cur_time():
    return time.perf_counter_ns() / 1000000
class EvalTopMergerMixin(MemoryMixin):
    """
    A memory mixin for merging values in memory to TOP.
    """

    def __init__(self, *args, top_func=None, **kwargs):
        self._top_func: Callable = top_func

        super().__init__(*args, **kwargs)

    @staticmethod
    def _state_global(state, key, default=None):
        try:
            return state.globals.get(key, default)
        except Exception:
            return default

    def _current_vpc_reg(self, all_states):
        if self._is_symbolizer_merge(all_states):
            return self._merge_point_vpc_reg(all_states)

        for state in reversed(list(all_states or [])):
            cur_vm_reg = self._state_global(state, 'cur_vm_reg')
            if cur_vm_reg is not None:
                return cur_vm_reg

        cur_vm_reg = self._state_global(self.state, 'cur_vm_reg')
        if cur_vm_reg is not None:
            return cur_vm_reg

        return self._merge_point_vpc_reg(all_states)

    def _is_symbolizer_merge(self, all_states):
        if self._state_global(self.state, 'is_symbolizer', False):
            return True

        for state in all_states or []:
            if self._state_global(state, 'is_symbolizer', False):
                return True

        return False

    def _merge_point_vpc_reg(self, all_states):
        block_id = self._current_block_id(all_states)
        if block_id is None:
            return None

        project = getattr(self.state, 'project', None)
        return getattr(project, 'vpc_reg_at_merge_points', {}).get(block_id, None)

    def _current_block_id(self, all_states):
        block_id = self._state_global(self.state, 'cur_block_id')
        if block_id is not None:
            return block_id

        for state in reversed(list(all_states or [])):
            block_id = self._state_global(state, 'cur_block_id')
            if block_id is not None:
                return block_id

        return None

    def _is_current_vpc_reg_merge(self, all_states, page_addr, offset, size, merged_size):
        if self.id != 'reg' or offset is None:
            return False

        merge_kind, _ = self._merge_point_kind(all_states)
        if merge_kind != "loop":
            return False

        cur_vm_reg = self._current_vpc_reg(all_states)
        if cur_vm_reg is None:
            return False

        reg_off, reg_size = cur_vm_reg
        loc_offsets = [offset]
        if page_addr is not None:
            loc_offsets.append(page_addr + offset)

        merge_size = size if size is not None else merged_size
        return reg_size == merge_size and any(loc_off == reg_off for loc_off in loc_offsets)

    def _latest_value_index(self, values, all_states):
        states = list(all_states or [])
        for idx in range(len(values) - 1, -1, -1):
            state = states[idx] if idx < len(states) else self.state
            try:
                state.partial_symbolic_constraint_solver.eval_one(values[idx][0])
                return idx
            except Exception:
                pass

        return len(values) - 1

    def _merge_point_kind(self, all_states):
        block_id = self._current_block_id(all_states)
        project = getattr(self.state, 'project', None)

        if block_id in getattr(project, 'loop_start_nodes', set()):
            return "loop", block_id

        if block_id is not None:
            return "non-loop", block_id

        return "unknown", block_id

    def _keep_latest_vpc_reg_value(self, values, all_states, page_addr, offset, size, reason):
        latest_idx = self._latest_value_index(values, all_states)
        latest_value = values[latest_idx][0]
        merge_kind, block_id = self._merge_point_kind(all_states)
        cur_vm_reg = self._current_vpc_reg(all_states)

        print("EvalTopMerger: keeping latest VPC register value instead of merging")
        print("EvalTopMerger:", {
            "reason": reason,
            "merge_kind": merge_kind,
            "block_id": block_id,
            "cur_vm_reg": cur_vm_reg,
            "latest_idx": latest_idx,
            "page_addr": page_addr,
            "offset": offset,
            "size": size,
        })

        if merge_kind != "loop":
            print("EvalTopMerger: VPC register merge is not at a loop merge point")
            import ipdb;ipdb.set_trace()

        return latest_value

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, all_states=None, page_addr=None, offset=None, size=None, **kwargs):
        if len(all_states) != len(values):
            print("We have a problem!")
            import ipdb;ipdb.set_trace()
        if len(values) > 2:
            import ipdb;ipdb.set_trace()
        value0 = values[0][0]
        value1 = values[1][0]
        state0 = all_states[0]
        state1 = all_states[1]

        do_check = True
        conc_addr0 = None
        conc_addr1 = None


        try:
            conc_addr0 = state0.partial_symbolic_constraint_solver.eval_one(value0)
        except:
            do_check = False

        try:
            conc_addr1 = state1.partial_symbolic_constraint_solver.eval_one(value1)
        except:
            do_check = False

        if self._is_current_vpc_reg_merge(all_states, page_addr, offset, size, merged_size):
            return self._keep_latest_vpc_reg_value(values, all_states, page_addr, offset, size, "cur_vm_reg")

        if state1.globals['last_added_state_split_cond'] is not None and state1.globals['last_added_state_split_cond'] is not state0.globals['last_added_state_split_cond']:
            existing_state_split_var = None

            # this is when the mba state var had been set but not yet used to do the indirect jump but the loop merged back around and the jump will happen later
            # we keep the state var instead of symbolizing it, so that the indirect jump can happen correctly

            for var in value1.variables:
                if var.startswith(state1.globals['last_added_state_split_cond'].args[0]):
                    existing_state_split_var = var
                    break

            if conc_addr1 is None and existing_state_split_var:
                solns = state1.partial_symbolic_constraint_solver.eval_upto(value1, 3)
                if len(solns) == 2:
                    return value1

        if do_check and conc_addr0 == conc_addr1:
            # we return value0 aka the older states values, because of the following case I observedd
            # if there's a loop, because of which a new mba_state_split_cond variable is added to constraints and merged with the
            # original state the new merged constraints will look like this
            # [ < Bool
            # state_merge_0_51_16 == 0x0 & & precon_sp_3_32 == 0x7fff0000 & & !BoolS(
            #    mba_state_split_cond_20_ - 1) & & BoolS(mba_state_split_cond_42_ - 1) & & !BoolS(
            #    mba_state_split_cond_47_ - 1) | |
            #    state_merge_0_51_16 == 0x1 & & precon_sp_3_32 == 0x7fff0000 & & !BoolS(
            #    mba_state_split_cond_20_ - 1) & & BoolS(mba_state_split_cond_42_ - 1) & & !BoolS(
            #    mba_state_split_cond_47_ - 1) & & !BoolS(mba_state_split_cond_50_ - 1) >]
            # here the constraint before || (from initial state) doesn't have mba_state_split_cond_50, because of which it can evaluate to both true and false
            # the constraint after || is the new state
            # in this constraint mba_state_split_cond_50_-1 can both 0 or 1 instead of being restricted to a single value as it should be
            # this causes load address which should only resolve to one address to resolve to multiple addresses
            # and create another mba_split_cond variable
            # So if both the values evaluate to the same concrete value
            # return value0

            is_sp_addr1 = False
            is_sp_addr2 = False
            for var in value0.variables:
                if var.startswith('precon_sp'):
                    is_sp_addr1 = True
                    break
            for var in value1.variables:
                if var.startswith('precon_sp'):
                    is_sp_addr2 = True
                    break
            if not is_sp_addr1 or not is_sp_addr2:
                conc_ast = self.state.solver.BVV(conc_addr1, value0.size())
                return conc_ast
            else:
                # merged_val = self.state.solver.BVV(0, merged_size * self.state.arch.byte_width)
                # for tm, fv in values:
                #     merged_val = self.state.solver.If(fv, tm, merged_val)
                # # should we add state constraint as well?
                # return merged_val
                # we only return value0 to make things easier and quicker for the solver, otherwise the right thing to do is return both as above
                return value0

        # if value0.symbolic and value1.symbolic:
        #     is_sp_addr1 = False
        #     is_sp_addr2 = False
        #     for var in value0.variables:
        #         if var.startswith('precon_sp'):
        #             is_sp_addr1 = True
        #             break
        #     if is_sp_addr1:
        #         for var in value1.variables:
        #             if var.startswith('precon_sp'):
        #                 is_sp_addr2 = True
        #                 break
        #
        #     if is_sp_addr1 and is_sp_addr2:
        #         do_check = True
        #         try:
        #             conc_addr0 = state0.partial_symbolic_constraint_solver.eval_one(value0)
        #         except:
        #             do_check=False
        #
        #         try:
        #             conc_addr1 = state1.partial_symbolic_constraint_solver.eval_one(value1)
        #         except:
        #             do_check=False
        #
        #         if do_check and conc_addr0 == conc_addr1:
        #             # import ipdb;ipdb.set_trace()
        #             return value0
        #         # else:
                #     import ipdb;
                #     ipdb.set_trace()

        if conc_addr0 is not None:
            # this is to deal with the case when we have not yet explored a branch plit, but during symbolization
            # the vips are resolving to two values and now a merge is happening with the previous single vip value
            # we do not want vip to become TOP, so we return the initial vip and wait for the new branch discovery
            # to deal with the two vips
            # this also handles the continuosly changing decryption key, which function similar to the vpc, it
            # is also supposed to be a constant wrt to the vpc
            try:
                conc_addrs1 = state1.partial_symbolic_constraint_solver.eval_upto(value1, 3)
                if len(conc_addrs1) == 2 and conc_addr0 in conc_addrs1:
                    possible_vip_split = False
                    for addr in conc_addrs1:
                        if state1.project.loader.main_object.contains_addr(addr):
                            possible_vip_split = True
                        else:
                            possible_vip_split = False
                            break


                    if possible_vip_split:
                        # value1 already covers the old concrete value and the newly discovered VIP.
                        # Returning it avoids introducing a fake zero branch from an If-chain default.
                        return value1

            except:
                pass
        elif conc_addr1 is not None:
            try:
                conc_addrs0 = state0.partial_symbolic_constraint_solver.eval_upto(value0, 3)
                if len(conc_addrs0) == 2 and conc_addr1 in conc_addrs0:
                    possible_vip_split = False
                    for addr in conc_addrs0:
                        if state0.project.loader.main_object.contains_addr(addr):
                            possible_vip_split = True
                        else:
                            possible_vip_split = False
                            break

                    if possible_vip_split:
                        return value0


            except:
                pass
        # elif self.state.globals['is_constant_propagation']:
        #     #keep both symbolic values, we could replace this with TOP to make things faster
        #     merged_val = self.state.solver.BVV(0, merged_size * self.state.arch.byte_width)
        #     for tm, fv in values:
        #         merged_val = self.state.solver.If(fv, tm, merged_val)
        #     # should we add state constraint as well?
        #     return merged_val

        # special check to simplify away jumps that depend on guards like this
        # if (3 | big_expression) == 0:
        # the value will always be non zero
        # alternative would be to keep both symbolic values but that makes analyses slow
        if value0.op == "__or__" and value1.op == "__or__" and value0.args[0].concrete and value1.args[0].concrete and \
            value1.args[0].concrete_value == value0.args[0].concrete_value:
            merged_val = self._top_func(merged_size * self.state.arch.byte_width)
            self.state.project.merger_top_dict_debug[merged_val.args[0]] = (values, "This comes from the special case")
            return value1.args[0].concrete_value | merged_val

        merged_val = self._top_func(merged_size * self.state.arch.byte_width)
        self.state.project.merger_top_dict_debug[merged_val.args[0]] = (values, self.state.globals['cur_block_id'])
        if self.id not in self.state.project.to_symbolize[self.state.globals['cur_block_id']]:
            self.state.project.to_symbolize[self.state.globals['cur_block_id']][self.id] = []
        self.state.project.to_symbolize[self.state.globals['cur_block_id']][self.id].append((page_addr, offset, size))
        return merged_val

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._top_func = self._top_func
        return copied
