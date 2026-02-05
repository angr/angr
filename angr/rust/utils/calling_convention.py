from angr.ailment.statement import Call
from angr.rust.sim_type import RustSimTypeFunction


def zip_args_and_types(call: Call, prototype: RustSimTypeFunction):
    """
    Group each argument type from the prototype with its corresponding AIL argument(s).

    This handles cases where:
    - One type maps to one arg (normal case)
    - One type spans multiple args (e.g., 16-byte struct split across two 8-byte registers)

    :param call: The AIL Call statement
    :param prototype: The Rust function prototype
    :return: List of tuples (arg_ty, [args]) or None if sizes don't match
    """
    if not call.args or not prototype:
        return None
    arch = prototype._arch

    total_arg_size = sum(arg.size * arch.byte_width for arg in call.args)
    total_type_size = sum(arg_ty.size for arg_ty in prototype.args)

    if total_arg_size != total_type_size:
        return None

    # Build offset -> arg_ty mapping
    offset_to_arg_ty = {}
    cur_offset = 0
    for arg_ty in prototype.args:
        offset_to_arg_ty[cur_offset] = arg_ty
        cur_offset += arg_ty.size

    # Build offset -> arg mapping
    offset_to_arg = {}
    cur_offset = 0
    for arg in call.args:
        offset_to_arg[cur_offset] = arg
        cur_offset += arg.size * arch.byte_width

    # Check that all type offsets align with arg offsets
    if not set(offset_to_arg_ty.keys()).issubset(set(offset_to_arg.keys())):
        return None

    # Group args by their corresponding arg_ty
    result = []
    sorted_type_offsets = sorted(offset_to_arg_ty.keys())

    for i, type_offset in enumerate(sorted_type_offsets):
        arg_ty = offset_to_arg_ty[type_offset]
        type_end_offset = type_offset + arg_ty.size

        # Collect all args that fall within this type's range
        args_for_type = []
        expected_offset = type_offset
        for arg_offset, arg in sorted(offset_to_arg.items()):
            if arg_offset >= type_end_offset:
                break
            if arg_offset < type_offset:
                continue
            # Check for gaps - args must be contiguous and start at expected offset
            if arg_offset != expected_offset:
                return None
            args_for_type.append(arg)
            expected_offset = arg_offset + arg.size * arch.byte_width

        # Verify args fully fill the type's range
        if expected_offset != type_end_offset:
            return None

        result.append((args_for_type, arg_ty))

    return result
