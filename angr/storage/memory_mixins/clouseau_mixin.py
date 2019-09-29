class ClouseauMixin:
    def store(self, addr, data, size=None, condition=None, endness=None, inspect=True, **kwargs):
        if not inspect or not self.state.supports_inspect:
            self.store(addr, data, size=size, condition=condition, endness=endness, **kwargs)

        if self.category == 'reg':
            self.state._inspect(
                'reg_write',
                BP_BEFORE,
                reg_write_offset=addr,
                reg_write_length=size,
                reg_write_expr=data,
                reg_write_condition=condition,
                reg_write_endness=endness,
            )
            addr = self.state._inspect_getattr('reg_write_offset', addr)
            size = self.state._inspect_getattr('reg_write_length', size)
            data = self.state._inspect_getattr('reg_write_expr', data)
            condition = self.state._inspect_getattr('reg_write_condition', condition)
            endness = self.state._inspect_getattr('reg_write_endness', endness)
        elif self.category == 'mem':
            self.state._inspect(
                'mem_write',
                BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
                mem_write_condition=condition,
                mem_write_endness=endness,
            )
            addr = self.state._inspect_getattr('mem_write_address', addr)
            size = self.state._inspect_getattr('mem_write_length', size)
            data = self.state._inspect_getattr('mem_write_expr', data)
            condition = self.state._inspect_getattr('mem_write_condition', condition)
            endness = self.state._inspect_getattr('mem_write_endness', endness)

        super().store(addr, data, size=size, condition=condition, endness=endness, **kwargs)

        if self.category == 'reg': self.state._inspect('reg_write', BP_AFTER)
        elif self.category == 'mem': self.state._inspect('mem_write', BP_AFTER)

    def load(self, addr, size=None, condition=None, endness=None, inspect=True, **kwargs):
        if not inspect or not self.state.supports_inspect:
            return super().load(addr, size=size, condition=condition, endness=endness, **kwargs)

        if self.category == 'reg':
            self.state._inspect('reg_read', BP_BEFORE, reg_read_offset=addr, reg_read_length=size, reg_read_condition=condition, reg_read_endness=endness)
            addr = self.state._inspect_getattr("reg_read_offset", addr)
            size = self.state._inspect_getattr("reg_read_length", size)
            condition = self.state._inspect_getattr("reg_read_condition", condition)
            endness = self.state._inspect_getattr("reg_read_endness", endness)
        elif self.category == 'mem':
            self.state._inspect('mem_read', BP_BEFORE, mem_read_address=addr, mem_read_length=size, mem_read_condition=condition, mem_read_endness=endness)
            addr = self.state._inspect_getattr("mem_read_address", addr)
            size = self.state._inspect_getattr("mem_read_length", size)
            condition = self.state._inspect_getattr("mem_read_condition", condition)
            endness = self.state._inspect_getattr('mem_read_endness', endness)

        r = super().load(addr, size=size, condition=condition, endness=endness, **kwargs)

        if self.category == 'mem':
            self.state._inspect('mem_read', BP_AFTER, mem_read_expr=r)
            r = self.state._inspect_getattr("mem_read_expr", r)

        elif self.category == 'reg':
            self.state._inspect('reg_read', BP_AFTER, reg_read_expr=r)
            r = self.state._inspect_getattr("reg_read_expr", r)

        return r


from ...state_plugins.inspect import BP_BEFORE, BP_AFTER
