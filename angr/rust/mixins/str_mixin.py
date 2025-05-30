from angr.ailment import Const


class StrMixin:
    def __init__(self, project):
        self.project = project

    def extract_str_from_addr(self, addr, infer_empty_str=False):
        decoded_str = None
        if (section := self.project.loader.find_section_containing(addr)) and section.is_readable:
            if infer_empty_str:
                decoded_str = ""
            memory = self.project.loader.memory
            str_addr = memory.unpack(addr, self.project.arch.struct_fmt())[0]
            if (
                (section := self.project.loader.find_section_containing(str_addr))
                and section.is_readable
                and not section.is_writable
            ):
                str_len = memory.unpack(addr + self.project.arch.bytes, self.project.arch.struct_fmt())[0]
                try:
                    decoded_str = memory.load(str_addr, str_len).decode("utf-8")
                    decoded_str = decoded_str if decoded_str.isprintable() else None
                except UnicodeDecodeError:
                    pass
        return decoded_str

    def extract_str(self, ptr_expr: Const, len_expr: Const):
        decoded_str = None
        memory = self.project.loader.memory
        str_addr = ptr_expr.value
        str_len = len_expr.value
        if str_len >= 0 and (
            (section := self.project.loader.find_section_containing(ptr_expr.value))
            and section.is_readable
            and not section.is_writable
        ):
            try:
                decoded_str = memory.load(str_addr, str_len).decode("utf-8")
                decoded_str = decoded_str if decoded_str.isprintable() else None
            except UnicodeDecodeError:
                pass
        return decoded_str
