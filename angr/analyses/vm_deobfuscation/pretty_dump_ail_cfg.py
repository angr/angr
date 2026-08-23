import signal
import logging
from typing import Any, List, Union, Dict
import pickle

from angr import ailment
import networkx as nx

l = logging.getLogger(__name__)

#
# Utility
#

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type_, value, traceback):
        signal.alarm(0)


def is_printable(ch):
    return 32 <= ch < 127


def filter_string_for_display(s):
    output = ""
    for ch in s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"):
        char = ord(ch)
        if not is_printable(char):
            ch = "\\x%0.2x" % char
        output += ch
    return output


def fast_memory_load_pointer(project, addr, size=None):
    try:
        return project.loader.memory.unpack_word(addr, size=size)
    except KeyError:
        return None


def string_at_addr(cfg, addr, project, max_size=50):
    try:
        mem_data = cfg.memory_data[addr]
    except KeyError:
        return None

    if mem_data.sort == "string":
        str_content = mem_data.content.decode("utf-8")
    elif mem_data.sort == "pointer-array":
        ptr = fast_memory_load_pointer(project, mem_data.address)
        try:
            next_level = cfg.memory_data[ptr]
        except KeyError:
            return None

        if next_level.sort != "string":
            return None

        str_content = next_level.content.decode("utf-8")
    else:
        return None

    if str_content is not None:
        if len(str_content) > max_size:
            return '"' + filter_string_for_display(str_content[:max_size]) + '..."'
        else:
            return '"' + filter_string_for_display(str_content) + '"'
    else:
        return None


#
# Pretty Printing Classes
#

class OutputBuffer:
    def __init__(self):
        self.text = ""
        self.position = 0

    def insertText(self, text):
        self.text += text
        self.position += len(text)

    def newline(self):
        self.insertText("\n")


class PrettyBlockCodeObj:
    def __init__(self, obj: Any, project: Any, cfg: Any, *args, **kwargs):
        self.obj = obj
        self.project = project
        self.cfg = cfg
        self.span = None
        self.subobjs = []
        self.create_subobjs(obj)

    def create_subobjs(self, obj: Any):
        raise NotImplementedError()

    def recreate_subobjs(self):
        self.subobjs.clear()
        self.create_subobjs(self.obj)

    def render(self, output_buffer):
        """
        Add each subobject to the document
        """
        self.recreate_subobjs()
        span_min = output_buffer.position
        for obj in self.subobjs:
            if type(obj) is str:
                output_buffer.insertText(obj)
            else:
                obj.render(output_buffer)
        span_max = output_buffer.position
        self.span = (span_min, span_max)

    def _add_subobj(self, subobj):
        self.subobjs.append(subobj)

    def add_text(self, text: str):
        """
        Add a text leaf
        """
        self._add_subobj(text)

    def add_variable(self, var):
        self._add_subobj(PrettyVariableObj(var, self.project, self.cfg))


class PrettyAilObj(PrettyBlockCodeObj):
    """
    Renders an AIL object
    """

    def __init__(self, obj: Any, project: Any, cfg: Any, *args, stmt=None, **kwargs):
        self.stmt = stmt or obj
        super().__init__(obj, project, cfg, *args, **kwargs)

    def create_subobjs(self, obj: Any):
        self.add_ailobj(obj)

    def add_ailobj(self, obj: Any):
        """
        Map appropriate AIL type to the display type
        """
        subobjcls = {
            ailment.statement.Assignment: PrettyAilAssignmentObj,
            ailment.statement.Store: PrettyAilStoreObj,
            ailment.statement.Jump: PrettyAilJumpObj,
            ailment.statement.ConditionalJump: PrettyAilConditionalJumpObj,
            ailment.statement.Return: PrettyAilReturnObj,
            ailment.statement.Call: PrettyAilCallObj,
            ailment.expression.Const: PrettyAilConstObj,
            ailment.expression.Tmp: PrettyAilTmpObj,
            ailment.expression.Register: PrettyAilRegisterObj,
            ailment.expression.UnaryOp: PrettyAilUnaryOpObj,
            ailment.expression.BinaryOp: PrettyAilBinaryOpObj,
            ailment.expression.Convert: PrettyAilConvertObj,
            ailment.expression.Load: PrettyAilLoadObj,
        }.get(type(obj), PrettyAilTextObj)
        subobj = subobjcls(obj, self.project, self.cfg, stmt=self.stmt)
        self._add_subobj(subobj)


class PrettyAilTextObj(PrettyAilObj):
    """
    Renders an AIL object via __str__
    """

    def create_subobjs(self, obj: Any):
        self.add_text(str(obj))


class PrettyAilAssignmentObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.Assignment
    """

    def create_subobjs(self, obj: ailment.statement.Assignment):
        self.add_ailobj(obj.dst)
        self.add_text(" = ")
        self.add_ailobj(obj.src)


class PrettyAilStoreObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.Store
    """

    def create_subobjs(self, obj: ailment.statement.Store):
        #if obj.variable is None or not self.options.show_variables:
        if obj.variable is None:
            self.add_text("*(")
            self.add_ailobj(obj.addr)
            self.add_text(") = ")
            self.add_ailobj(obj.data)
        else:
            self.add_variable(obj.variable)
            self.add_text(" = ")
            self.add_ailobj(obj.data)


class PrettyAilJumpObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.Jump
    """

    def create_subobjs(self, obj: ailment.statement.Jump):
        self.add_text("goto ")
        self.add_ailobj(obj.target)


class PrettyAilConditionalJumpObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.ConditionalJump
    """

    def create_subobjs(self, obj: ailment.statement.ConditionalJump):
        self.add_text("if ")
        self.add_ailobj(obj.condition)

        #if self.options.show_conditional_jump_targets:
        self.add_text(" goto ")
        self.add_ailobj(obj.true_target)
        self.add_text(" else goto ")
        self.add_ailobj(obj.false_target)


class PrettyAilReturnObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.Return
    """

    def create_subobjs(self, obj: ailment.statement.Return):
        self.add_text("return ")
        for expr in obj.ret_exprs:
            self.add_ailobj(expr)


class PrettyAilCallObj(PrettyAilTextObj):
    """
    Renders an ailment.statement.Call
    """

    def create_subobjs(self, obj: ailment.statement.Call):
        if obj.ret_expr is not None and self.stmt is self.obj:
            self.add_ailobj(obj.ret_expr)
            self.add_text(" = ")
        self.add_ailobj(obj.target)
        self.add_text("(")
        if obj.args:
            for i, arg in enumerate(obj.args):
                if i > 0:
                    self.add_text(", ")
                self.add_ailobj(arg)
        self.add_text(")")


class PrettyAilConstObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.Const
    """

    def create_subobjs(self, obj: ailment.expression.Const):
        # take care of labels first
        kb = self.project.kb
        if obj.value in kb.labels:
            self.add_text(kb.labels[obj.value])
            return

        data_str = string_at_addr(
            self.cfg,
            obj.value,
            self.project,
        )
        if data_str:
            self.add_text(data_str)
        else:
            self.add_text(f"{obj.value:#x}")


class PrettyAilTmpObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.Tmp
    """
    pass


class PrettyAilRegisterObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.Register
    """
    def create_subobjs(self, obj: ailment.expression.Register):
        #if obj.variable is not None and self.options.show_variables:
        if obj.variable is not None:
            self.add_variable(obj.variable)
        else:
            s = f"{obj.reg_name}" if hasattr(obj, "reg_name") else "reg_%d<%d>" % (obj.reg_offset, obj.bits // 8)
            self.add_text(s)


class PrettyAilUnaryOpObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.UnaryOp
    """

    def create_subobjs(self, obj: ailment.expression.UnaryOp):
        self.add_text("(")
        self.add_text(obj.op + " ")
        self.add_ailobj(obj.operand)
        self.add_text(")")


class PrettyAilBinaryOpObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.BinaryOp
    """

    def create_subobjs(self, obj: ailment.expression.BinaryOp):
        self.add_text("(")
        self.add_ailobj(obj.operands[0])
        verbose_op = obj.OPSTR_MAP.get(obj.verbose_op, obj.verbose_op)
        if verbose_op is None:
            verbose_op = "unknown_op"
        self.add_text(" " + verbose_op + " ")
        self.add_ailobj(obj.operands[1])
        self.add_text(")")


class PrettyAilConvertObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.Convert
    """

    def create_subobjs(self, obj: ailment.expression.Convert):
        self.add_text("Conv(%d->%d, " % (obj.from_bits, obj.to_bits))
        self.add_ailobj(obj.operand)
        self.add_text(")")


class PrettyAilLoadObj(PrettyAilTextObj):
    """
    Renders an ailment.expression.Load
    """

    def create_subobjs(self, obj: ailment.expression.Load):
        #if obj.variable is not None and self.options.show_variables:
        if obj.variable is not None:
            self.add_variable(obj.variable)
        else:
            self.add_text("*(")
            self.add_ailobj(obj.addr)
            self.add_text(")")


class PrettyVariableObj(PrettyBlockCodeObj):
    """
    Renders a variable
    """
    def create_subobjs(self, obj):
        #ident = "<%s>" % (obj.ident if obj.ident else "") if self.options.show_variable_identifiers else ""
        ident = ""
        self.add_text(obj.name + ident)


#
# Output Linear AIL
#

def pretty_dump_ail_cfg(ail_cfg, proj, output="ail_cfg.pickle"):
    str_cfg = nx.DiGraph()
    str_cfg.name = ail_cfg.name
    proj_cfg = proj.kb.cfgs.get_most_accurate()
    for node in ail_cfg.nodes:
        stmts = []
        for stmt in node.statements:
            output_buffer = OutputBuffer()
            pretty_obj = PrettyAilObj(stmt, proj, proj_cfg)
            pretty_obj.render(output_buffer)
            stmts.append(output_buffer.text)
        
        str_cfg.add_node(node.addr, label=stmts)
    
    for src, dst in ail_cfg.edges:
        str_cfg.add_edge(src.addr, dst.addr)
    
    with open(output, "wb") as fp:
        pickle.dump(str_cfg, fp)
