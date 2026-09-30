# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import pickle
from unittest import TestCase, main

import archinfo

from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import DefinitionAnnotation


class TestRegisterAtom(TestCase):
    def test_register_atom_does_not_carry_arch(self):
        arch = archinfo.ArchAMD64()
        atom = Atom.reg("rax", arch=arch)
        assert atom == Register(*arch.registers["rax"])
        assert atom.name(arch) == "rax"
        # DefinitionAnnotations are pickled into every annotated AST; they must stay small
        anno = DefinitionAnnotation(Definition(atom, CodeLocation(0x1000, 0)))
        assert len(pickle.dumps(anno)) < 2048

    def test_dep_graph_find_definitions_by_register_name(self):
        arch = archinfo.ArchAMD64()
        defn = Definition(Atom.reg("rax", arch=arch), CodeLocation(0x1000, 0))
        graph = DepGraph()
        graph.add_node(defn)
        assert graph.find_definitions(reg_name="rax", arch=arch) == [defn]
        assert graph.find_definitions(reg_name="eax", arch=arch) == [defn]
        assert graph.find_definitions(reg_name="rbx", arch=arch) == []
        assert graph.find_definitions(reg_name=arch.registers["rax"][0]) == [defn]
        assert graph.find_definitions(reg_name="rax") == []


if __name__ == "__main__":
    main()
