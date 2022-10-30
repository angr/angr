#include <pybind11/pybind11.h>
#include <iostream>
#include "block.hpp"
#include "memories.hpp"
#include "angr_c.hpp"

using namespace std;
namespace py = pybind11;
using namespace py::literals;


namespace angr_c
{
	py::object claripyAstBV;
	py::object claripyBVV;
	py::object claripyFPV;
	py::object claripyFSORT_FLOAT;
	py::object claripyFSORT_DOUBLE;

	py::object Clemory;

	void Initialize()
	{
		auto cle = py::module::import("cle");
		Clemory = cle.attr("Clemory");

		claripyAstBV = py::module_::import("claripy").attr("ast").attr("BV");
		claripyBVV = py::module_::import("claripy").attr("BVV");
		claripyFPV = py::module_::import("claripy").attr("FPV");
		claripyFSORT_FLOAT = py::module_::import("claripy").attr("FSORT_FLOAT");
		claripyFSORT_DOUBLE = py::module_::import("claripy").attr("FSORT_DOUBLE");

		initialize_block();
	}

	PYBIND11_MODULE(angr_native, m) {
		m.doc() = "angr native";
		m.def("initialize", &Initialize, "Initialize all necessary stuff.");
		register_block_class(m);
		register_memory_class(m);
	}
}
