#include <nanobind/nanobind.h>
#include <iostream>
#include "block.hpp"
#include "memories.hpp"
#include "angr_c.hpp"

using namespace std;
namespace nb = nanobind;
using namespace nb::literals;


namespace angr_c
{
	nb::object claripyAstBV;
	nb::object claripyBVV;
	nb::object claripyFPV;
	nb::object claripyFSORT_FLOAT;
	nb::object claripyFSORT_DOUBLE;

	nb::object Clemory;

	void Initialize()
	{
		auto cle = nb::module_::import_("cle");
		Clemory = cle.attr("Clemory");

		claripyAstBV = nb::module_::import_("claripy").attr("ast").attr("BV");
		claripyBVV = nb::module_::import_("claripy").attr("BVV");
		claripyFPV = nb::module_::import_("claripy").attr("FPV");
		claripyFSORT_FLOAT = nb::module_::import_("claripy").attr("FSORT_FLOAT");
		claripyFSORT_DOUBLE = nb::module_::import_("claripy").attr("FSORT_DOUBLE");

		initialize_block();
	}

	NB_MODULE(angr_native, m) {
		m.doc() = "angr native";
		m.def("initialize", &Initialize, "Initialize all necessary stuff.");
		register_block_class(m);
		register_memory_class(m);
	}
}
