#ifndef _MEMORIES_HPP_
#define _MEMORIES_HPP_

#include <pybind11/pybind11.h>

namespace py = pybind11;


namespace angr_c
{
	void register_memory_class(py::module_& m);
}

#endif