#ifndef _MEMORIES_HPP_
#define _MEMORIES_HPP_

#include <nanobind/nanobind.h>

namespace nb = nanobind;


namespace angr_c
{
	void register_memory_class(nb::module_& m);
}

#endif