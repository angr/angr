#ifndef _COOPERATION_H_
#define _COOPERATION_H_

#include <pybind11/pybind11.h>
#include "endness.hpp"
#include "decomposer.hpp"

namespace py = pybind11;


namespace angr_c
{
	class CooperationBase {
	public:
		static Decomposer* _decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr) {
			return NULL;
		};
	};

	class MemoryObjectMixin : public CooperationBase {
	public:
		static Decomposer* _decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr);
	};
}

#endif