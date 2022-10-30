#ifndef _MEMORY_MIXIN_BASE_H_
#define _MEMORY_MIXIN_BASE_H_

#include <pybind11/pybind11.h>
#include <stdint.h>
#include "endness.hpp"

namespace py = pybind11;


namespace angr_c
{
	class MemoryMixinBase {
	public:
		MemoryMixinBase(uint32_t bits, uint32_t byte_width, Endness endness);
		MemoryMixinBase(const py::kwargs kwargs);

		virtual void store(uint64_t addr, py::object data, py::kwargs kwargs) {};
		virtual py::object load(uint64_t addr, uint64_t size, py::kwargs kwargs) { return py::none(); };
		virtual ~MemoryMixinBase() {};
	protected:
		uint32_t bits;
		uint32_t byte_width;
		Endness endness = Unspecified;
	};
}

#endif