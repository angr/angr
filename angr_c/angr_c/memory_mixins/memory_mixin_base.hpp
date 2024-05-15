#ifndef _MEMORY_MIXIN_BASE_H_
#define _MEMORY_MIXIN_BASE_H_

#include <nanobind/nanobind.h>
#include <stdint.h>
#include "endness.hpp"

namespace nb = nanobind;


namespace angr_c
{
	class MemoryMixinBase {
	public:
		MemoryMixinBase(uint32_t bits, uint32_t byte_width, Endness endness);
		MemoryMixinBase(const nb::kwargs kwargs);

		virtual void store(uint64_t addr, nb::object data, nb::kwargs kwargs) {};
		virtual nb::object load(uint64_t addr, uint64_t size, nb::kwargs kwargs) { return nb::none(); };
		virtual ~MemoryMixinBase() {};
	protected:
		uint32_t bits;
		uint32_t byte_width;
		Endness endness;
	};
}

#endif