#include "memory_mixin_base.hpp"

namespace angr_c
{
	MemoryMixinBase::MemoryMixinBase(uint32_t bits, uint32_t byte_width, Endness endness)
		: bits(bits), byte_width(byte_width), endness(endness)
	{

	}


	MemoryMixinBase::MemoryMixinBase(const py::kwargs kwargs)
	{
		// TODO: Extract endness
	}
}
