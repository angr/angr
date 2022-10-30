#include "cooperation.hpp"

namespace angr_c
{
	Decomposer*
		MemoryObjectMixin::_decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr)
	{
		MemoryObjectDecomposer* decomposer = new MemoryObjectDecomposer(addr, data, byte_width, endness, page_addr);
		return decomposer;
	}
}
