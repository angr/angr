#include "decomposer.hpp"

namespace angr_c
{
	Decomposer::Decomposer(uint64_t addr, nb::object data, uint8_t byte_width, Endness endness, uint64_t page_addr)
		: m_addr(addr), m_curr_addr(addr + page_addr), m_data(data), m_byte_width(byte_width), m_endness(endness)
	{
		
	}

	Decomposer::~Decomposer()
	{
		
	}

	MemoryObjectDecomposer::MemoryObjectDecomposer(uint64_t addr, nb::object data, uint8_t byte_width, Endness endness, uint64_t page_addr)
		: Decomposer(addr, data, byte_width, endness, page_addr)
	{
		this->m_memobj = std::shared_ptr<SimMemoryObject>(new SimMemoryObject(data, m_curr_addr, m_endness, m_byte_width));
	}

	MemoryObjectDecomposer::~MemoryObjectDecomposer()
	{

	}

	std::pair<std::shared_ptr<SimMemoryObject>, uint32_t>
		MemoryObjectDecomposer::yield(uint32_t size)
	{
		m_curr_addr += size;
		return std::make_pair(m_memobj, m_memobj->get_length());
	}
}
