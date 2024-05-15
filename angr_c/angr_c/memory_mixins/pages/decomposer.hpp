#ifndef _DECOMPOSER_H_
#define _DECOMPOSER_H_

#include <nanobind/nanobind.h>
#include <stdint.h>
#include <utility>
#include <memory>
#include "../sim_memory_object.hpp"
#include "../endness.hpp"

namespace nb = nanobind;


namespace angr_c
{
	class Decomposer {
	public:
		Decomposer(uint64_t addr, nb::object data, uint8_t byte_width, Endness endness, uint64_t page_addr); // TODO: label
		~Decomposer();
		std::pair<std::shared_ptr<SimMemoryObject>, uint32_t> yield(uint32_t size);

	protected:
		uint64_t m_addr;
		nb::object m_data;
		uint8_t m_byte_width;
		Endness m_endness;
		uint64_t m_curr_addr;
	};

	class MemoryObjectDecomposer : public Decomposer {
	public:
		MemoryObjectDecomposer(uint64_t addr, nb::object data, uint8_t byte_width, Endness endness, uint64_t page_addr); // TODO: label
		~MemoryObjectDecomposer();
		std::pair<std::shared_ptr<SimMemoryObject>, uint32_t> yield(uint32_t size);

	private:
		std::shared_ptr<SimMemoryObject> m_memobj;
	};
}

#endif
