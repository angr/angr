#ifndef _DECOMPOSER_H_
#define _DECOMPOSER_H_

#include <pybind11/pybind11.h>
#include <stdint.h>
#include <utility>
#include "../sim_memory_object.hpp"
#include "../endness.hpp"

namespace py = pybind11;


namespace angr_c
{
	class Decomposer {
	public:
		Decomposer(uint64_t addr, py::object data, uint8_t byte_width, Endness endness, uint64_t page_addr); // TODO: label
		virtual ~Decomposer();
		virtual std::pair<SimMemoryObject*, uint32_t> yield(uint32_t size) = 0;

	protected:
		uint64_t m_addr;
		py::object m_data;
		uint8_t m_byte_width;
		Endness m_endness;
		uint64_t m_curr_addr;
	};

	class MemoryObjectDecomposer : public Decomposer {
	public:
		MemoryObjectDecomposer(uint64_t addr, py::object data, uint8_t byte_width, Endness endness, uint64_t page_addr); // TODO: label
		~MemoryObjectDecomposer();
		std::pair<SimMemoryObject*, uint32_t> yield(uint32_t size);

	private:
		SimMemoryObject* m_memobj;
	};
}

#endif
