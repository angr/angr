#ifndef _SIM_MEMORY_OBJECT_H_
#define _SIM_MEMORY_OBJECT_H_

#include <pybind11/pybind11.h>
#include <stdint.h>
#include "endness.hpp"

namespace py = pybind11;


namespace angr_c
{
	class SimMemoryObject {
	public:
		SimMemoryObject(py::object ast, uint64_t base, Endness endness, uint64_t byte_width, uint64_t length = 0);
		SimMemoryObject(uint8_t* bytes, uint64_t base, Endness endness, uint64_t byte_width, uint64_t length);
		virtual ~SimMemoryObject();

		uint64_t get_length() const { return m_length; };
		py::object get_ast() { return m_ast; }

	private:
		py::object m_ast;
		uint8_t* m_bytes = NULL;
		uint64_t m_base;
		Endness m_endness;
		uint64_t m_length;
		uint64_t m_byte_width;
	};
}


#endif
