#include "sim_memory_object.hpp"

namespace angr_c
{
	SimMemoryObject::SimMemoryObject(py::object ast, uint64_t base, Endness endness, uint64_t byte_width, uint64_t length)
		: m_ast(ast), m_bytes(NULL), m_base(base), m_endness(endness), m_byte_width(byte_width)
	{
		if (length == 0) {
			// TODO: Call into Python land to get the length of the AST
		}
		m_length = length;
	}

	SimMemoryObject::SimMemoryObject(uint8_t* bytes, uint64_t base, Endness endness, uint64_t byte_width, uint64_t length)
		: m_ast(py::none()), m_bytes(bytes), m_base(base), m_endness(endness), m_byte_width(byte_width), m_length(length)
	{

	}

	SimMemoryObject::~SimMemoryObject()
	{
		if (m_bytes != NULL) {
			// TODO: Use a shared pointer for m_bytes
			;
		}
	}
}
