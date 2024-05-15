#include "sim_memory_object.hpp"


namespace angr_c
{
	SimMemoryObject::SimMemoryObject(nb::object ast, uint64_t base, Endness endness, uint8_t byte_width, uint32_t length)
		: m_ast(ast), m_bytes(NULL), m_base(base), m_endness(endness), m_byte_width(byte_width)
	{
		if (length == 0) {
			uint64_t bit_size;
			if (nb::isinstance<nb::bytes>(ast)) {
				bit_size = nb::cast<uint64_t>(ast.attr("__len__")());
			}
			else {
				bit_size = nb::cast<uint64_t>(ast.attr("size")());
			}
			length = bit_size / m_byte_width;
		}
		m_length = length;
	}

	SimMemoryObject::SimMemoryObject(uint8_t* bytes, uint64_t base, Endness endness, uint8_t byte_width, uint32_t length)
		: m_ast(nb::none()), m_bytes(bytes), m_base(base), m_endness(endness), m_byte_width(byte_width), m_length(length)
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
