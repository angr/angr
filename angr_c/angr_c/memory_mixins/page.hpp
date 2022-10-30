#ifndef _PAGE_H_
#define _PAGE_H_

#include <map>
#include <exception>
#include <vector>
#include <pybind11/pybind11.h>
#include "endness.hpp"
#include "sim_memory_object.hpp"

namespace py = pybind11;


namespace angr_c
{
	template <class COOPERATION_T>
	class Page : public COOPERATION_T {
	public:
		void store(uint64_t addr, SimMemoryObject* obj, uint64_t size, Endness endness, uint64_t page_addr, bool cooperate) { m_content[addr] = obj; };
		SimMemoryObject* load(uint64_t addr, uint64_t size, Endness endness, uint64_t page_addr, bool cooperate);

		py::object static _compose_objects(std::vector<SimMemoryObject*>& vals, uint64_t size, Endness endness);

	private:
		std::map<uint64_t, SimMemoryObject*> m_content;
	};

	template <class COOPERATION_T>
	SimMemoryObject* Page<COOPERATION_T>::load(uint64_t addr, uint64_t size, Endness endness, uint64_t page_addr, bool cooperate)
	{
		return m_content[addr];
	}

	template <class COOPERATION_T>
	py::object Page<COOPERATION_T>::_compose_objects(std::vector<SimMemoryObject*>& vals, uint64_t size, Endness endness)
	{
		py::object r = vals[0]->get_ast();
		return r;
	}
}

#endif

