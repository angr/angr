#ifndef _PAGE_H_
#define _PAGE_H_

#include <map>
#include "endness.hpp"
#include "sim_memory_object.hpp"

namespace angr_c
{
	template <class COOPERATION_T>
	class Page : public COOPERATION_T {
	public:
		void store(uint64_t addr, SimMemoryObject* obj, uint64_t size, Endness endness, uint64_t page_addr, bool cooperate) { m_content[addr] = obj; };

	private:
		std::map<uint64_t, SimMemoryObject*> m_content;
	};
}

#endif

