#ifndef _LIST_PAGE_HPP_
#define _LIST_PAGE_HPP_

#include <vector>
#include <set>
#include <tuple>
#include <pybind11/pybind11.h>
#include "page.hpp"

namespace py = pybind11;


namespace angr_c
{
	template <class COOPERATION_T, class VALUE_T>
	class ListPage : public Page<COOPERATION_T, VALUE_T> {
	public:
		ListPage(uint32_t page_size);
		void store(uint64_t addr, VALUE_T* data, uint32_t size, Endness endness, uint64_t page_addr, bool cooperate);
		std::vector<std::tuple<uint64_t, VALUE_T*>> load_raw(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr);
		py::object load(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr);

		py::object static compose_objects(std::vector<std::tuple<uint64_t, VALUE_T*>> result, uint32_t size, Endness endness);

	private:
		std::vector<VALUE_T*> m_content;
		std::set<uint64_t> m_stored_offset;
		VALUE_T* m_sinkhole;
	};

	template <class COOPERATION_T, class VALUE_T>
	ListPage<COOPERATION_T, VALUE_T>::ListPage(uint32_t page_size)
		: Page<COOPERATION_T, VALUE_T>(page_size), m_sinkhole(nullptr)
	{
		// pre-allocate memory space
		m_content.assign(this->get_page_size(), nullptr);
	}

	template <class COOPERATION_T, class VALUE_T>
	void ListPage<COOPERATION_T, VALUE_T>::store(uint64_t addr, VALUE_T* data, uint32_t size, Endness endness, uint64_t page_addr, bool cooperate)
	{
		if (!cooperate) {
			throw std::runtime_error("cooperate is not implemented");
		}

		if (size == m_content.size() && addr == 0) {
			m_sinkhole = data;
		}
		else {
			uint64_t max_addr = std::min(addr + size, (uint64_t)this->get_page_size());
			for (uint64_t sub_addr = addr; sub_addr < max_addr; ++sub_addr) {
				m_content[sub_addr] = data;
				m_stored_offset.insert(sub_addr);
			}
		}
	}

	template <class COOPERATION_T, class VALUE_T>
	std::vector<std::tuple<uint64_t,VALUE_T*>> ListPage<COOPERATION_T, VALUE_T>::load_raw(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr)
	{
		std::vector<std::tuple<uint64_t,VALUE_T*>> result;
		VALUE_T* last_seen = nullptr;
		bool loaded_any = false;

		// loop over the loading range. accumulate a result for each byte, but collapse results from adjacent bytes
		// using the same memory object
		for (uint64_t subaddr = addr; subaddr < addr + size; ++subaddr) {
			VALUE_T* item = m_content[subaddr];
			if (item == nullptr) {
				item = m_sinkhole;
			}
			if (!loaded_any || item != last_seen) {
				if (loaded_any && last_seen == nullptr) {
					// _fill()
					throw std::runtime_error("Call to _fill() is not implemented - 1");
				}
				result.push_back(std::make_tuple(subaddr + page_addr, item));
				last_seen = item;
				loaded_any = true;
			}
		}

		if (last_seen == nullptr) {
			// _fill()
			throw std::runtime_error("Call to _fill() is not implemented - 2");
		}

		return result;
	}

	template <class COOPERATION_T, class VALUE_T>
	py::object ListPage<COOPERATION_T, VALUE_T>::load(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr)
	{
		auto result = load_raw(addr, size, endness, page_addr);
		return COOPERATION_T::force_load_cooperation(result, size, page_addr, endness);
	}

	template <class COOPERATION_T, class VALUE_T>
	py::object ListPage<COOPERATION_T, VALUE_T>::compose_objects(std::vector<std::tuple<uint64_t, VALUE_T*>> result, uint32_t size, Endness endness)
	{
		return COOPERATION_T::compose_objects(result, size, endness);
	}
}

#endif