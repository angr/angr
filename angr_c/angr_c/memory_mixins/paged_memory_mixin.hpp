#ifndef _PAGED_MEMORY_MIXIN_HPP_
#define _PAGED_MEMORY_MIXIN_HPP_

#include <pybind11/pybind11.h>
#include <map>
#include <iostream>
#include <algorithm>
#include <stdint.h>
#include "page.hpp"
#include "endness.hpp"
#include "memory_mixin_base.hpp"
#include "decomposer.hpp"

namespace py = pybind11;
using namespace py::literals;


namespace angr_c
{
	template <class T, class PAGE_TYPE>
	class PagedMemoryMixin : public T {
	public:
		PagedMemoryMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs);
		PagedMemoryMixin(const py::kwargs kwargs);

		void store(uint64_t addr, py::object data, uint64_t size, py::kwargs kwargs);
		py::object load(uint64_t addr, uint64_t size, py::kwargs kwargs);
		~PagedMemoryMixin();

	private:
		int m_page_size;
		std::map<uint64_t, PAGE_TYPE*> m_pages;

		std::pair<uint64_t, uint64_t> _divide_addr(uint64_t addr);
		PAGE_TYPE* _get_page(uint64_t pageno, bool writing);
		PAGE_TYPE* _initialize_page(uint64_t pageno, bool force_default);
	};

	template <class T, class PAGE_TYPE>
	PagedMemoryMixin<T, PAGE_TYPE>::PagedMemoryMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs)
		: T(bits, byte_width, endness)
	{
		uint32_t page_size = 4096;
		if (kwargs.contains("page_size")) {
			page_size = kwargs["page_size"].cast<uint32_t>();
		}
		m_page_size = page_size;
	}

	template <class T, class PAGE_TYPE>
	PagedMemoryMixin<T, PAGE_TYPE>::PagedMemoryMixin(const py::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T, class PAGE_TYPE>
	void
	PagedMemoryMixin<T, PAGE_TYPE>::store(uint64_t addr, py::object data, uint64_t size, py::kwargs kwargs)
	{
		Endness endness = this->endness;
		if (kwargs.contains("endness")) {
			py::object arg = kwargs["endness"];
			if (!arg.is_none()) {
				std::string arg_str = arg.cast<std::string>();
				if (arg_str == "Iend_LE") {
					endness = LE;
				}
				else if (arg_str == "Iend_BE") {
					endness = BE;
				}
			}
		}

		auto tpl = this->_divide_addr(addr);
		uint64_t pageno = tpl.first, pageoff = tpl.second;
		Decomposer* decomposer = PAGE_TYPE::_decompose_objects(addr, data, endness, 8, 0);

		// fast-track basic case
		if (pageoff + size <= this->m_page_size) {
			uint64_t written_size = 0;
			while (written_size < size) {
				auto pair = decomposer->yield(size - written_size);
				SimMemoryObject* sub_data = pair.first;
				uint64_t sub_data_size = pair.second;
				auto page = this->_get_page(pageno, true);
				sub_data_size = std::min(sub_data_size, size - written_size);
				page->store(pageoff + written_size, sub_data, sub_data_size, endness,
					pageno * this->m_page_size, /* cooperate */ true);
				written_size += sub_data_size;
			}
			delete decomposer;
			return;
		}

		delete decomposer;
	}

	template <class T, class PAGE_TYPE>
	py::object
	PagedMemoryMixin<T, PAGE_TYPE>::load(uint64_t addr, uint64_t size, py::kwargs kwargs)
	{
		return py::none();
	}

	template <class T, class PAGE_TYPE>
	PAGE_TYPE*
	PagedMemoryMixin<T, PAGE_TYPE>::_get_page(uint64_t pageno, bool writing)
	{
		bool force_default = true;
		// force_default means don't consult any "backers"
		// if NULL is stored explicitly in _pages, it means it was unmapped explicitly, so don't consult backers

		PAGE_TYPE* page = NULL;
		if (m_pages.contains(pageno)) {
			page = m_pages[pageno];
		}
		else {
			page = this->_initialize_page(pageno, force_default);
			m_pages[pageno] = page;
		}

		if (writing) {
			// TODO: acquire_unique()
			m_pages[pageno] = page;
		}
		return page;
	}
	
	template <class T, class PAGE_TYPE>
	PAGE_TYPE*
	PagedMemoryMixin<T, PAGE_TYPE>::_initialize_page(uint64_t pageno, bool force_default)
	{
		return new PAGE_TYPE();
	}

	template <class T, class PAGE_TYPE>
	std::pair<uint64_t, uint64_t>
	PagedMemoryMixin<T, PAGE_TYPE>::_divide_addr(uint64_t addr)
	{
		uint64_t pageno = addr / this->m_page_size;
		uint64_t pageoff = addr % this->m_page_size;
		return std::make_pair(pageno, pageoff);
	}

	template <class T, class PAGE_TYPE>
	PagedMemoryMixin<T, PAGE_TYPE>::~PagedMemoryMixin()
	{

	}
}

#endif
