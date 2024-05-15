#ifndef _PAGED_MEMORY_MIXIN_HPP_
#define _PAGED_MEMORY_MIXIN_HPP_

#include <nanobind/nanobind.h>
#include <map>
#include <iostream>
#include <algorithm>
#include <stdint.h>
#include "pages/page.hpp"
#include "endness.hpp"
#include "memory_mixin_base.hpp"
#include "pages/decomposer.hpp"

namespace nb = nanobind;
using namespace nb::literals;


namespace angr_c
{
	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	class PagedMemoryMixin : public T {
	public:
		PagedMemoryMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs);
		PagedMemoryMixin(const nb::kwargs kwargs);

		void store(uint64_t addr, nb::object data, uint32_t size, nb::kwargs kwargs);
		nb::object load(uint64_t addr, uint32_t size, nb::kwargs kwargs);
		~PagedMemoryMixin();

	private:
		int m_page_size;
		std::map<uint64_t, PAGE_TYPE*> m_pages;

		std::pair<uint64_t, uint64_t> _divide_addr(uint64_t addr);
		PAGE_TYPE* _get_page(uint64_t pageno, bool writing);
		PAGE_TYPE* _initialize_page(uint64_t pageno, bool force_default);
	};

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::PagedMemoryMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs)
		: T(bits, byte_width, endness)
	{
		uint32_t page_size = 4096;
		if (kwargs.contains("page_size")) {
			page_size = nb::cast<uint32_t>(kwargs["page_size"]);
		}
		m_page_size = page_size;
	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::PagedMemoryMixin(const nb::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	void
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::store(uint64_t addr, nb::object data, uint32_t size, nb::kwargs kwargs)
	{
		Endness endness = this->endness;
		if (kwargs.contains("endness")) {
			nb::object arg = kwargs["endness"];
			if (!arg.is_none()) {
				std::string arg_str = nb::cast<std::string>(arg);
				if (arg_str == "Iend_LE") {
					endness = Endness::LE;
				}
				else if (arg_str == "Iend_BE") {
					endness = Endness::BE;
				}
			}
		}

		auto tpl = this->_divide_addr(addr);
		uint64_t pageno = tpl.first, pageoff = tpl.second;
		DECOMPOSER_T decomposer = PAGE_TYPE::decompose_objects(addr, data, endness, 8, 0);

		// fast-track basic case
		if (pageoff + size <= this->m_page_size) {
			uint32_t written_size = 0;
			while (written_size < size) {
				auto pair = decomposer.yield(size - written_size);
				auto sub_data = pair.first;
				uint32_t sub_data_size = pair.second;
				auto page = this->_get_page(pageno, true);
				sub_data_size = std::min(sub_data_size, size - written_size);
				page->store(pageoff + written_size, sub_data, sub_data_size, endness,
					pageno * this->m_page_size, /* cooperate */ true);
				written_size += sub_data_size;
			}
			return;
		}
	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	nb::object
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::load(uint64_t addr, uint32_t size, nb::kwargs kwargs)
	{
		Endness endness = this->endness;
		if (kwargs.contains("endness")) {
			nb::object arg = kwargs["endness"];
			if (!arg.is_none()) {
				std::string arg_str = nb::cast<std::string>(arg);
				if (arg_str == "Iend_LE") {
					endness = Endness::LE;
				}
				else if (arg_str == "Iend_BE") {
					endness = Endness::BE;
				}
			}
		}

		auto tpl = this->_divide_addr(addr);
		uint64_t pageno = tpl.first, pageoff = tpl.second;
		std::vector<std::tuple<uint64_t,std::shared_ptr<SimMemoryObject>>> vals;

		// fast-track basic case
		if (pageoff + size <= this->m_page_size) {
			auto page = this->_get_page(pageno, false);
			auto tmp_vals = page->load_raw(pageoff, size, endness, pageno * this->m_page_size);
			vals.insert(vals.end(), tmp_vals.begin(), tmp_vals.end());
		}
		else {
			throw std::runtime_error("The complex case of lead() is not implemented");
		}

		auto out = PAGE_TYPE::compose_objects(vals, size, endness);
		return out;
	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	PAGE_TYPE*
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::_get_page(uint64_t pageno, bool writing)
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
	
	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	PAGE_TYPE*
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::_initialize_page(uint64_t pageno, bool force_default)
	{
		return new PAGE_TYPE(this->m_page_size);
	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	std::pair<uint64_t, uint64_t>
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::_divide_addr(uint64_t addr)
	{
		uint64_t pageno = addr / this->m_page_size;
		uint64_t pageoff = addr % this->m_page_size;
		return std::make_pair(pageno, pageoff);
	}

	template <class T, class PAGE_TYPE, class DECOMPOSER_T>
	PagedMemoryMixin<T, PAGE_TYPE, DECOMPOSER_T>::~PagedMemoryMixin()
	{

	}
}

#endif
