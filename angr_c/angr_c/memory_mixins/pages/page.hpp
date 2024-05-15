#ifndef _PAGE_HPP_
#define _PAGE_HPP_

#include <exception>
#include <vector>
#include <nanobind/nanobind.h>
#include "../endness.hpp"
#include "../sim_memory_object.hpp"
#include "decomposer.hpp"

namespace nb = nanobind;


namespace angr_c
{
	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	class Page {
	public:
		Page(uint32_t page_size);
		void store(uint64_t addr, VALUE_T* data, uint32_t size, Endness endness, uint64_t page_addr, bool cooperate);
		std::vector<std::tuple<uint64_t, VALUE_T*>> load_raw(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr);
		nb::object load(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr);

		uint32_t get_page_size() const { return m_page_size; }

		static DECOMPOSER_T decompose_objects(uint64_t addr, nb::object data, Endness endness, uint8_t byte_width, uint64_t page_addr);
		static nb::object compose_objects(std::vector<std::tuple<uint64_t, VALUE_T*>> result, uint32_t size, Endness endness);

	private:
		uint32_t m_page_size;
	};

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::Page(uint32_t page_size)
		: m_page_size(page_size)
	{

	}

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	void Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::store(uint64_t addr, VALUE_T* data, uint32_t size, Endness endness, uint64_t page_addr, bool cooperate)
	{
		throw std::runtime_error("Page::store() Not implemented");
		// m_content[addr] = obj;
	}

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	std::vector<std::tuple<uint64_t, VALUE_T*>> Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::load_raw(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr)
	{

	}

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	nb::object Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::load(uint64_t addr, uint32_t size, Endness endness, uint64_t page_addr)
	{
		throw std::runtime_error("Page::load() Not implemented");
		// return m_content[addr];
	}

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	DECOMPOSER_T Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::decompose_objects(uint64_t addr, nb::object data, Endness endness, uint8_t byte_width, uint64_t page_addr)
	{
		return COOPERATION_T::decompose_objects(addr, data, endness, byte_width, page_addr);
	}

	template <class COOPERATION_T, class VALUE_T, class DECOMPOSER_T>
	nb::object Page<COOPERATION_T, VALUE_T, DECOMPOSER_T>::compose_objects(std::vector<std::tuple<uint64_t,VALUE_T*>> result, uint32_t size, Endness endness)
	{
		throw std::runtime_error("Page::compose_objects Not implemented");
		// nb::object r = vals[0]->get_ast();
		// return r;
	}
}

#endif

