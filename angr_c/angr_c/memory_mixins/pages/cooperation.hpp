#ifndef _COOPERATION_H_
#define _COOPERATION_H_

#include <vector>
#include <tuple>
#include <pybind11/pybind11.h>
#include "../endness.hpp"
#include "decomposer.hpp"

namespace py = pybind11;


namespace angr_c
{
	template <class VALUE_T>
	class CooperationBase {
	public:
		static Decomposer decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr);
		static py::object force_load_cooperation(std::vector<std::tuple<uint64_t, std::shared_ptr<VALUE_T>>> &result, uint32_t size, Endness endness);
		static py::object compose_objects(std::vector<std::tuple<uint64_t, std::shared_ptr<VALUE_T>>> &result, uint32_t size, Endness endness);
	};

	template <class VALUE_T>
	py::object CooperationBase<VALUE_T>::force_load_cooperation(std::vector<std::tuple<uint64_t, std::shared_ptr<VALUE_T>>> &result, uint32_t size, Endness endness)
	{
		return compose_objects(result, size, endness);
	}

	/*
		Uses SimMemoryObjects in region storage.
		With this, load will return a list of tuple (address, MO) and store will take a MO.
	*/
	template <class VALUE_T>
	class MemoryObjectMixin : public CooperationBase<VALUE_T> {
	public:
		static MemoryObjectDecomposer decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr);
		static py::object compose_objects(std::vector<std::tuple<uint64_t, std::shared_ptr<VALUE_T>>> &result, uint32_t size, Endness endness);
	};

	template <class VALUE_T>
	MemoryObjectDecomposer MemoryObjectMixin<VALUE_T>::decompose_objects(uint64_t addr, py::object data, Endness endness, uint8_t byte_width, uint64_t page_addr)
	{
		auto decomposer = MemoryObjectDecomposer(addr, data, byte_width, endness, page_addr);
		return decomposer;
	}

	template <class VALUE_T>
	py::object MemoryObjectMixin<VALUE_T>::compose_objects(std::vector<std::tuple<uint64_t, std::shared_ptr<VALUE_T>>> &result, uint32_t size, Endness endness)
	{
		// TODO:
		return std::get<1>(result[0])->get_ast();
	}
}

#endif