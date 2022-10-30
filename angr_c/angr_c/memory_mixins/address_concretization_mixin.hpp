/*
This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
Assumes that the data is a BV.

- symbolic load sizes will be concretized as their maximum and a warning will be logged
- symbolic store sizes will be dispatched as several conditional stores with concrete sizes
*/

#ifndef _ADDRESS_CONCRETIZATION_MIXIN_HPP_
#define _ADDRESS_CONCRETIZATION_MIXIN_HPP_

#include <pybind11/pybind11.h>
#include <stdint.h>

namespace py = pybind11;

namespace angr_c
{
	template <class T>
	class AddressConcretizationMixin : public T {
	public:
		AddressConcretizationMixin(const py::kwargs kwargs);
		AddressConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs);

		void store(py::object addr, py::object data, uint32_t size, py::kwargs kwargs);
		py::object load(uint64_t addr, uint32_t size, py::kwargs kwargs);
		py::object load(py::object addr, uint32_t size, py::kwargs kwargs);
	private:
		void _store_one_addr(uint64_t concrete_addr, py::object data, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs);
		py::object _load_one_addr(uint64_t concrete_addr, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs);
	};

	template <class T>
	AddressConcretizationMixin<T>::AddressConcretizationMixin(const py::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	AddressConcretizationMixin<T>::AddressConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void AddressConcretizationMixin<T>::_store_one_addr(uint64_t concrete_addr, py::object data, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs)
	{
		T::store(concrete_addr, data, size, kwargs);
	}


	template <class T>
	void AddressConcretizationMixin<T>::store(py::object addr, py::object data, uint32_t size, py::kwargs kwargs)
	{
		if (py::hasattr(addr, "op") && addr.attr("op").cast<std::string>() == "BVV") {
			py::tuple tpl = addr.attr("args").cast<py::tuple>();
			return _store_one_addr(tpl[0].cast<uint64_t>(), data, true, addr, py::none(), size, kwargs);
		}
	}

	template <class T>
	py::object AddressConcretizationMixin<T>::_load_one_addr(uint64_t concrete_addr, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs)
	{
		// TODO: Handle trivial

		py::object sub_value = T::load(concrete_addr, size, kwargs);

		// TODO: Handle read_value

		return sub_value;
	}

	template <class T>
	py::object AddressConcretizationMixin<T>::load(uint64_t addr, uint32_t size, py::kwargs kwargs)
	{
		return _load_one_addr(addr, true, py::none(), py::none(), size, kwargs);
	}

	template <class T>
	py::object AddressConcretizationMixin<T>::load(py::object addr, uint32_t size, py::kwargs kwargs)
	{
		if (py::hasattr(addr, "op") && addr.attr("op").cast<std::string>() == "BVV") {
			py::tuple tpl = addr.attr("args").cast<py::tuple>();
			return _load_one_addr(tpl[0].cast<uint64_t>(), true, addr, py::none(), size, kwargs);
		}

		// TODO:
		return py::none();
	}
}

#endif