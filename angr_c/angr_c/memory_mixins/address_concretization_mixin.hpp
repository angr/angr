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
		// TODO: load
	private:
		void _store_one_addr(uint64_t concrete_addr, py::object data, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs);
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
	void AddressConcretizationMixin<T>::store(py::object addr, py::object data, uint32_t size, py::kwargs kwargs)
	{
		
	}

	template <class T>
	void AddressConcretizationMixin<T>::_store_one_addr(uint64_t concrete_addr, py::object data, bool trivial, py::object addr, py::object condition, uint32_t size, py::kwargs kwargs)
	{
		T::store(concrete_addr, data, size, kwargs);
	}
}

#endif