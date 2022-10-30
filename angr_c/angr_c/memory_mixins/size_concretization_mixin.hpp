/*
This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
Assumes that the data is a BV.

- symbolic load sizes will be concretized as their maximum and a warning will be logged
- symbolic store sizes will be dispatched as several conditional stores with concrete sizes
*/

#ifndef _SIZE_CONCRETIZATION_MIXIN_HPP_
#define _SIZE_CONCRETIZATION_MIXIN_HPP_

#include <pybind11/pybind11.h>
#include <stdint.h>

namespace py = pybind11;

namespace angr_c
{
	template <class T>
	class SizeConcretizationMixin : public T {
	public:
		SizeConcretizationMixin(const py::kwargs kwargs);
		SizeConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs);

		void store(py::object addr, py::object data, py::object size, py::kwargs kwargs);
		// TODO: load
	};

	template <class T>
	SizeConcretizationMixin<T>::SizeConcretizationMixin(const py::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	SizeConcretizationMixin<T>::SizeConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void SizeConcretizationMixin<T>::store(py::object addr, py::object data, py::object size, py::kwargs kwargs)
	{
		if (py::hasattr(size, "op") && size.attr("op").cast<std::string>() == "BVV") {
			T::store(addr, data, size, kwargs);
			return;
		}

		// TODO: Concretization
	}
}

#endif