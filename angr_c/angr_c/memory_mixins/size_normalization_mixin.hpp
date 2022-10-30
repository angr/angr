/*
Provides basic services related to normalizing sizes. After this mixin, sizes will always be a plain int.
Assumes that the data is a BV.

- load will throw a TypeError if no size is provided
- store will default to len(data)//byte_width if no size is provided
*/

#ifndef _SIZE_NORMALIZATION_MIXIN_HPP_
#define _SIZE_NORMALIZATION_MIXIN_HPP_

#include <pybind11/pybind11.h>
#include <stdint.h>

namespace py = pybind11;


namespace angr_c
{
	template <class T>
	class SizeNormalizationMixin : public T {
	public:
		SizeNormalizationMixin(const py::kwargs kwargs);
		SizeNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs);

		void store(py::object addr, py::object data, py::object size, py::kwargs kwargs);
		py::object load(py::object addr, py::object size, py::kwargs kwargs);
	};

	template <class T>
	SizeNormalizationMixin<T>::SizeNormalizationMixin(const py::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	SizeNormalizationMixin<T>::SizeNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	py::object SizeNormalizationMixin<T>::load(py::object addr, py::object size, py::kwargs kwargs)
	{
		uint32_t out_size;
		if (size.is_none()) {
			throw py::type_error("Must provide size to load");
		}
		if (py::isinstance<py::int_>(size)) {
			out_size = size.cast<uint32_t>();
		}
		else if (py::hasattr(size, "op") && size.attr("op").cast<std::string>() == "BVV") {
			out_size = size.attr("args")[0].cast<uint32_t>();
		}
		else {
			throw py::value_error("Size must be concretely resolved by this point in the memory stack");
		}
		return T::load(addr, out_size, kwargs);
	}

	template <class T>
	void SizeNormalizationMixin<T>::store(py::object addr, py::object data, py::object size, py::kwargs kwargs)
	{
		uint32_t max_size = data.attr("__len__")().cast<uint32_t>() / this->byte_width;
		uint32_t out_size;
		if (size.is_none()) {
			out_size = max_size;
		}
		else if (py::isinstance<py::int_>(size)) {
			out_size = size.cast<uint32_t>();
		}
		else if (py::hasattr(size, "op") && size.attr("op").cast<std::string>() == "BVV") {
			out_size = size.attr("args").cast<py::tuple>()[0].cast<uint32_t>();
		}
		else {
			throw py::value_error("Size must be concretely resolved by this point in the memory stack");
		}

		if (out_size > max_size) {
			// raise SimMemoryError("Not enough data for store")
			throw py::value_error("Not enough data for store");
		}

		if (out_size == 0) {
			// skip zero-sized stores
			return;
		}

		T::store(addr, data, out_size, kwargs);
	}
}

#endif