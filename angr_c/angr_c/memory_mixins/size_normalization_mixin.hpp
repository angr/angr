/*
Provides basic services related to normalizing sizes. After this mixin, sizes will always be a plain int.
Assumes that the data is a BV.

- load will throw a TypeError if no size is provided
- store will default to len(data)//byte_width if no size is provided
*/

#ifndef _SIZE_NORMALIZATION_MIXIN_HPP_
#define _SIZE_NORMALIZATION_MIXIN_HPP_

#include <nanobind/nanobind.h>
#include <stdint.h>

namespace nb = nanobind;


namespace angr_c
{
	template <class T>
	class SizeNormalizationMixin : public T {
	public:
		SizeNormalizationMixin(const nb::kwargs kwargs);
		SizeNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs);

		void store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs);
		nb::object load(nb::object addr, nb::object size, nb::kwargs kwargs);
	};

	template <class T>
	SizeNormalizationMixin<T>::SizeNormalizationMixin(const nb::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	SizeNormalizationMixin<T>::SizeNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	nb::object SizeNormalizationMixin<T>::load(nb::object addr, nb::object size, nb::kwargs kwargs)
	{
		uint32_t out_size;
		if (size.is_none()) {
			throw nb::type_error("Must provide size to load");
		}
		if (nb::isinstance<nb::int_>(size)) {
			out_size = nb::cast<uint32_t>(size);
		}
		else if (nb::hasattr(size, "op") && nb::cast<std::string>(size.attr("op")) == "BVV") {
			out_size = nb::cast<uint32_t>(nb::cast<nb::tuple>(size.attr("args"))[0]);
		}
		else {
			throw nb::value_error("Size must be concretely resolved by this point in the memory stack");
		}
		return T::load(addr, out_size, kwargs);
	}

	template <class T>
	void SizeNormalizationMixin<T>::store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs)
	{
		uint32_t max_size = nb::cast<uint32_t>(data.attr("__len__")()) / this->byte_width;
		uint32_t out_size;
		if (size.is_none()) {
			out_size = max_size;
		}
		else if (nb::isinstance<nb::int_>(size)) {
			out_size = nb::cast<uint32_t>(size);
		}
		else if (nb::hasattr(size, "op") && nb::cast<std::string>(size.attr("op")) == "BVV") {
			out_size = nb::cast<uint32_t>(nb::cast<nb::tuple>(size.attr("args"))[0]);
		}
		else {
			throw nb::value_error("Size must be concretely resolved by this point in the memory stack");
		}

		if (out_size > max_size) {
			// raise SimMemoryError("Not enough data for store")
			throw nb::value_error("Not enough data for store");
		}

		if (out_size == 0) {
			// skip zero-sized stores
			return;
		}

		T::store(addr, data, out_size, kwargs);
	}
}

#endif