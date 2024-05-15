/*
This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
Assumes that the data is a BV.

- symbolic load sizes will be concretized as their maximum and a warning will be logged
- symbolic store sizes will be dispatched as several conditional stores with concrete sizes
*/

#ifndef _SIZE_CONCRETIZATION_MIXIN_HPP_
#define _SIZE_CONCRETIZATION_MIXIN_HPP_

#include <nanobind/nanobind.h>
#include <stdint.h>

namespace nb = nanobind;

namespace angr_c
{
	template <class T>
	class SizeConcretizationMixin : public T {
	public:
		SizeConcretizationMixin(const nb::kwargs kwargs);
		SizeConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs);

		void store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs);
		nb::object load(nb::object addr, nb::object size, nb::kwargs kwargs);
	};

	template <class T>
	SizeConcretizationMixin<T>::SizeConcretizationMixin(const nb::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	SizeConcretizationMixin<T>::SizeConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void SizeConcretizationMixin<T>::store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs)
	{
		if (nb::hasattr(size, "op") && nb::cast<std::string>(size.attr("op")) == "BVV") {
			T::store(addr, data, size, kwargs);
			return;
		}

		// TODO: Concretization
	}

	template <class T>
	nb::object SizeConcretizationMixin<T>::load(nb::object addr, nb::object size, nb::kwargs kwargs)
	{
		if (nb::hasattr(size, "op") && nb::cast<std::string>(size.attr("op")) == "BVV") {
			return T::load(addr, size, kwargs);
		}

		// TODO: Concretization
		return nb::none();
	}
}

#endif
