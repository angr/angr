/*
This mixin allows memory to process symbolic sizes. It will not touch any sizes which are not ASTs with non-BVV ops.
Assumes that the data is a BV.

- symbolic load sizes will be concretized as their maximum and a warning will be logged
- symbolic store sizes will be dispatched as several conditional stores with concrete sizes
*/

#ifndef _ADDRESS_CONCRETIZATION_MIXIN_HPP_
#define _ADDRESS_CONCRETIZATION_MIXIN_HPP_

#include <nanobind/nanobind.h>
#include <stdint.h>

namespace nb = nanobind;

namespace angr_c
{
	template <class T>
	class AddressConcretizationMixin : public T {
	public:
		AddressConcretizationMixin(const nb::kwargs kwargs);
		AddressConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs);

		void store(nb::object addr, nb::object data, uint32_t size, nb::kwargs kwargs);
		nb::object load(uint64_t addr, uint32_t size, nb::kwargs kwargs);
		nb::object load(nb::object addr, uint32_t size, nb::kwargs kwargs);
	private:
		void _store_one_addr(uint64_t concrete_addr, nb::object data, bool trivial, nb::object addr, nb::object condition, uint32_t size, nb::kwargs kwargs);
		nb::object _load_one_addr(uint64_t concrete_addr, bool trivial, nb::object addr, nb::object condition, uint32_t size, nb::kwargs kwargs);
	};

	template <class T>
	AddressConcretizationMixin<T>::AddressConcretizationMixin(const nb::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	AddressConcretizationMixin<T>::AddressConcretizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void AddressConcretizationMixin<T>::_store_one_addr(uint64_t concrete_addr, nb::object data, bool trivial, nb::object addr, nb::object condition, uint32_t size, nb::kwargs kwargs)
	{
		T::store(concrete_addr, data, size, kwargs);
	}


	template <class T>
	void AddressConcretizationMixin<T>::store(nb::object addr, nb::object data, uint32_t size, nb::kwargs kwargs)
	{
		if (nb::hasattr(addr, "op") && nb::cast<std::string>(addr.attr("op")) == "BVV") {
			nb::tuple tpl = nb::cast<nb::tuple>(addr.attr("args"));
			return _store_one_addr(nb::cast<uint64_t>(tpl[0]), data, true, addr, nb::none(), size, kwargs);
		}
	}

	template <class T>
	nb::object AddressConcretizationMixin<T>::_load_one_addr(uint64_t concrete_addr, bool trivial, nb::object addr, nb::object condition, uint32_t size, nb::kwargs kwargs)
	{
		// TODO: Handle trivial

		nb::object sub_value = T::load(concrete_addr, size, kwargs);

		// TODO: Handle read_value

		return sub_value;
	}

	template <class T>
	nb::object AddressConcretizationMixin<T>::load(uint64_t addr, uint32_t size, nb::kwargs kwargs)
	{
		return _load_one_addr(addr, true, nb::none(), nb::none(), size, kwargs);
	}

	template <class T>
	nb::object AddressConcretizationMixin<T>::load(nb::object addr, uint32_t size, nb::kwargs kwargs)
	{
		if (nb::hasattr(addr, "op") && nb::cast<std::string>(addr.attr("op")) == "BVV") {
			nb::tuple tpl = nb::cast<nb::tuple>(addr.attr("args"));
			return _load_one_addr(nb::cast<uint64_t>(tpl[0]), true, addr, nb::none(), size, kwargs);
		}

		// TODO:
		return nb::none();
	}
}

#endif