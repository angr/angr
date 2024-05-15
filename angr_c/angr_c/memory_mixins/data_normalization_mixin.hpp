#ifndef _DATA_NORMALIZATION_MIXIN_HPP_
#define _DATA_NORMALIZATION_MIXIN_HPP_

#include <nanobind/nanobind.h>
#include <stdint.h>

namespace nb = nanobind;


namespace angr_c
{
	extern nb::object claripyAstBV;
	extern nb::object claripyBVV;
	extern nb::object claripyFPV;
	extern nb::object claripyFSORT_FLOAT;
	extern nb::object claripyFSORT_DOUBLE;

	template <class T>
	class DataNormalizationMixin: public T {
	public:
		DataNormalizationMixin(const nb::kwargs kwargs);
		DataNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs);

		void store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs);
		nb::object load(nb::object addr, nb::object size, nb::kwargs kwargs);
	private:
		nb::object _convert_to_ast(nb::object thing, nb::object size, uint32_t byte_with);
	};

	template <class T>
	DataNormalizationMixin<T>::DataNormalizationMixin(const nb::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	DataNormalizationMixin<T>::DataNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, nb::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void DataNormalizationMixin<T>::store(nb::object addr, nb::object data, nb::object size, nb::kwargs kwargs)
	{
		auto data_bv = _convert_to_ast(data, size, this->byte_width);

		if (nb::cast<int>(data_bv.attr("__len__")()) % this->byte_width != 0) {
			// raise SimMemoryError("Attempting to store non-byte data to memory")
			throw nb::type_error("Attempting to store non-byte data to memory");
		}

		T::store(addr, data_bv, size, kwargs);
	}

	template <class T>
	nb::object DataNormalizationMixin<T>::load(nb::object addr, nb::object size, nb::kwargs kwargs)
	{
		return T::load(addr, size, kwargs);
	}

	template <class T>
	nb::object DataNormalizationMixin<T>::_convert_to_ast(nb::object thing, nb::object size, uint32_t byte_width)
	{
		if (thing.type().is(claripyAstBV)) {
			return thing;
		}

		int32_t bits = -1;
		if (nb::isinstance<nb::int_>(thing)) {
			bits = nb::cast<int>(thing) * byte_width;
		}
		else if (nb::hasattr(thing, "op") && nb::cast<std::string>(size.attr("op")) == "BVV") {
			bits = nb::cast<int>(size.attr("args")()[0]) * byte_width;
		}

		if (nb::isinstance<nb::str>(thing)) {
			// l.warning("Encoding unicode string for memory as utf-8. Did you mean to use a bytestring?")
			thing = thing.attr("encode")("utf-8");
		}
		if (nb::isinstance<nb::bytes>(thing)) {
			// TODO: Optimize it - why do we want to convert bytes into BVVs?
			return claripyBVV(thing);
		}
		if (nb::isinstance<nb::int_>(thing)) {
			if (bits == -1) {
				// l.warning("Unknown size for memory data %#x. Default to arch.bits.", thing)
				bits = this->bits;
			}
			return claripyBVV(thing, bits);
		}
		if (nb::isinstance<nb::float_>(thing)) {
			switch (bits) {
			case 32:
				return claripyFPV(thing, claripyFSORT_FLOAT).attr("raw_to_bv")();
			case 64:
				return claripyFPV(thing, claripyFSORT_DOUBLE).attr("raw_to_bv")();
			default:
				throw nb::type_error("Passed float size which is not a float or a double");
			}
		}
		if (nb::hasattr(thing, "raw_to_bv")) {
			return thing.attr("raw_to_bv")();
		}
		throw nb::type_error("Bad value passed to memory");
	}
}

#endif