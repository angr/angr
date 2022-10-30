#ifndef _DATA_NORMALIZATION_MIXIN_HPP_
#define _DATA_NORMALIZATION_MIXIN_HPP_

#include <pybind11/pybind11.h>
#include <stdint.h>

namespace py = pybind11;


namespace angr_c
{
	extern py::object claripyAstBV;
	extern py::object claripyBVV;
	extern py::object claripyFPV;
	extern py::object claripyFSORT_FLOAT;
	extern py::object claripyFSORT_DOUBLE;

	template <class T>
	class DataNormalizationMixin: public T {
	public:
		DataNormalizationMixin(const py::kwargs kwargs);
		DataNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs);

		void store(py::object addr, py::object data, py::object size, py::kwargs kwargs);
		py::object load(py::object addr, py::object size, py::kwargs kwargs);
	private:
		py::object _convert_to_ast(py::object thing, py::object size, uint32_t byte_with);
	};

	template <class T>
	DataNormalizationMixin<T>::DataNormalizationMixin(const py::kwargs kwargs)
		: T(kwargs)
	{

	}

	template <class T>
	DataNormalizationMixin<T>::DataNormalizationMixin(uint32_t bits, uint32_t byte_width, Endness endness, py::kwargs kwargs)
		: T(bits, byte_width, endness, kwargs)
	{

	}

	template <class T>
	void DataNormalizationMixin<T>::store(py::object addr, py::object data, py::object size, py::kwargs kwargs)
	{
		auto data_bv = _convert_to_ast(data, size, this->byte_width);

		if (data_bv.attr("__len__")().cast<int>() % this->byte_width != 0) {
			// raise SimMemoryError("Attempting to store non-byte data to memory")
			throw py::type_error("Attempting to store non-byte data to memory");
		}

		T::store(addr, data_bv, size, kwargs);
	}

	template <class T>
	py::object DataNormalizationMixin<T>::load(py::object addr, py::object size, py::kwargs kwargs)
	{
		return T::load(addr, size, kwargs);
	}

	template <class T>
	py::object DataNormalizationMixin<T>::_convert_to_ast(py::object thing, py::object size, uint32_t byte_width)
	{
		if (thing.get_type().is(claripyAstBV)) {
			return thing;
		}

		int32_t bits = -1;
		if (py::isinstance<py::int_>(thing)) {
			bits = thing.cast<int>() * byte_width;
		}
		else if (py::hasattr(thing, "op") && size.attr("op").cast<std::string>() == "BVV") {
			bits = size.attr("args")()[0].cast<int>() * byte_width;
		}

		if (py::isinstance<py::str>(thing)) {
			// l.warning("Encoding unicode string for memory as utf-8. Did you mean to use a bytestring?")
			thing = thing.attr("encode")("utf-8");
		}
		if (py::isinstance<py::bytes>(thing) || py::isinstance<py::bytearray>(thing) || py::isinstance<py::memoryview>(thing)) {
			return claripyBVV(thing);
		}
		if (py::isinstance<py::int_>(thing)) {
			if (bits == -1) {
				// l.warning("Unknown size for memory data %#x. Default to arch.bits.", thing)
				bits = this->bits;
			}
			return claripyBVV(thing, bits);
		}
		if (py::isinstance<py::float_>(thing)) {
			switch (bits) {
			case 32:
				return claripyFPV(thing, claripyFSORT_FLOAT).attr("raw_to_bv")();
			case 64:
				return claripyFPV(thing, claripyFSORT_DOUBLE).attr("raw_to_bv")();
			default:
				throw py::type_error("Passed float size which is not a float or a double");
			}
		}
		if (py::hasattr(thing, "raw_to_bv")) {
			return thing.attr("raw_to_bv")();
		}
		throw py::type_error("Bad value passed to memory");
	}
}

#endif