#include "memories.hpp"
#include "memory_mixins/pages/list_page.hpp"
#include "memory_mixins/memory_mixin_base.hpp"
#include "memory_mixins/paged_memory_mixin.hpp"
#include "memory_mixins/data_normalization_mixin.hpp"
#include "memory_mixins/size_concretization_mixin.hpp"
#include "memory_mixins/size_normalization_mixin.hpp"
#include "memory_mixins/address_concretization_mixin.hpp"
#include "memory_mixins/pages/cooperation.hpp"
#include "memory_mixins/endness.hpp"


namespace angr_c
{
	typedef DataNormalizationMixin<
		SizeConcretizationMixin<
		SizeNormalizationMixin<
		AddressConcretizationMixin<
		PagedMemoryMixin<MemoryMixinBase, ListPage<MemoryObjectMixin<SimMemoryObject>,SimMemoryObject>>
		>
		>
		>
	> DefaultMemory;

	void register_memory_class(py::module_& m)
	{
		py::class_<DefaultMemory>(m, "DefaultMemory")
			.def(py::init<
				const py::kwargs&>())
			.def(py::init<
				uint32_t,  // bits
				uint32_t,  // byte_width
				Endness,
				py::kwargs
				>())
			.def("store", &DefaultMemory::store, "TODO")
			.def("load", &DefaultMemory::load, "TODO");
		py::enum_<Endness>(m, "Endness")
			.value("Unspecified", Unspecified)
			.value("BE", BE)
			.value("LE", LE)
			.export_values();
	}
}