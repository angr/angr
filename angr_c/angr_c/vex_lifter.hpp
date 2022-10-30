#include "lru_cache.hpp"

namespace py = pybind11;

namespace angr_c
{
	class VEXLifter {
	public:
		VEXLifter(
			py::object project,
			bool use_cache = false,
			size_t cache_size = 5000,
			int default_opt_level = 1,
			bool support_selfmodifying_code = false,
			bool single_step = false,
			bool default_strict_block_end = false
		);

		py::object LiftVEX(const py::kwargs& kwargs);

	private:
		void InitializeBlockCache();
		void ClearBlockCache();
		void LoadBytes(uint64_t addr, uint32_t max_size, std::optional<py::object> state, std::optional<py::object> clemory,
			// out
			uint8_t* & buff, uint32_t& size, uint32_t& offset);

		bool m_UseCache;
		int m_DefaultOptLevel;
		size_t m_CacheSize;
		bool m_SupportSelfmodifyingCode;
		bool m_SingleStep;
		bool m_DefaultStrictBlockEnd;
		LRUCache<uint64_t, py::object> m_BlockCache;
		uint64_t m_BlockCacheHits;
		uint64_t m_BlockCacheMisses;
	};
}