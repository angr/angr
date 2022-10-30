#include <stdint.h>
#include <optional>
#include <algorithm>
#include <string>
#include <pybind11/pybind11.h>

#include "vex_lifter.hpp"

using namespace py::literals;

const uint32_t VEX_IRSB_MAX_SIZE = 400;
const uint32_t VEX_IRSB_MAX_INST = 99;


namespace angr_c
{
	extern py::object Clemory;

	VEXLifter::VEXLifter(
		py::object project,
		bool use_cache,
		size_t cache_size,
		int default_opt_level,
		bool support_selfmodifying_code,
		bool single_step,
		bool default_strict_block_end
	) :
		m_UseCache(use_cache),
		m_CacheSize(cache_size),
		m_DefaultOptLevel(default_opt_level),
		m_SupportSelfmodifyingCode(support_selfmodifying_code),
		m_SingleStep(single_step),
		m_DefaultStrictBlockEnd(default_strict_block_end),
		m_BlockCache(m_CacheSize),
		m_BlockCacheHits(0),
		m_BlockCacheMisses(0)
	{

	}

	void VEXLifter::InitializeBlockCache()
	{
		m_BlockCache = LRUCache<uint64_t, py::object>(m_CacheSize);
		m_BlockCacheHits = 0;
		m_BlockCacheMisses = 0;
	}

	void VEXLifter::ClearBlockCache()
	{
		m_BlockCache = LRUCache<uint64_t, py::object>(m_CacheSize);
		m_BlockCacheHits = 0;
		m_BlockCacheMisses = 0;
	}

	py::object VEXLifter::LiftVEX(const py::kwargs& kwargs)
	{
		//
		// phase 0: sanity check
		//
		std::optional<py::object> state(std::nullopt);
		std::optional<py::object> clemory(std::nullopt);
		std::optional<py::object> insn_bytes(std::nullopt);
		std::optional<py::object> arch(std::nullopt);
		std::optional<uint64_t> addr(std::nullopt);
		std::optional<bool> single_step(std::nullopt);
		std::optional<uint32_t> size(std::nullopt);
		std::optional<uint32_t> num_inst(std::nullopt);
		std::optional<bool> opt_level(std::nullopt);
		std::optional<bool> cross_insn_opt(std::nullopt);
		std::optional<bool> strict_block_end(std::nullopt);
		bool skip_stmts = false;
		bool collect_data_refs = false;
		bool load_from_ro_regions = false;
		uint32_t offset = 0;
		int thumb = 0;

		if (kwargs.contains("state")) {
			py::object arg = kwargs["state"];
			if (!arg.is_none()) {
				state = arg;
			}
		}

		if (kwargs.contains("clemory")) {
			py::object arg = kwargs["clemory"];
			if (!arg.is_none()) {
				clemory = arg;
			}
		}

		if (kwargs.contains("insn_bytes")) {
			py::object arg = kwargs["insn_bytes"];
			if (!arg.is_none()) {
				insn_bytes = arg;
			}
		}

		if (kwargs.contains("arch")) {
			py::object arg = kwargs["arch"];
			if (!arg.is_none()) {
				arch = arg;
			}
		}

		if (kwargs.contains("addr")) {
			py::object arg = kwargs["addr"];
			if (!arg.is_none()) {
				addr = arg.cast<uint64_t>();
			}
		}

		if (kwargs.contains("size")) {
			py::object arg = kwargs["size"];
			if (!arg.is_none()) {
				size = arg.cast<uint32_t>();
			}
		}

		if (kwargs.contains("num_inst")) {
			py::object arg = kwargs["num_inst"];
			if (!arg.is_none()) {
				num_inst = arg.cast<uint32_t>();
			}
		}

		if (kwargs.contains("offset")) {
			py::object arg = kwargs["offset"];
			if (!arg.is_none()) {
				offset = arg.cast<uint32_t>();
			}
		}

		if (kwargs.contains("thumb")) {
			py::object arg = kwargs["thumb"];
			if (!arg.is_none()) {
				thumb = arg.cast<bool>()? 1: 0;
			}
		}

		if (kwargs.contains("single_step")) {
			py::object arg = kwargs["single_step"];
			if (!arg.is_none()) {
				single_step = arg.cast<bool>();
			}
		}

		if (kwargs.contains("opt_level")) {
			py::object arg = kwargs["opt_level"];
			if (!arg.is_none()) {
				opt_level = arg.cast<bool>();
			}
		}

		if (kwargs.contains("cross_insn_opt")) {
			py::object arg = kwargs["cross_insn_opt"];
			if (!arg.is_none()) {
				cross_insn_opt = arg.cast<bool>();
			}
		}

		if (kwargs.contains("strict_block_end")) {
			py::object arg = kwargs["strict_block_end"];
			if (!arg.is_none()) {
				strict_block_end = arg.cast<bool>();
			}
		}

		if (kwargs.contains("collect_data_refs")) {
			py::object arg = kwargs["collect_data_refs"];
			if (!arg.is_none()) {
				collect_data_refs = arg.cast<bool>();
			}
		}

		if (kwargs.contains("load_from_ro_regions")) {
			py::object arg = kwargs["load_from_ro_regions"];
			if (!arg.is_none()) {
				load_from_ro_regions = arg.cast<bool>();
			}
		}

		if (kwargs.contains("skip_stmts")) {
			py::object arg = kwargs["skip_stmts"];
			if (!arg.is_none()) {
				skip_stmts = arg.cast<bool>();
			}
		}

		if (!state && !clemory && !insn_bytes) {
			throw py::value_error("Must provide state or clemory or insn_bytes");
		}
		if (!state && !clemory && !arch) {
			throw py::value_error("Must provide state or clemory or arch");
		}
		if (!addr && !state) {
			throw py::value_error("Must provide state or addr");
		}
		if (!arch) {
			if (clemory) {
				arch = (*clemory).attr("_arch");
			}
			else {
				arch = (*state).attr("arch");
			}
		}
		if ((*arch).attr("name").cast<std::string>().rfind("MIPS", 0) == 0 
			&& single_step && *single_step) {
			// TODO: l.error("Cannot specify single-stepping on MIPS.")
			single_step = false;
		}

		//
		// phase 1: parameter defaults
		//
		if (!addr) {
			addr = (*state).attr("solver").attr("eval")((*state).attr("_ip")).cast<uint64_t>();
		}
		if (size) {
			size = std::min(*size, VEX_IRSB_MAX_SIZE);
		}
		else {
			size = VEX_IRSB_MAX_SIZE;
		}
		if (num_inst) {
			num_inst = std::min(*num_inst, VEX_IRSB_MAX_INST);
		}
		if (!num_inst && *single_step) {
			num_inst = 1;
		}
		if (!opt_level) {
			if (state && (*state).attr("options").attr("__contains__")("OPTIMIZE_IR").cast<bool>()) {
				opt_level = 1;
			}
			else {
				opt_level = m_DefaultOptLevel;
			}
		}
		if (!cross_insn_opt) {
			if (state && (*state).attr("options").attr("__contains__")("NO_CROSS_INSN_OPT").cast<bool>()) {
				cross_insn_opt = false;
			}
			else {
				cross_insn_opt = true;
			}
		}
		if (!strict_block_end) {
			strict_block_end = m_DefaultStrictBlockEnd;
		}
		if (m_SupportSelfmodifyingCode) {
			if (*opt_level > 0) {
				// TODO:
				// l.warning("Self-modifying code is not always correctly optimized by PyVEX. To guarantee correctness, VEX optimizations have been disabled.")
				opt_level = 0;
				if (state && (*state).attr("options").attr("__contains__")("OPTIMIZE_IR").cast<bool>()) {
					(*state).attr("options").attr("remove")("OPTIMIZE_IR");
				}
			}
		}
		
		bool use_cache = m_UseCache;
		if (skip_stmts || collect_data_refs) {
			// Do not cache the blocks if skip_stmts or collect_data_refs are enabled
			use_cache = false;
		}

		//
		// phase 2: thumb normalization
		//
		std::string arch_name = (*arch).attr("name").cast<std::string>();
		if (arch_name.find("ARM") != std::string::npos) {
			if (*addr % 2 == 1) {
				thumb = 1;
			}
			if (thumb == 1) {
				addr = *addr & 0xfffffffffffffffe;
			}
		}
		else if (thumb != 0) {
			// TODO: l.error("thumb=True passed on non-arm architecture!")
			thumb = 0;
		}

		//
		// phase 3: check cache
		//

		// TODO:

		std::optional<uint8_t*> buff(std::nullopt);

		//
		// phase 4: get bytes
		//

		if (!buff) {
			if (insn_bytes) {

			}
			else {
				uint8_t* buff_;
				uint32_t size_;
				LoadBytes(*addr, *size, state, clemory, buff_, size_, offset);
				buff = buff_;
				size = size_;
			}
		}

		//
		// phase 5: call into pyvex
		//
	}

	void VEXLifter::LoadBytes(uint64_t addr, uint32_t max_size, std::optional<py::object> state, std::optional<py::object> clemory, uint8_t* & buff,
		uint32_t& size, uint32_t& offset)
	{
		bool smc = m_SupportSelfmodifyingCode;
		if (!smc || !state) {
			if (clemory && py::isinstance(*clemory, Clemory)) {
				try {
					py::tuple start_backer = (*clemory).attr("backers")(addr).attr("__next__")().cast<py::tuple>();
					uint64_t start = start_backer[0].cast<uint64_t>();
					py::object backer = start_backer[1];

					if (start <= addr) {
						offset = addr - start;
					}
					if (py::isinstance<py::bytes>(backer) || py::isinstance<py::bytearray>(backer)) {
						py::buffer_info info(py::buffer(backer).request());
						buff = static_cast<uint8_t*>(info.ptr);
						size = info.size - offset;
					}
					else if (py::isinstance<py::list>(backer)) {
						// TODO: SimTranslationError
						throw py::value_error("Cannot lift block for arch with strange byte width.If you think you ought to be able to, open an issue.");
					}
					else {
						throw py::type_error("Unsupported backer type");
					}
				}
				catch (py::error_already_set& ex) {
					if (ex.matches(PyExc_StopIteration)) {
						;
					}
					else {
						throw;
					}
				}
			}
			else if (state) {
				if ((*state).attr("memory").attr("SUPPORTS_CONCRETE_LOAD").cast<bool>()) {
					py::object buff_ = (*state).attr("memory").attr("concrete_load")(addr, max_size);
					py::buffer_info info(py::buffer(buff_).request());
					buff = static_cast<uint8_t*>(info.ptr);
					size = info.size;
				}
				else {
					py::object data_ = (*state).attr("memory").attr("load")(addr, max_size, "inspect"_a = false);
					py::object buff_ = (*state).attr("solver").attr("eval")(data_, "cast_to"_a = py::bytes());
				}
			}
		}
	}
}