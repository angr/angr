#include <stdint.h>
#include <optional>
#include <algorithm>
#include <string>
#include <nanobind/nanobind.h>

#include "vex_lifter.hpp"

using namespace nb::literals;

const uint32_t VEX_IRSB_MAX_SIZE = 400;
const uint32_t VEX_IRSB_MAX_INST = 99;


namespace angr_c
{
	extern nb::object Clemory;

	VEXLifter::VEXLifter(
		nb::object project,
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
		m_BlockCache = LRUCache<uint64_t, nb::object>(m_CacheSize);
		m_BlockCacheHits = 0;
		m_BlockCacheMisses = 0;
	}

	void VEXLifter::ClearBlockCache()
	{
		m_BlockCache = LRUCache<uint64_t, nb::object>(m_CacheSize);
		m_BlockCacheHits = 0;
		m_BlockCacheMisses = 0;
	}

	nb::object VEXLifter::LiftVEX(const nb::kwargs& kwargs)
	{
		//
		// phase 0: sanity check
		//
		std::optional<nb::object> state(std::nullopt);
		std::optional<nb::object> clemory(std::nullopt);
		std::optional<nb::object> insn_bytes(std::nullopt);
		std::optional<nb::object> arch(std::nullopt);
		std::optional<uint64_t> addr(std::nullopt);
		std::optional<bool> single_step(std::nullopt);
		std::optional<uint32_t> size(std::nullopt);
		std::optional<uint32_t> num_inst(std::nullopt);
		std::optional<uint32_t> opt_level(std::nullopt);
		std::optional<bool> cross_insn_opt(std::nullopt);
		std::optional<bool> strict_block_end(std::nullopt);
		bool skip_stmts = false;
		bool collect_data_refs = false;
		bool load_from_ro_regions = false;
		uint32_t offset = 0;
		int thumb = 0;

		if (kwargs.contains("state")) {
			nb::object arg = kwargs["state"];
			if (!arg.is_none()) {
				state = arg;
			}
		}

		if (kwargs.contains("clemory")) {
			nb::object arg = kwargs["clemory"];
			if (!arg.is_none()) {
				clemory = arg;
			}
		}

		if (kwargs.contains("insn_bytes")) {
			nb::object arg = kwargs["insn_bytes"];
			if (!arg.is_none()) {
				insn_bytes = arg;
			}
		}

		if (kwargs.contains("arch")) {
			nb::object arg = kwargs["arch"];
			if (!arg.is_none()) {
				arch = arg;
			}
		}

		if (kwargs.contains("addr")) {
			nb::object arg = kwargs["addr"];
			if (!arg.is_none()) {
				addr = nb::cast<uint64_t>(arg);
			}
		}

		if (kwargs.contains("size")) {
			nb::object arg = kwargs["size"];
			if (!arg.is_none()) {
				size = nb::cast<uint32_t>(arg);
			}
		}

		if (kwargs.contains("num_inst")) {
			nb::object arg = kwargs["num_inst"];
			if (!arg.is_none()) {
				num_inst = nb::cast<uint32_t>(arg);
			}
		}

		if (kwargs.contains("offset")) {
			nb::object arg = kwargs["offset"];
			if (!arg.is_none()) {
				offset = nb::cast<uint32_t>(arg);
			}
		}

		if (kwargs.contains("thumb")) {
			nb::object arg = kwargs["thumb"];
			if (!arg.is_none()) {
				thumb = nb::cast<bool>(arg)? 1: 0;
			}
		}

		if (kwargs.contains("single_step")) {
			nb::object arg = kwargs["single_step"];
			if (!arg.is_none()) {
				single_step = nb::cast<bool>(arg);
			}
		}

		if (kwargs.contains("opt_level")) {
			nb::object arg = kwargs["opt_level"];
			if (!arg.is_none()) {
				opt_level = nb::cast<uint32_t>(arg);
			}
		}

		if (kwargs.contains("cross_insn_opt")) {
			nb::object arg = kwargs["cross_insn_opt"];
			if (!arg.is_none()) {
				cross_insn_opt = nb::cast<bool>(arg);
			}
		}

		if (kwargs.contains("strict_block_end")) {
			nb::object arg = kwargs["strict_block_end"];
			if (!arg.is_none()) {
				strict_block_end = nb::cast<bool>(arg);
			}
		}

		if (kwargs.contains("collect_data_refs")) {
			nb::object arg = kwargs["collect_data_refs"];
			if (!arg.is_none()) {
				collect_data_refs = nb::cast<bool>(arg);
			}
		}

		if (kwargs.contains("load_from_ro_regions")) {
			nb::object arg = kwargs["load_from_ro_regions"];
			if (!arg.is_none()) {
				load_from_ro_regions = nb::cast<bool>(arg);
			}
		}

		if (kwargs.contains("skip_stmts")) {
			nb::object arg = kwargs["skip_stmts"];
			if (!arg.is_none()) {
				skip_stmts = nb::cast<bool>(arg);
			}
		}

		if (!state && !clemory && !insn_bytes) {
			throw nb::value_error("Must provide state or clemory or insn_bytes");
		}
		if (!state && !clemory && !arch) {
			throw nb::value_error("Must provide state or clemory or arch");
		}
		if (!addr && !state) {
			throw nb::value_error("Must provide state or addr");
		}
		if (!arch) {
			if (clemory) {
				arch = (*clemory).attr("_arch");
			}
			else {
				arch = (*state).attr("arch");
			}
		}
		if (nb::cast<std::string>((*arch).attr("name")).rfind("MIPS", 0) == 0
			&& single_step && *single_step) {
			// TODO: l.error("Cannot specify single-stepping on MIPS.")
			single_step = false;
		}

		//
		// phase 1: parameter defaults
		//
		if (!addr) {
			addr = nb::cast<uint64_t>((*state).attr("solver").attr("eval")((*state).attr("_ip")));
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
			if (state && nb::cast<bool>((*state).attr("options").attr("__contains__")("OPTIMIZE_IR"))) {
				opt_level = 1;
			}
			else {
				opt_level = m_DefaultOptLevel;
			}
		}
		if (!cross_insn_opt) {
			if (state && nb::cast<bool>((*state).attr("options").attr("__contains__")("NO_CROSS_INSN_OPT"))) {
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
				if (state && nb::cast<bool>((*state).attr("options").attr("__contains__")("OPTIMIZE_IR"))) {
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
		std::string arch_name = nb::cast<std::string>((*arch).attr("name"));
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

		std::optional<const uint8_t*> buff(std::nullopt);

		//
		// phase 4: get bytes
		//

		if (!buff) {
			if (insn_bytes) {

			}
			else {
				const uint8_t* buff_;
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

	void VEXLifter::LoadBytes(uint64_t addr, uint32_t max_size, std::optional<nb::object> state, std::optional<nb::object> clemory, const uint8_t* & buff,
		uint32_t& size, uint32_t& offset)
	{
		bool smc = m_SupportSelfmodifyingCode;
		if (!smc || !state) {
			if (clemory && (*clemory).type().is(Clemory)) {
				try {
					nb::tuple start_backer = nb::cast<nb::tuple>((*clemory).attr("backers")(addr).attr("__next__")());
					uint64_t start = nb::cast<uint64_t>(start_backer[0]);
					nb::object backer = start_backer[1];

					if (start <= addr) {
						offset = addr - start;
					}
					if (nb::isinstance<nb::bytes>(backer) || nb::isinstance<nb::bytes>(backer)) {
						nb::bytes info(backer);
						buff = static_cast<const uint8_t*>(info.data());
						size = info.size() - offset;
					}
					else if (nb::isinstance<nb::list>(backer)) {
						// TODO: SimTranslationError
						throw nb::value_error("Cannot lift block for arch with strange byte width.If you think you ought to be able to, open an issue.");
					}
					else {
						throw nb::type_error("Unsupported backer type");
					}
				}
				catch (nb::python_error& ex) {
					if (ex.matches(PyExc_StopIteration)) {
						;
					}
					else {
						throw;
					}
				}
			}
			else if (state) {
				if (nb::cast<bool>((*state).attr("memory").attr("SUPPORTS_CONCRETE_LOAD"))) {
					nb::object buff_ = (*state).attr("memory").attr("concrete_load")(addr, max_size);
					nb::bytes info(buff_);
					buff = static_cast<const uint8_t*>(info.data());
					size = info.size();
				}
				else {
					nb::object data_ = (*state).attr("memory").attr("load")(addr, max_size, "inspect"_a = false);
					nb::object buff_ = (*state).attr("solver").attr("eval")(data_, "cast_to"_a = nb::bytes());
				}
			}
		}
	}
}