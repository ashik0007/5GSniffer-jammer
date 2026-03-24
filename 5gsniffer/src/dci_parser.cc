/**
 * DCI Parser implementation for 5GSniffer.
 *
 * Field extraction order follows srsRAN's dci_nr.c:
 *   - dci_nr_format_0_1_unpack() for DCI 0_1 (UL)
 *   - dci_nr_format_1_1_unpack() for DCI 1_1 (DL)
 *
 * TBS computation per TS 38.214 §5.1.3.2.
 */

#include "dci_parser.h"
#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>

// ─── TBS computation internals ─────────────────────────────────────────────────

static uint32_t tbs_from_n_info3(uint32_t n_info) {
  uint32_t n = std::max(3u, static_cast<uint32_t>(std::floor(std::log2(n_info))) - 6);
  uint32_t pow2n = 1u << n;
  uint32_t n_info_prime = std::max(TBS_TABLE[0], pow2n * (n_info / pow2n));

  for (uint32_t i = 0; i < 93; i++) {
    if (n_info_prime <= TBS_TABLE[i]) {
      return TBS_TABLE[i];
    }
  }
  return TBS_TABLE[92];
}

static uint32_t tbs_from_n_info4(uint32_t n_info, double R) {
  uint32_t n = static_cast<uint32_t>(std::floor(std::log2(n_info - 24.0)) - 5.0);
  uint32_t pow2n = 1u << n;
  uint32_t n_info_sub24 = n_info - 24;
  // round to nearest multiple of pow2n
  uint32_t n_info_prime = std::max(3840u, pow2n * ((n_info_sub24 + pow2n / 2) / pow2n));

  auto ceil_div = [](uint32_t a, uint32_t b) -> uint32_t {
    return (a + b - 1) / b;
  };

  if (R <= 0.25) {
    uint32_t C = ceil_div(n_info_prime + 24, 3816);
    return 8 * C * ceil_div(n_info_prime + 24, 8 * C) - 24;
  }

  if (n_info_prime > 8424) {
    uint32_t C = ceil_div(n_info_prime + 24, 8424);
    return 8 * C * ceil_div(n_info_prime + 24, 8 * C) - 24;
  }

  return 8 * ceil_div(n_info_prime + 24, 8) - 24;
}

// Look up MCS table entry. Returns false if mcs_idx is out of range.
static bool mcs_lookup(uint8_t table_id, uint32_t mcs_idx,
                       uint8_t& Qm, double& R_x1024, const char*& mod_str) {
  switch (table_id) {
    case 0:
      if (mcs_idx >= 29) return false;
      Qm = MCS_TABLE_1[mcs_idx].mod_order;
      R_x1024 = MCS_TABLE_1[mcs_idx].code_rate_x1024;
      mod_str = MCS_TABLE_1[mcs_idx].mod_string;
      return true;
    case 1:
      if (mcs_idx >= 28) return false;
      Qm = MCS_TABLE_2[mcs_idx].mod_order;
      R_x1024 = MCS_TABLE_2[mcs_idx].code_rate_x1024;
      mod_str = MCS_TABLE_2[mcs_idx].mod_string;
      return true;
    case 2:
      if (mcs_idx >= 29) return false;
      Qm = MCS_TABLE_3[mcs_idx].mod_order;
      R_x1024 = MCS_TABLE_3[mcs_idx].code_rate_x1024;
      mod_str = MCS_TABLE_3[mcs_idx].mod_string;
      return true;
    default:
      return false;
  }
}

// ─── Frequency domain resource size for alloc type ─────────────────────────────

static uint32_t freq_resource_size(uint8_t alloc_type, uint32_t nof_rb_groups,
                                   uint32_t bwp_active_bw) {
  if (alloc_type == 0) {
    return nof_rb_groups;
  }
  // Type 1
  return fdra_type1_width(bwp_active_bw);
}

// ─── Antenna ports size (DL) ───────────────────────────────────────────────────
// Simplified: for single-codeword, DMRS type 1, max len 1 → 4 bits
// UNVERIFIED ASSUMPTION: using 4 bits for srsRAN default config
static uint32_t dl_ports_size(const CarrierConfig& /*cfg*/) {
  return 4;
}

// ─── Antenna ports size (UL) ───────────────────────────────────────────────────
// For no transform precoding and DMRS max len 1 → 3 bits
static uint32_t ul_ports_size(const CarrierConfig& cfg) {
  if (!cfg.enable_transform_precoding && cfg.pusch_dmrs_max_len == 1) {
    return 3;
  }
  // UNVERIFIED ASSUMPTION: fallback to 3 bits
  return 3;
}

// ─── SLIV to S and L decoding ──────────────────────────────────────────────────
// Per TS 38.211 §7.3.1.1.2 (PDCCH) and TS 38.212
// Decodes Start and Length Indicator Value (SLIV) to symbol start S and length L
// N is total symbols per slot (14 for normal CP, typical for DL and UL)
void sliv_to_s_and_l(uint32_t N, uint32_t sliv, uint32_t* S, uint32_t* L) {
  uint32_t low  = sliv % N;
  uint32_t high = sliv / N;
  if (high + 1 + low <= N) {
    *S = low;
    *L = high + 1;
  } else {
    *S = N - 1 - low;
    *L = N - high + 1;
  }
}

// ─── Resolve TDRA to symbol start and length ───────────────────────────────────
// Looks up SLIV table using TDRA index and decodes to extract actual S and L.
// Returns false if TDRA index is out of range; sets S=0, L=fallback on error.
static bool resolve_tdra(uint32_t tdra_idx, const std::vector<TDRAEntry>& tdra_table,
                         uint32_t fallback_symbols,
                         uint32_t* symbol_start, uint32_t* symbol_length) {
  if (tdra_table.empty()) {
    // No TDRA table configured; use fallback
    *symbol_start = 0;
    *symbol_length = fallback_symbols;
    return false;
  }

  if (tdra_idx >= tdra_table.size()) {
    SPDLOG_WARN("TDRA index {} out of range (table size {})", tdra_idx, tdra_table.size());
    *symbol_start = 0;
    *symbol_length = fallback_symbols;
    return false;
  }

  uint32_t sliv = tdra_table[tdra_idx].sliv;
  sliv_to_s_and_l(14, sliv, symbol_start, symbol_length);
  return true;
}

// ─── Parse DCI format 0_1 (UL) ────────────────────────────────────────────────

DCIFields parse_dci_0_1(const uint8_t* payload, uint16_t nof_bits,
                        const CarrierConfig& cfg) {
  DCIFields f;
  f.dci_format = "0_1";
  f.direction = "UL";

  uint32_t offset = 0;

  // Identifier for DCI formats – 1 bit (should be 0 for UL)
  f.format_id = bit_pack(payload, &offset, 1);
  if (f.format_id != 0) {
    f.error_msg = "DCI format ID bit is 1, expected 0 for format 0_1";
    // Continue parsing anyway — the sniffer may have misidentified the format
  }

  // Carrier indicator – 0 or 3 bits
  f.carrier_indicator = bit_pack(payload, &offset,
    std::min(cfg.carrier_indicator_size, 3u));

  // UL/SUL indicator – 0 or 1 bit
  f.sul = bit_pack(payload, &offset, cfg.enable_sul ? 1 : 0);

  // Bandwidth part indicator – 0, 1 or 2 bits
  f.bwp_id = bit_pack(payload, &offset, bwp_id_size(cfg.nof_ul_bwp));

  // Frequency domain resource assignment
  uint32_t fdra_bits = freq_resource_size(cfg.pusch_alloc_type,
    cfg.nof_rb_groups, cfg.bwp_ul_active_bw);
  f.fdra = bit_pack(payload, &offset, fdra_bits);

  // Time domain resource assignment – 0 to 4 bits
  f.tdra = bit_pack(payload, &offset, time_res_size(cfg.nof_ul_time_res));

  // Frequency hopping flag – 0 or 1 bit
  if (cfg.pusch_alloc_type != 0 && cfg.enable_hopping) {
    f.freq_hopping_flag = bit_pack(payload, &offset, 1);
  }

  // MCS – 5 bits
  f.mcs = bit_pack(payload, &offset, 5);

  // NDI – 1 bit
  f.ndi = bit_pack(payload, &offset, 1);

  // RV – 2 bits
  f.rv = bit_pack(payload, &offset, 2);

  // HARQ process number – 4 bits
  f.harq_process_id = bit_pack(payload, &offset, 4);

  // 1st DAI – 1 or 2 bits
  if (cfg.harq_ack_codebook == 0) {  // semi-static
    f.dai = bit_pack(payload, &offset, 1);
  } else {
    f.dai = bit_pack(payload, &offset, 2);
  }

  // 2nd DAI – 0 or 2 bits
  if (cfg.dynamic_dual_harq_ack_codebook) {
    f.dai2 = bit_pack(payload, &offset, 2);
  }

  // TPC – 2 bits
  f.tpc = bit_pack(payload, &offset, 2);

  // SRS resource indicator
  f.srs_id = bit_pack(payload, &offset, cfg.srs_id_bits);

  // Antenna ports – 3 bits (no transform precoding, DMRS max len 1)
  f.ports = bit_pack(payload, &offset, ul_ports_size(cfg));

  // SRS request – 2 or 3 bits
  f.srs_request = bit_pack(payload, &offset, cfg.enable_sul ? 3 : 2);

  // CSI request – 0 to 6 bits
  f.csi_request = bit_pack(payload, &offset, std::min(6u, cfg.report_trigger_size));

  // CBG transmission information – 0, 2, 4, 6, or 8 bits
  f.cbg_info = bit_pack(payload, &offset, cfg.pusch_nof_cbg);

  // PTRS-DMRS association – 0 or 2 bits
  uint32_t ptrs_bits = cfg.enable_ptrs ? 2 : 0;
  f.ptrs_id = bit_pack(payload, &offset, ptrs_bits);

  // beta_offset indicator – 0 or 2 bits
  if (cfg.pusch_dynamic_betas) {
    f.beta_id = bit_pack(payload, &offset, 2);
  }

  // DMRS sequence initialization – 0 or 1 bit
  if (!cfg.enable_transform_precoding) {
    f.dmrs_id = bit_pack(payload, &offset, 1);
  }

  // UL-SCH indicator – 1 bit
  f.ulsch = bit_pack(payload, &offset, 1);

  // Validate consumed bits
  if (offset != nof_bits) {
    f.error_msg = "Parsed " + std::to_string(offset) + " bits but DCI has " +
                  std::to_string(nof_bits) + " bits";
    SPDLOG_WARN("DCI 0_1 parse mismatch: {}", f.error_msg);
    // Still mark parse_ok if we got past the critical fields
  }

  f.parse_ok = true;

  // Decode RIV → PRB start + count
  if (cfg.pusch_alloc_type == 1) {
    decode_riv(f.fdra, cfg.bwp_ul_active_bw, f.prb_start, f.nof_prbs);
  }

  // Resolve TDRA index to actual symbol start and length
  resolve_tdra(f.tdra, cfg.pusch_tdra_table, cfg.nof_pusch_symbols,
               &f.symbol_start, &f.symbol_length);

  // MCS lookup + TBS computation (using actual symbol_length from TDRA)
  f.tb_size_bytes = compute_tbs(f.mcs, f.nof_prbs, f.symbol_length, cfg, false) / 8;

  uint8_t Qm;
  double R_x1024;
  const char* mod_str;
  if (mcs_lookup(cfg.mcs_table, f.mcs, Qm, R_x1024, mod_str)) {
    f.modulation = mod_str;
    f.code_rate = R_x1024 / 1024.0;
  } else {
    f.modulation = "unknown";
  }

  return f;
}

// ─── Parse DCI format 1_1 (DL) ────────────────────────────────────────────────

DCIFields parse_dci_1_1(const uint8_t* payload, uint16_t nof_bits,
                        const CarrierConfig& cfg) {
  DCIFields f;
  f.dci_format = "1_1";
  f.direction = "DL";

  uint32_t offset = 0;

  // Identifier for DCI formats – 1 bit (should be 1 for DL)
  f.format_id = bit_pack(payload, &offset, 1);
  if (f.format_id != 1) {
    f.error_msg = "DCI format ID bit is 0, expected 1 for format 1_1";
  }

  // Carrier indicator – 0 or 3 bits
  f.carrier_indicator = bit_pack(payload, &offset, cfg.carrier_indicator_size);

  // Bandwidth part indicator – 0, 1 or 2 bits
  f.bwp_id = bit_pack(payload, &offset, bwp_id_size(cfg.nof_dl_bwp));

  // Frequency domain resource assignment
  uint32_t fdra_bits = freq_resource_size(cfg.pdsch_alloc_type,
    cfg.nof_rb_groups, cfg.bwp_dl_active_bw);
  f.fdra = bit_pack(payload, &offset, fdra_bits);

  // Time domain resource assignment – 0 to 4 bits
  f.tdra = bit_pack(payload, &offset, time_res_size(cfg.nof_dl_time_res));

  // VRB-to-PRB mapping – 0 or 1 bit
  if (cfg.pdsch_alloc_type != 0 && cfg.pdsch_inter_prb_to_prb) {
    f.vrb_to_prb_mapping = bit_pack(payload, &offset, 1);
  }

  // Rate matching indicator – 0, 1, or 2 bits
  if (cfg.pdsch_rm_pattern1) {
    f.rm_pattern1 = bit_pack(payload, &offset, 1);
  }
  if (cfg.pdsch_rm_pattern2) {
    f.rm_pattern2 = bit_pack(payload, &offset, 1);
  }

  // ZP CSI-RS trigger – 0, 1, or 2 bits
  f.zp_csi_rs_id = bit_pack(payload, &offset, ceil_log2(cfg.nof_aperiodic_zp + 1));

  // TB1: MCS – 5 bits
  f.mcs = bit_pack(payload, &offset, 5);

  // TB1: NDI – 1 bit
  f.ndi = bit_pack(payload, &offset, 1);

  // TB1: RV – 2 bits
  f.rv = bit_pack(payload, &offset, 2);

  // TB2 (two-codeword) — skipped for srsRAN single-layer
  // (cfg.pdsch_2cw is false)

  // HARQ process number – 4 bits
  f.harq_process_id = bit_pack(payload, &offset, 4);

  // DAI – 0, 2, or 4 bits
  if (cfg.harq_ack_codebook == 1) {  // dynamic
    if (cfg.multiple_scell) {
      f.dai = bit_pack(payload, &offset, 4);
    } else {
      f.dai = bit_pack(payload, &offset, 2);
    }
  }

  // TPC – 2 bits
  f.tpc = bit_pack(payload, &offset, 2);

  // PUCCH resource indicator – 3 bits
  f.pucch_resource = bit_pack(payload, &offset, 3);

  // PDSCH-to-HARQ feedback timing – 0 to 3 bits
  f.harq_feedback = bit_pack(payload, &offset, ceil_log2(cfg.nof_dl_to_ul_ack));

  // Antenna ports – 4, 5, or 6 bits
  f.ports = bit_pack(payload, &offset, dl_ports_size(cfg));

  // TCI – 0 or 3 bits
  if (cfg.pdsch_tci) {
    f.tci = bit_pack(payload, &offset, 3);
  }

  // SRS request – 2 or 3 bits
  f.srs_request = bit_pack(payload, &offset, cfg.enable_sul ? 3 : 2);

  // CBG transmission information – 0, 2, 4, 6, or 8 bits
  f.cbg_info = bit_pack(payload, &offset, cfg.pdsch_nof_cbg);

  // CBG flushing – 0 or 1 bit
  if (cfg.pdsch_cbg_flush) {
    f.cbg_flush = bit_pack(payload, &offset, 1);
  }

  // DMRS sequence initialization – 1 bit
  f.dmrs_id = bit_pack(payload, &offset, 1);

  // Validate consumed bits
  if (offset != nof_bits) {
    f.error_msg = "Parsed " + std::to_string(offset) + " bits but DCI has " +
                  std::to_string(nof_bits) + " bits";
    SPDLOG_WARN("DCI 1_1 parse mismatch: {}", f.error_msg);
  }

  f.parse_ok = true;

  // Decode RIV → PRB start + count
  if (cfg.pdsch_alloc_type == 1) {
    decode_riv(f.fdra, cfg.bwp_dl_active_bw, f.prb_start, f.nof_prbs);
  }

  // Resolve TDRA index to actual symbol start and length
  resolve_tdra(f.tdra, cfg.pdsch_tdra_table, cfg.nof_pdsch_symbols,
               &f.symbol_start, &f.symbol_length);

  // MCS lookup + TBS computation (using actual symbol_length from TDRA)
  f.tb_size_bytes = compute_tbs(f.mcs, f.nof_prbs, f.symbol_length, cfg, true) / 8;

  uint8_t Qm;
  double R_x1024;
  const char* mod_str;
  if (mcs_lookup(cfg.mcs_table, f.mcs, Qm, R_x1024, mod_str)) {
    f.modulation = mod_str;
    f.code_rate = R_x1024 / 1024.0;
  } else {
    f.modulation = "unknown";
  }

  return f;
}

// ─── Top-level dispatcher ──────────────────────────────────────────────────────

DCIFields parse_dci(const uint8_t* payload, uint16_t nof_bits,
                    const std::string& dci_format, const CarrierConfig& cfg) {
  if (dci_format == "0_1") {
    return parse_dci_0_1(payload, nof_bits, cfg);
  } else if (dci_format == "1_1") {
    return parse_dci_1_1(payload, nof_bits, cfg);
  }

  DCIFields f;
  f.parse_ok = false;
  f.error_msg = "Unsupported DCI format: " + dci_format;
  return f;
}

// ─── TBS computation (TS 38.214 §5.1.3.2) ─────────────────────────────────────

uint32_t compute_tbs(uint32_t mcs_idx, uint32_t nof_prbs, uint32_t symbol_length,
                     const CarrierConfig& cfg, bool is_dl) {
  if (nof_prbs == 0 || symbol_length == 0) return 0;

  uint8_t Qm;
  double R_x1024;
  const char* mod_str;
  if (!mcs_lookup(cfg.mcs_table, mcs_idx, Qm, R_x1024, mod_str)) {
    SPDLOG_WARN("MCS index {} out of range for table {}", mcs_idx, cfg.mcs_table);
    return 0;
  }

  double R = R_x1024 / 1024.0;

  // Step 1: N_RE per PRB (use actual symbol_length from TDRA, not config default)
  uint32_t n_prb_dmrs = is_dl ? cfg.dmrs_re_per_prb : cfg.dmrs_ul_re_per_prb;
  uint32_t n_prb_oh = cfg.xoverhead;

  // N'_RE = min(156, 12 * symbol_length - n_prb_dmrs - n_prb_oh)
  uint32_t n_re_prime = 12 * symbol_length - n_prb_dmrs - n_prb_oh;
  if (n_re_prime > 156) n_re_prime = 156;  // 156 = SRSRAN_MAX_NRE_NR

  // N_RE = N'_RE * nof_prbs
  uint32_t N_re = n_re_prime * nof_prbs;

  // Step 2: N_info = N_RE * R * Qm * nof_layers
  double S = 1.0;  // scaling factor (1.0 for C-RNTI)
  uint32_t n_info = static_cast<uint32_t>(N_re * S * R * Qm * cfg.nof_layers);

  if (n_info == 0) return 0;

  // Step 3/4: quantize to TBS
  if (n_info <= 3824) {
    return tbs_from_n_info3(n_info);
  }
  return tbs_from_n_info4(n_info, R);
}

// ─── HARQ State Tracker ────────────────────────────────────────────────────────

bool HarqStateTracker::check_retransmission(uint16_t rnti, uint32_t harq_id,
                                             uint32_t ndi, bool is_dl) {
  std::lock_guard<std::mutex> lock(mutex_);
  uint64_t key = make_key(rnti, harq_id, is_dl);

  auto it = state_map_.find(key);
  if (it == state_map_.end()) {
    // First time seeing this (RNTI, HARQ, direction) — new data
    state_map_[key] = {static_cast<int>(ndi)};
    return false;  // not a retransmission
  }

  HarqState& st = it->second;
  if (st.ndi == -1) {
    // First sight (shouldn't happen after insertion, but just in case)
    st.ndi = static_cast<int>(ndi);
    return false;
  }

  if (static_cast<int>(ndi) == st.ndi) {
    // NDI not toggled → retransmission
    return true;
  }

  // NDI toggled → new data
  st.ndi = static_cast<int>(ndi);
  return false;
}
