/**
 * DCI Parser for 5GSniffer — extracts structured fields from raw DCI bits.
 *
 * Supports DCI formats 0_1 (UL) and 1_1 (DL) per 3GPP TS 38.212.
 * Field widths follow srsRAN's dci_nr.c implementation.
 * TBS computation per TS 38.214 §5.1.3.2 / §6.1.4.2.
 */

#ifndef DCI_PARSER_H
#define DCI_PARSER_H

#include <cstdint>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

// ─── TDRA (Time Domain Resource Assignment) table entry ──────────────────────
// Maps TDRA index to SLIV (Start and Length Indicator Value) per TS 38.213
struct TDRAEntry {
  uint32_t sliv;  // Encodes start symbol S and length L: S + 14*L or N*(N-L+1)+(N-1-S)
};

// ─── Carrier / cell config (mirrors srsran_dci_cfg_nr_t defaults for srsRAN) ──
struct CarrierConfig {
  // BWP size — for FDRA width calculation
  uint32_t bwp_dl_active_bw = 52;   // N_RB for DL BWP
  uint32_t bwp_ul_active_bw = 52;   // N_RB for UL BWP

  // Resource allocation type (Type 1 for srsRAN default)
  // 0 = Type 0, 1 = Type 1
  uint8_t pdsch_alloc_type = 1;
  uint8_t pusch_alloc_type = 1;

  // Number of RB groups (only used for Type 0)
  uint32_t nof_rb_groups = 0;

  // BWP indicator field size (0 = single BWP)
  uint32_t nof_dl_bwp = 0;
  uint32_t nof_ul_bwp = 0;

  // Carrier indicator (0 = no carrier aggregation)
  uint32_t carrier_indicator_size = 0;

  // SUL (supplementary uplink) — false for srsRAN
  bool enable_sul = false;

  // Time domain resource assignment entries
  // UNVERIFIED ASSUMPTION: srsRAN uses default TDRA table (16 entries) → 4 bits
  uint32_t nof_dl_time_res = 16;
  uint32_t nof_ul_time_res = 16;

  // VRB-to-PRB interleaving for PDSCH Type 1
  bool pdsch_inter_prb_to_prb = false;

  // Rate matching patterns
  bool pdsch_rm_pattern1 = false;
  bool pdsch_rm_pattern2 = false;

  // ZP CSI-RS (0 = none)
  uint32_t nof_aperiodic_zp = 0;

  // Two-codeword PDSCH
  bool pdsch_2cw = false;

  // HARQ-ACK codebook: 0 = semi-static, 1 = dynamic
  // UNVERIFIED ASSUMPTION: srsRAN uses dynamic HARQ-ACK codebook
  uint8_t harq_ack_codebook = 1;  // 0=semi_static, 1=dynamic

  // Multiple serving cells
  bool multiple_scell = false;

  // DL-to-UL ACK timing entries
  // UNVERIFIED ASSUMPTION: srsRAN default = 8 entries → 3 bits
  uint32_t nof_dl_to_ul_ack = 8;

  // Antenna ports config
  // UNVERIFIED ASSUMPTION: single layer, no transform precoding, DMRS max len 1
  bool enable_transform_precoding = false;
  uint8_t pusch_dmrs_max_len = 1;  // 1 = single symbol DMRS

  // TCI (transmission config indication)
  bool pdsch_tci = false;

  // SRS resource indicator size (0 for minimal config)
  // UNVERIFIED ASSUMPTION: 0 bits for srsRAN default
  uint32_t srs_id_bits = 0;

  // CSI request bits
  uint32_t report_trigger_size = 0;

  // CBG (code block group) — 0 for srsRAN
  uint32_t pusch_nof_cbg = 0;
  uint32_t pdsch_nof_cbg = 0;
  bool pdsch_cbg_flush = false;

  // PTRS
  bool enable_ptrs = false;

  // Dynamic beta offsets for PUSCH
  bool pusch_dynamic_betas = false;

  // Dynamic dual HARQ-ACK
  bool dynamic_dual_harq_ack_codebook = false;

  // Frequency hopping
  bool enable_hopping = false;

  // PUSCH codebook config
  bool pusch_tx_config_non_codebook = false;

  // MCS table: 0 = Table 1 (64QAM), 1 = Table 2 (256QAM), 2 = Table 3 (lowSE)
  uint8_t mcs_table = 0;

  // Number of DMRS CDM groups without data (default 1 for single-layer)
  uint32_t nof_dmrs_cdm_groups_without_data = 1;

  // DMRS REs per PRB for DL (PDSCH) — e.g. type1, 1 CDM group, 3 symbols → 18
  uint32_t dmrs_re_per_prb = 6;
  // DMRS REs per PRB for UL (PUSCH) — may differ from DL (e.g. 2 CDM groups → 36)
  uint32_t dmrs_ul_re_per_prb = 6;

  // Number of OFDM symbols for PDSCH/PUSCH allocation
  // NOTE: These are now fallback defaults if TDRA table is not provided
  // With TDRA tables, actual symbol count is retrieved from the table entry
  uint32_t nof_pdsch_symbols = 12;
  uint32_t nof_pusch_symbols = 14;

  // ─── TDRA Tables (RRC-configured, indexed by TDRA field in DCI) ───────────────
  // For DL (PDSCH): maps TDRA index to SLIV
  std::vector<TDRAEntry> pdsch_tdra_table;
  // For UL (PUSCH): maps TDRA index to SLIV
  std::vector<TDRAEntry> pusch_tdra_table;

  // xOverhead from PDSCH-ServingCellConfig (0, 6, 12, or 18 RE per PRB)
  uint32_t xoverhead = 0;

  // Number of layers
  uint32_t nof_layers = 1;
};

// ─── Parsed DCI fields ─────────────────────────────────────────────────────────
struct DCIFields {
  bool parse_ok = false;
  std::string error_msg;

  // Common identifiers
  std::string dci_format;   // "0_1" or "1_1"
  std::string direction;    // "UL" or "DL"

  // DCI format identifier bit
  uint8_t format_id = 0;

  // Carrier indicator
  uint32_t carrier_indicator = 0;

  // BWP indicator
  uint32_t bwp_id = 0;

  // SUL indicator (UL only)
  uint32_t sul = 0;

  // Frequency domain resource assignment (raw value)
  uint32_t fdra = 0;

  // Time domain resource assignment
  uint32_t tdra = 0;

  // Decoded from TDRA: OFDM symbol start index (0...13)
  uint32_t symbol_start = 0;

  // Decoded from TDRA: number of allocated OFDM symbols
  uint32_t symbol_length = 0;

  // Frequency hopping flag (UL only)
  uint32_t freq_hopping_flag = 0;

  // VRB-to-PRB mapping (DL only)
  uint32_t vrb_to_prb_mapping = 0;

  // Rate matching indicators (DL only)
  uint32_t rm_pattern1 = 0;
  uint32_t rm_pattern2 = 0;

  // ZP CSI-RS trigger (DL only)
  uint32_t zp_csi_rs_id = 0;

  // MCS (5 bits)
  uint32_t mcs = 0;

  // NDI (1 bit)
  uint32_t ndi = 0;

  // Redundancy version (2 bits)
  uint32_t rv = 0;

  // HARQ process number (4 bits)
  uint32_t harq_process_id = 0;

  // DAI
  uint32_t dai = 0;
  uint32_t dai2 = 0;

  // TPC (2 bits)
  uint32_t tpc = 0;

  // PUCCH resource indicator (DL only, 3 bits)
  uint32_t pucch_resource = 0;

  // PDSCH-to-HARQ feedback timing (DL only)
  uint32_t harq_feedback = 0;

  // Antenna ports
  uint32_t ports = 0;

  // TCI (DL only)
  uint32_t tci = 0;

  // SRS request
  uint32_t srs_request = 0;

  // SRS resource indicator (UL only)
  uint32_t srs_id = 0;

  // CSI request (UL only)
  uint32_t csi_request = 0;

  // CBG info
  uint32_t cbg_info = 0;
  uint32_t cbg_flush = 0;

  // PTRS-DMRS association (UL only)
  uint32_t ptrs_id = 0;

  // Beta offset (UL only)
  uint32_t beta_id = 0;

  // DMRS sequence initialization
  uint32_t dmrs_id = 0;

  // UL-SCH indicator (UL only)
  uint32_t ulsch = 0;

  // ─── Derived fields (computed after parsing) ──────────────────────────────
  // Modulation order string
  std::string modulation;

  // Code rate (R x 1024 from MCS table, then /1024)
  double code_rate = 0.0;

  // Number of allocated PRBs (derived from FDRA via RIV decode)
  uint32_t nof_prbs = 0;

  // PRB start position
  uint32_t prb_start = 0;

  // Transport block size in bytes
  uint32_t tb_size_bytes = 0;

  // Retransmission detection
  bool is_retransmission = false;
};

// ─── Bit-packing helper (mimics srsran_bit_pack) ───────────────────────────────
// Reads `nof_bits` from the payload starting at `*offset`, advances offset.
// Each element of payload is 0 or 1.
inline uint32_t bit_pack(const uint8_t* payload, uint32_t* offset, uint32_t nof_bits) {
  uint32_t val = 0;
  for (uint32_t i = 0; i < nof_bits; i++) {
    val = (val << 1) | (payload[*offset] & 1);
    (*offset)++;
  }
  return val;
}

// ─── FDRA field width helpers ──────────────────────────────────────────────────
inline uint32_t fdra_type1_width(uint32_t N_bwp_rb) {
  if (N_bwp_rb == 0) return 0;
  return static_cast<uint32_t>(std::ceil(std::log2(N_bwp_rb * (N_bwp_rb + 1) / 2.0)));
}

inline uint32_t bwp_id_size(uint32_t nof_bwp) {
  if (nof_bwp <= 1) return 0;
  if (nof_bwp <= 2) return 1;
  return 2;
}

inline uint32_t time_res_size(uint32_t nof_time_res) {
  if (nof_time_res == 0) return 0;
  // ceil(log2(nof_time_res))
  return static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(nof_time_res))));
}

inline uint32_t ceil_log2(uint32_t x) {
  if (x <= 1) return 0;
  return static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(x))));
}

// ─── RIV (Resource Indication Value) decoding ──────────────────────────────────
// TS 38.214 §5.1.2.2.2 — Resource allocation type 1
inline void decode_riv(uint32_t riv, uint32_t N_bwp_rb, uint32_t& start_rb, uint32_t& nof_rb) {
  // RIV = N_bwp_rb * (L-1) + RB_start            if (L-1) <= floor(N_bwp_rb/2)
  // RIV = N_bwp_rb * (N_bwp_rb - L + 1) + (N_bwp_rb - 1 - RB_start) otherwise
  if (N_bwp_rb == 0) {
    start_rb = 0;
    nof_rb = 0;
    return;
  }
  for (uint32_t L = 1; L <= N_bwp_rb; L++) {
    for (uint32_t S = 0; S + L <= N_bwp_rb; S++) {
      uint32_t riv_test;
      if ((L - 1) <= N_bwp_rb / 2) {
        riv_test = N_bwp_rb * (L - 1) + S;
      } else {
        riv_test = N_bwp_rb * (N_bwp_rb - L + 1) + (N_bwp_rb - 1 - S);
      }
      if (riv_test == riv) {
        start_rb = S;
        nof_rb = L;
        return;
      }
    }
  }
  // Fallback: brute force failed (shouldn't happen with valid RIV)
  start_rb = 0;
  nof_rb = 0;
}

// ─── MCS Table 1 (TS 38.214 Table 5.1.3.1-1) — default 64QAM ─────────────────
struct MCSEntry {
  uint8_t mod_order;     // Qm: 2=QPSK, 4=16QAM, 6=64QAM, 8=256QAM
  double  code_rate_x1024;
  const char* mod_string;
};

static const MCSEntry MCS_TABLE_1[29] = {
  {2, 120,   "QPSK"},   {2, 157,   "QPSK"},   {2, 193,   "QPSK"},
  {2, 251,   "QPSK"},   {2, 308,   "QPSK"},   {2, 379,   "QPSK"},
  {2, 449,   "QPSK"},   {2, 526,   "QPSK"},   {2, 602,   "QPSK"},
  {2, 679,   "QPSK"},   {4, 340,   "16QAM"},  {4, 378,   "16QAM"},
  {4, 434,   "16QAM"},  {4, 490,   "16QAM"},  {4, 553,   "16QAM"},
  {4, 616,   "16QAM"},  {4, 658,   "16QAM"},  {6, 438,   "64QAM"},
  {6, 466,   "64QAM"},  {6, 517,   "64QAM"},  {6, 567,   "64QAM"},
  {6, 616,   "64QAM"},  {6, 666,   "64QAM"},  {6, 719,   "64QAM"},
  {6, 772,   "64QAM"},  {6, 822,   "64QAM"},  {6, 873,   "64QAM"},
  {6, 910,   "64QAM"},  {6, 948,   "64QAM"},
};

static const MCSEntry MCS_TABLE_2[28] = {
  {2, 120,   "QPSK"},   {2, 193,   "QPSK"},   {2, 308,   "QPSK"},
  {2, 449,   "QPSK"},   {2, 602,   "QPSK"},   {4, 378,   "16QAM"},
  {4, 434,   "16QAM"},  {4, 490,   "16QAM"},  {4, 553,   "16QAM"},
  {4, 616,   "16QAM"},  {4, 658,   "16QAM"},  {6, 466,   "64QAM"},
  {6, 517,   "64QAM"},  {6, 567,   "64QAM"},  {6, 616,   "64QAM"},
  {6, 666,   "64QAM"},  {6, 719,   "64QAM"},  {6, 772,   "64QAM"},
  {6, 822,   "64QAM"},  {6, 873,   "64QAM"},  {8, 682.5, "256QAM"},
  {8, 711,   "256QAM"}, {8, 754,   "256QAM"}, {8, 797,   "256QAM"},
  {8, 841,   "256QAM"}, {8, 885,   "256QAM"}, {8, 916.5, "256QAM"},
  {8, 948,   "256QAM"},
};

static const MCSEntry MCS_TABLE_3[29] = {
  {2, 30,    "QPSK"},   {2, 40,    "QPSK"},   {2, 50,    "QPSK"},
  {2, 64,    "QPSK"},   {2, 78,    "QPSK"},   {2, 99,    "QPSK"},
  {2, 120,   "QPSK"},   {2, 157,   "QPSK"},   {2, 193,   "QPSK"},
  {2, 251,   "QPSK"},   {2, 308,   "QPSK"},   {2, 379,   "QPSK"},
  {2, 449,   "QPSK"},   {2, 526,   "QPSK"},   {2, 602,   "QPSK"},
  {4, 340,   "16QAM"},  {4, 378,   "16QAM"},  {4, 434,   "16QAM"},
  {4, 490,   "16QAM"},  {4, 553,   "16QAM"},  {4, 616,   "16QAM"},
  {6, 438,   "64QAM"},  {6, 466,   "64QAM"},  {6, 517,   "64QAM"},
  {6, 567,   "64QAM"},  {6, 616,   "64QAM"},  {6, 666,   "64QAM"},
  {6, 719,   "64QAM"},  {6, 772,   "64QAM"},
};

// ─── TBS table (TS 38.214 Table 5.1.3.2-1) ────────────────────────────────────
static const uint32_t TBS_TABLE[93] = {
  24,   32,   40,   48,   56,   64,   72,   80,   88,   96,
  104,  112,  120,  128,  136,  144,  152,  160,  168,  176,
  184,  192,  208,  224,  240,  256,  272,  288,  304,  320,
  336,  352,  368,  384,  408,  432,  456,  480,  504,  528,
  552,  576,  608,  640,  672,  704,  736,  768,  808,  848,
  888,  928,  984,  1032, 1064, 1128, 1160, 1192, 1224, 1256,
  1288, 1320, 1352, 1416, 1480, 1544, 1608, 1672, 1736, 1800,
  1864, 1928, 2024, 2088, 2152, 2216, 2280, 2408, 2472, 2536,
  2600, 2664, 2728, 2792, 2856, 2976, 3104, 3240, 3368, 3496,
  3624, 3752, 3824,
};

// ─── Public API ────────────────────────────────────────────────────────────────

// Parse DCI format 0_1 (UL) from raw bit payload.
DCIFields parse_dci_0_1(const uint8_t* payload, uint16_t nof_bits,
                        const CarrierConfig& cfg);

// Parse DCI format 1_1 (DL) from raw bit payload.
DCIFields parse_dci_1_1(const uint8_t* payload, uint16_t nof_bits,
                        const CarrierConfig& cfg);

// Top-level dispatcher: picks parser based on dci_format string ("0_1" or "1_1").
DCIFields parse_dci(const uint8_t* payload, uint16_t nof_bits,
                    const std::string& dci_format, const CarrierConfig& cfg);

// Decode SLIV (Start and Length Indicator Value) per TS 38.211/38.212.
// N: total symbols per slot (14 for normal CP); sliv: SLIV value from DCI
// Sets S (symbol start index) and L (symbol length)
void sliv_to_s_and_l(uint32_t N, uint32_t sliv, uint32_t* S, uint32_t* L);

// Compute TBS in bits from MCS index, number of PRBs, symbol length, and config.
// Returns 0 on failure.
// symbol_length: actual number of allocated OFDM symbols (from decoded TDRA/SLIV)
uint32_t compute_tbs(uint32_t mcs_idx, uint32_t nof_prbs, uint32_t symbol_length,
                     const CarrierConfig& cfg, bool is_dl);

// ─── Per-RNTI HARQ state tracker (Step 4) ──────────────────────────────────────
class HarqStateTracker {
public:
  // Returns true if this is a retransmission (NDI not toggled and not first sight).
  bool check_retransmission(uint16_t rnti, uint32_t harq_id,
                            uint32_t ndi, bool is_dl);

private:
  struct HarqState {
    int ndi = -1;  // -1 = first sight
  };

  // Key: (rnti << 16) | (is_dl << 4) | harq_id
  std::unordered_map<uint64_t, HarqState> state_map_;
  std::mutex mutex_;

  uint64_t make_key(uint16_t rnti, uint32_t harq_id, bool is_dl) {
    return (static_cast<uint64_t>(rnti) << 16) |
           (static_cast<uint64_t>(is_dl ? 1 : 0) << 4) |
           (harq_id & 0xF);
  }
};

#endif // DCI_PARSER_H
