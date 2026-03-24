#!/usr/bin/env python3
"""
Extract 5GSniffer TOML parameters from NR-Scope / srsRAN log files.

Usage:
    python3 extract_params.py <logfile.txt>

Scans the log file for RRC configuration and DCI decoder output to extract:
  - bwp_dl_num_prbs, bwp_ul_num_prbs
  - dmrs_re_per_prb
  - nof_pdsch_symbols, nof_pusch_symbols
  - xoverhead, nof_layers
  - nof_dl_time_res    ← count of entries in pdsch-TimeDomainAllocationList
  - nof_ul_time_res    ← count of entries in pusch-TimeDomainAllocationList
  - harq_ack_codebook  ← from pdsch-HARQ-ACK-Codebook (0=semi-static, 1=dynamic)
  - nof_dl_to_ul_ack   ← count of elements in dl-DataToUL-ACK list
"""

import re
import sys


def compute_dmrs_re_per_prb(dmrs: dict) -> int | None:
    """
    Total DMRS RE overhead per PRB per scheduled allocation.
    Formula: nof_cdm_grps × re_per_prb_per_sym × sym_factor × nof_dmrs_symbols
      re_per_prb_per_sym : 6 for Type 1, 4 for Type 2
      sym_factor         : 2 for double-symbol DMRS, 1 for single
    """
    if dmrs['nof_syms'] is None:
        return None
    re_per_sym = 6 if dmrs['type'] == 1 else 4
    sym_factor = 2 if dmrs['len'] == 'double' else 1
    return dmrs['cdm_grps'] * re_per_sym * sym_factor * dmrs['nof_syms']


def count_tdra_entries(lines, start_idx):
    """
    Count JSON object entries inside a TimeDomainAllocationList array.
    Each entry in the list has exactly one "mappingType" key (required per spec).
    Stops when the array closes (a ']' at the right nesting depth is seen).
    Returns (entry_count, lines_consumed).
    """
    count = 0
    depth = 0          # bracket depth inside the array
    in_array = False

    for i, line in enumerate(lines[start_idx:]):
        stripped = line.strip()

        # The first '[' opens our array
        if not in_array:
            if '[' in stripped:
                in_array = True
                depth = 1
                # Check if the whole array is on one line: e.g. "...": []
                opens = stripped.count('[')
                closes = stripped.count(']')
                depth = opens - closes
                if depth == 0:
                    return count, i + 1
            continue

        opens = stripped.count('[') + stripped.count('{')
        closes = stripped.count(']') + stripped.count('}')
        depth += opens - closes

        # "mappingType" appears exactly once per TDRA entry — use it as a counter
        if '"mappingType"' in stripped:
            count += 1

        if depth <= 0:
            return count, i + 1

    return count, len(lines) - start_idx


def count_list_elements(line):
    """
    Count elements in a JSON array that appears on a single line.
    e.g.  "dl-DataToUL-ACK": [ 4 ]            → 1
          "dl-DataToUL-ACK": [ 1, 2, 3 ]       → 3
    Returns the element count, or 0 if no array found.
    """
    m = re.search(r'\[([^\]]*)\]', line)
    if not m:
        return 0
    content = m.group(1).strip()
    if not content:
        return 0
    return len([x for x in content.split(',') if x.strip()])


def extract_params(filepath):
    params = {}

    # ── Compiled patterns ───────────────────────────────────────────────────────
    p = {
        # HARQ-ACK codebook type
        'harq_ack_codebook': re.compile(
            r'"pdsch-HARQ-ACK-Codebook"\s*:\s*"([^"]+)"'),
        # DL-to-UL ACK timing list (often single-line)
        'dl_to_ul_ack':  re.compile(r'"dl-DataToUL-ACK"\s*:\s*\['),
        # PDSCH/PUSCH TDRA list headers
        'pdsch_tdra': re.compile(r'"pdsch-TimeDomainAllocationList"\s*:'),
        'pusch_tdra': re.compile(r'"pusch-TimeDomainAllocationList"\s*:'),
        # Context markers to distinguish common vs dedicated config
        'pdsch_cfg_common':    re.compile(r'"pdsch-ConfigCommon"'),
        'pdsch_cfg_dedicated': re.compile(r'"pdsch-Config"\s*:'),
        'pusch_cfg_common':    re.compile(r'"pusch-ConfigCommon"'),
        'pusch_cfg_dedicated': re.compile(r'"pusch-Config"\s*:'),
        # DMRS config
        'dmrs_type':       re.compile(r'"dmrs-Type"\s*:\s*"([^"]+)"'),
        'dmrs_add_pos':    re.compile(r'"dmrs-AdditionalPosition"\s*:\s*"([^"]+)"'),
        'max_length':      re.compile(r'"maxLength"\s*:\s*"([^"]+)"'),
        # BWP sizes
        'carrier_bw':      re.compile(r'"carrierBandwidth"\s*:\s*(\d+)'),
        'nof_prbs_rrc':    re.compile(r'"nrofPRBs"\s*:\s*(\d+)'),
        # xOverhead
        'x_overhead':      re.compile(r'"xOverhead"\s*:\s*"?([^",\}\n]+)"?'),
        # Number of layers / max rank
        'max_rank':        re.compile(r'"maxRank"\s*:\s*(\d+)'),
        # NR-Scope decoder blocks
        'nrscope_pdsch': re.compile(r'\bPDSCH_cfg\b'),
        'nrscope_pusch': re.compile(r'\bPUSCH(?:Decoder[^\n]*)?\s*--[^\n]*PUSCH_cfg\s*:|\bPUSCH_cfg\b'),

        # ADDED: NR-Scope DMRS specific properties
        'nrs_dmrs_type': re.compile(r'\btype=(\d+)'),
        'nrs_dmrs_len':  re.compile(r'\blen=(single|double)'),
        'nrs_dmrs_symb': re.compile(r'\bsymb=([01]+)'),
        'nrs_cdm_grps':  re.compile(r'\bnof_dmrs_cdm_grps=(\d+)'),

        'nrscope_dmrs_prb': re.compile(r'nof_dmrs_prb\s*[=:]\s*(\d+)'),
        'nrscope_symb_sh':  re.compile(r'nof_symb_sh\s*[=:]\s*(\d+)'),
        'nrscope_oh_prb':   re.compile(r'nof_oh_prb\s*[=:]\s*(\d+)'),
        'nrscope_layers':   re.compile(r'nof_layers\s*[=:]\s*(\d+)'),
        'nrscope_nof_prb':  re.compile(r'nof_prb\s*[=:]\s*(\d+)'),
        # DL/UL context markers for carrier bw
        'dl_context': re.compile(
            r'downlink|dl-BWP|pdsch|frequencyInfoDL', re.IGNORECASE),
        'ul_context': re.compile(
            r'uplink|ul-BWP|pusch|frequencyInfoUL', re.IGNORECASE),

        # ADDED: Cell search and MIB parameters
        'cell_found': re.compile(r'Cell Found!'),
        'nid': re.compile(r'N_id:\s*(\d+)'),
        'mib_scs': re.compile(r'MIB:.*\bscs=(\d+)'),
        'subcarrier_spacing': re.compile(r'"subcarrierSpacing"\s*:\s*"kHz(\d+)"'),

        # ADDED: PDCCH parameters from NR-Scope log
        'pdcch_coreset_id': re.compile(r'"controlResourceSetId"\s*:\s*(\d+)'),
        'pdcch_freq_domain': re.compile(r'"frequencyDomainResources"\s*:\s*"([01]+)"'),
        'pdcch_duration': re.compile(r'"duration"\s*:\s*(\d+)'),
        'pdcch_cce_reg_mapping': re.compile(r'"cce-REG-MappingType"\s*:\s*\{([^}]*)'),
        'pdcch_nrof_candidates': re.compile(r'"nrofCandidates"\s*:\s*\{'),
        'pdcch_al_pattern': re.compile(r'"aggregationLevel(\d+)"\s*:\s*"n(\d+)"'),
        'pdcch_current_offset': re.compile(r'current offset:\s*(-?\d+)'),
    }

    # ── State ──────────────────────────────────────────────────────────────────
    # TDRA: prefer dedicated config; fall back to common config
    dl_tdra_dedicated = None   # entry count from pdsch-Config (dedicated)
    dl_tdra_common    = None   # entry count from pdsch-ConfigCommon
    ul_tdra_dedicated = None
    ul_tdra_common    = None

    in_pdsch_common    = False
    in_pdsch_dedicated = False
    in_pusch_common    = False
    in_pusch_dedicated = False

    # NR-Scope section
    nrscope_section    = None
    nrscope_subsection = None

    # ADDED: NR-Scope DMRS state tracking
    nrs_dl_dmrs = {'type': 1, 'cdm_grps': 1, 'len': 'single', 'nof_syms': None}
    nrs_ul_dmrs = {'type': 1, 'cdm_grps': 1, 'len': 'single', 'nof_syms': None}

    # DMRS intermediate values (from RRC)
    dmrs_type_val  = None
    dmrs_add_pos   = 0
    dmrs_max_len   = 1

    # Carrier context
    last_context = None   # 'dl' or 'ul'

    # ADDED: PDCCH parameters state
    in_nrof_candidates = False
    pdcch_al_candidates = {1: 0, 2: 0, 4: 0, 8: 0, 16: 0}
    in_cce_reg_mapping = False

    # ADDED: Cell search and MIB parameters
    sniffer_nid_1 = None
    sniffer_ssb_numerology = None
    subcarrier_spacing_dl = None
    pdcch_numerology = None
    pdcch_interleaving_pattern = None

    # ── Read all lines once ─────────────────────────────────────────────────────
    with open(filepath, 'r', errors='replace') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line  = lines[i]
        strip = line.strip()

        # ── Context tracking ────────────────────────────────────────────────────

        if p['pdsch_cfg_common'].search(strip):
            in_pdsch_common    = True
            in_pdsch_dedicated = False
        elif p['pdsch_cfg_dedicated'].search(strip) and 'Common' not in strip:
            in_pdsch_dedicated = True
            in_pdsch_common    = False

        if p['pusch_cfg_common'].search(strip):
            in_pusch_common    = True
            in_pusch_dedicated = False
        elif p['pusch_cfg_dedicated'].search(strip) and 'Common' not in strip:
            in_pusch_dedicated = True
            in_pusch_common    = False

        if p['dl_context'].search(strip):
            last_context = 'dl'
        elif p['ul_context'].search(strip):
            last_context = 'ul'

        # ── HARQ-ACK codebook ───────────────────────────────────────────────────
        m = p['harq_ack_codebook'].search(strip)
        if m:
            val = m.group(1).lower()
            params['harq_ack_codebook'] = 1 if 'dynamic' in val else 0

        # ── dl-DataToUL-ACK ─────────────────────────────────────────────────────
        if p['dl_to_ul_ack'].search(strip):
            # May be on this line or span multiple lines
            if ']' in strip:
                # All on one line
                params['nof_dl_to_ul_ack'] = max(1, count_list_elements(strip))
            else:
                # Multi-line: collect until ']'
                elems = []
                j = i + 1
                while j < len(lines):
                    inner = lines[j].strip()
                    # each element is a number on its own line in this format
                    nums = re.findall(r'-?\d+', inner)
                    elems.extend(nums)
                    if ']' in inner:
                        break
                    j += 1
                params['nof_dl_to_ul_ack'] = max(1, len(elems))

        # ── PDSCH TimeDomainAllocationList ──────────────────────────────────────
        if p['pdsch_tdra'].search(strip):
            count, consumed = count_tdra_entries(lines, i)
            count = max(1, count)   # at least 1 if the list exists
            if in_pdsch_dedicated:
                dl_tdra_dedicated = count
            else:
                # common config or uncontextualised
                dl_tdra_common = count
            i += consumed
            continue

        # ── PUSCH TimeDomainAllocationList ──────────────────────────────────────
        if p['pusch_tdra'].search(strip):
            count, consumed = count_tdra_entries(lines, i)
            count = max(1, count)
            if in_pusch_dedicated:
                ul_tdra_dedicated = count
            else:
                ul_tdra_common = count
            i += consumed
            continue

        # ── Carrier bandwidth (BWP size) ─────────────────────────────────────────
        m = p['carrier_bw'].search(strip)
        if m:
            val = int(m.group(1))
            if last_context == 'ul':
                params['bwp_ul_num_prbs'] = val
            else:
                params['bwp_dl_num_prbs'] = val

        m = p['nof_prbs_rrc'].search(strip)
        if m:
            val = int(m.group(1))
            if last_context == 'ul':
                params.setdefault('bwp_ul_num_prbs', val)
            else:
                params.setdefault('bwp_dl_num_prbs', val)

        # ── xOverhead ───────────────────────────────────────────────────────────
        m = p['x_overhead'].search(strip)
        if m:
            raw = m.group(1).strip().strip('"')
            if raw.lstrip('-').isdigit():
                params['xoverhead'] = int(raw)
            else:
                digits = re.findall(r'\d+', raw)
                if digits:
                    params['xoverhead'] = int(digits[0])

        # ── maxRank / nof_layers ─────────────────────────────────────────────────
        m = p['max_rank'].search(strip)
        if m:
            params['nof_layers'] = int(m.group(1))

        # ── DMRS config (From RRC) ──────────────────────────────────────────────
        m = p['dmrs_type'].search(strip)
        if m:
            dmrs_type_val = m.group(1).lower()

        m = p['dmrs_add_pos'].search(strip)
        if m:
            val = m.group(1).lower()
            pos_map = {'pos0': 0, 'pos1': 1, 'pos2': 2, 'pos3': 3}
            dmrs_add_pos = pos_map.get(val, int(re.findall(r'\d', val)[0]) if re.findall(r'\d', val) else 0)

        m = p['max_length'].search(strip)
        if m:
            raw = m.group(1).lower()
            dmrs_max_len = 2 if 'len2' in raw or raw == '2' else 1

        # ── NR-Scope DCI decoder output ─────────────────────────────────────────
        if p['nrscope_pdsch'].search(strip):
            nrscope_section    = 'PDSCH'
            nrscope_subsection = None
        elif p['nrscope_pusch'].search(strip):
            nrscope_section    = 'PUSCH'
            nrscope_subsection = None

        if nrscope_section:
            tgt_dmrs = nrs_dl_dmrs if nrscope_section == 'PDSCH' else nrs_ul_dmrs
            
            if 'DMRS:' in strip or strip.startswith('DMRS '):
                nrscope_subsection = 'DMRS'
            elif 'SCH:' in strip or strip.startswith('SCH '):
                nrscope_subsection = 'SCH'
            elif 'Grant:' in strip or strip.startswith('Grant '):
                nrscope_subsection = 'Grant'

            if nrscope_subsection == 'DMRS':
                # ADDED: Extract specific NR-Scope DMRS properties
                m = p['nrs_dmrs_type'].search(strip)
                if m: tgt_dmrs['type'] = int(m.group(1))
                
                m = p['nrs_dmrs_len'].search(strip)
                if m: tgt_dmrs['len'] = m.group(1)
                
                m = p['nrs_dmrs_symb'].search(strip)
                if m and tgt_dmrs['nof_syms'] is None:
                    tgt_dmrs['nof_syms'] = m.group(1).count('1')
                
                # Fallback if the log explicitly outputs the final value
                m = p['nrscope_dmrs_prb'].search(strip)
                if m:
                    params['dmrs_re_per_prb'] = int(m.group(1))

            if nrscope_subsection == 'SCH':
                m = p['nrscope_symb_sh'].search(strip)
                if m:
                    val = int(m.group(1))
                    if nrscope_section == 'PDSCH':
                        params['nof_pdsch_symbols'] = val
                    else:
                        params['nof_pusch_symbols'] = val
                m = p['nrscope_oh_prb'].search(strip)
                if m:
                    params['xoverhead'] = int(m.group(1))
                m = p['nrscope_layers'].search(strip)
                if m:
                    params['nof_layers'] = int(m.group(1))

            if nrscope_subsection == 'Grant':
                # ADDED: Extract CDM groups from Grant block
                m = p['nrs_cdm_grps'].search(strip)
                if m: tgt_dmrs['cdm_grps'] = int(m.group(1))

                m = p['nrscope_nof_prb'].search(strip)
                if m:
                    bkey = 'bwp_dl_num_prbs' if nrscope_section == 'PDSCH' else 'bwp_ul_num_prbs'
                    params.setdefault(bkey, int(m.group(1)))

        # ── Cell search and MIB parameters (From NR-Scope output) ────────────────
        # Extract N_id from "Cell Found!" section
        m = p['nid'].search(strip)
        if m:
            sniffer_nid_1 = int(m.group(1))
            params['sniffer_nid_1'] = sniffer_nid_1

        # Extract scs from MIB line and convert to numerology
        # scs in kHz: 15 -> numerology 0, 30 -> numerology 1, 60 -> numerology 2, 120 -> numerology 3
        m = p['mib_scs'].search(strip)
        if m:
            scs_khz = int(m.group(1))
            # Convert kHz to numerology: numerology = log2(scs_khz / 15)
            sniffer_ssb_numerology = {15: 0, 30: 1, 60: 2, 120: 3}.get(scs_khz, 0)
            params['sniffer_ssb_numerology'] = sniffer_ssb_numerology

        # Extract subCarrierSpacing from scs-SpecificCarrierList in frequencyInfoDL
        m = p['subcarrier_spacing'].search(strip)
        if m:
            subcarrier_spacing_dl = int(m.group(1))
            # Only store if within frequencyInfoDL context (DL comes before UL in the log)
            if last_context == 'dl' or last_context is None:
                params.setdefault('sniffer_subcarrier_spacing', subcarrier_spacing_dl)

        # ── PDCCH parameters (From RRC) ────────────────────────────────────────
        # Extract controlResourceSetId (overwrite to get latest, dedicated config comes after common)
        m = p['pdcch_coreset_id'].search(strip)
        if m:
            params['pdcch_coreset_id'] = int(m.group(1))

        # Extract frequencyDomainResources and count bits (num_prbs = count of 1s × 6)
        m = p['pdcch_freq_domain'].search(strip)
        if m:
            freq_bits = m.group(1)
            num_ones = freq_bits.count('1')
            params['pdcch_num_prbs'] = num_ones * 6

        # Extract duration (overwrite to get latest)
        m = p['pdcch_duration'].search(strip)
        if m:
            params['pdcch_coreset_duration'] = int(m.group(1))

        # Extract and track cce-REG-MappingType (interleaving pattern)
        m = p['pdcch_cce_reg_mapping'].search(strip)
        if m:
            mapping_content = m.group(1)
            # If the content is empty (blank {}), it's non-interleaved
            if not mapping_content or mapping_content.strip() == '':
                pdcch_interleaving_pattern = 'non-interleaved'
            else:
                # If it has content like "interleaved", extract that
                if 'interleaved' in mapping_content.lower():
                    pdcch_interleaving_pattern = 'interleaved'
                else:
                    pdcch_interleaving_pattern = 'non-interleaved'
            params['pdcch_interleaving_pattern'] = pdcch_interleaving_pattern

        # Extract subCarrierSpacing for PDCCH numerology context
        # Convert from kHz to numerology: 15kHz->0, 30kHz->1, 60kHz->2, 120kHz->3
        if last_context == 'dl' or 'frequencyInfoDL' in strip:
            m = p['subcarrier_spacing'].search(strip)
            if m:
                scs_khz = int(m.group(1))
                pdcch_numerology = {15: 0, 30: 1, 60: 2, 120: 3}.get(scs_khz, 0)
                params['pdcch_numerology'] = pdcch_numerology

        # Track when we enter nrofCandidates block
        if p['pdcch_nrof_candidates'].search(strip):
            in_nrof_candidates = True

        # Extract aggregation level candidates
        if in_nrof_candidates:
            m = p['pdcch_al_pattern'].search(strip)
            if m:
                al = int(m.group(1))
                candidates = int(m.group(2))
                pdcch_al_candidates[al] = candidates

            # End of nrofCandidates block
            if '}' in strip and in_nrof_candidates:
                in_nrof_candidates = False
                # Store only after we've collected all values
                if not any(k in params for k in ['pdcch_num_candidates_al1', 'pdcch_num_candidates_al2']):
                    params['pdcch_num_candidates_per_AL'] = [
                        pdcch_al_candidates[1],
                        pdcch_al_candidates[2],
                        pdcch_al_candidates[4],
                        pdcch_al_candidates[8],
                        pdcch_al_candidates[16]
                    ]

        # Extract current offset (subcarrier_offset)
        m = p['pdcch_current_offset'].search(strip)
        if m:
            params.setdefault('pdcch_subcarrier_offset', int(m.group(1)))

        i += 1

    # ── Finalise TDRA counts ────────────────────────────────────────────────────
    # Dedicated config takes priority; fall back to common; fall back to default 16
    nof_dl = dl_tdra_dedicated if dl_tdra_dedicated is not None else (
             dl_tdra_common    if dl_tdra_common    is not None else 16)
    nof_ul = ul_tdra_dedicated if ul_tdra_dedicated is not None else (
             ul_tdra_common    if ul_tdra_common    is not None else 16)

    params['nof_dl_time_res'] = nof_dl
    params['nof_ul_time_res'] = nof_ul

    # Source annotation for reporting
    params['_dl_tdra_src'] = ('dedicated' if dl_tdra_dedicated is not None else
                              'common'    if dl_tdra_common    is not None else 'default')
    params['_ul_tdra_src'] = ('dedicated' if ul_tdra_dedicated is not None else
                              'common'    if ul_tdra_common    is not None else 'default')

    # ── Compute dmrs_re_per_prb from NR-Scope DMRS parsing (Primary) ────────────
    nrs_dmrs_v = compute_dmrs_re_per_prb(nrs_dl_dmrs)
    if nrs_dmrs_v is not None:
        params['dmrs_re_per_prb'] = nrs_dmrs_v
    
    # ── Fallback: Compute dmrs_re_per_prb from RRC DMRS config if not found ─────
    elif 'dmrs_re_per_prb' not in params and dmrs_type_val is not None:
        re_per_sym = 6 if ('type1' in dmrs_type_val or '1' in dmrs_type_val) else 4
        nof_dmrs_sym = 1 + dmrs_add_pos
        if dmrs_max_len == 2:
            nof_dmrs_sym *= 2
        params['dmrs_re_per_prb'] = re_per_sym * nof_dmrs_sym

    return params


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <logfile.txt>")
        sys.exit(1)

    filepath = sys.argv[1]
    params = extract_params(filepath)

    if not params:
        print("No parameters found in the log file.")
        sys.exit(1)

    # Display order (organized by TOML sections)
    sniffer_order = [
        'sniffer_nid_1',
        'sniffer_ssb_numerology',
        'sniffer_subcarrier_spacing',
    ]

    pdcch_order = [
        'pdcch_coreset_id',
        'pdcch_subcarrier_offset',
        'pdcch_num_prbs',
        'pdcch_numerology',
        'pdcch_interleaving_pattern',
        'pdcch_coreset_duration',
        'pdcch_num_candidates_per_AL',
    ]

    other_order = [
        'bwp_dl_num_prbs', 'bwp_ul_num_prbs',
        'dmrs_re_per_prb',
        'nof_pdsch_symbols', 'nof_pusch_symbols',
        'xoverhead', 'nof_layers',
        'nof_dl_time_res', 'nof_ul_time_res',
        'harq_ack_codebook', 'nof_dl_to_ul_ack',
    ]

    descriptions = {
        'sniffer_nid_1':     'NR physical cell ID (N_id) from Cell Found! in NR-Scope',
        'sniffer_ssb_numerology': 'SSB numerology (0=15kHz, 1=30kHz, 2=60kHz, 3=120kHz) from MIB scs',
        'sniffer_subcarrier_spacing': 'Subcarrier spacing in kHz from scs-SpecificCarrierList',
        'pdcch_coreset_id':  'CORESET ID from controlResourceSetId',
        'pdcch_subcarrier_offset': 'Subcarrier offset from Coreset 1 parameter: current offset',
        'pdcch_num_prbs':    'PDCCH PRBs (frequencyDomainResources: count of 1s × 6)',
        'pdcch_numerology':  'Numerology from subCarrierSpacing (0=15kHz, 1=30kHz, 2=60kHz, 3=120kHz)',
        'pdcch_interleaving_pattern': 'Interleaving pattern from cce-REG-MappingType (blank=non-interleaved)',
        'pdcch_coreset_duration': 'PDCCH duration from duration field',
        'pdcch_num_candidates_per_AL': 'Number of candidates per aggregation level [AL1, AL2, AL4, AL8, AL16]',
        'bwp_dl_num_prbs':   'Active DL BWP size in PRBs',
        'bwp_ul_num_prbs':   'Active UL BWP size in PRBs',
        'dmrs_re_per_prb':   'DMRS REs per PRB',
        'nof_pdsch_symbols': 'PDSCH OFDM symbols per slot',
        'nof_pusch_symbols': 'PUSCH OFDM symbols per slot',
        'xoverhead':         'Overhead REs per PRB (xOverhead)',
        'nof_layers':        'Number of spatial layers',
        'nof_dl_time_res':   'PDSCH TDRA table entries → ceil_log2 bits in DCI 1_1',
        'nof_ul_time_res':   'PUSCH TDRA table entries → ceil_log2 bits in DCI 0_1',
        'harq_ack_codebook': 'HARQ-ACK codebook (0=semi-static, 1=dynamic)',
        'nof_dl_to_ul_ack':  'dl-DataToUL-ACK list length → ceil_log2 bits in DCI 1_1',
    }

    dl_src = params.pop('_dl_tdra_src', 'unknown')
    ul_src = params.pop('_ul_tdra_src', 'unknown')

    print("=" * 90)
    print("Extracted TOML parameters (organized by section):")
    print("=" * 90)

    print("\n[sniffer] section:")
    print("-" * 90)
    for key in sniffer_order:
        if key in params:
            val  = params[key]
            desc = descriptions.get(key, '')
            print(f"{key:<35} = {val!s:<6}  # {desc}")

    print("\n[[pdcch]] section:")
    print("-" * 90)
    for key in pdcch_order:
        if key in params:
            val  = params[key]
            desc = descriptions.get(key, '')
            if isinstance(val, list):
                print(f"{key:<35} = {val}  # {desc}")
            else:
                print(f"{key:<35} = {val!s:<6}  # {desc}")

    print("\nOther parameters:")
    print("-" * 90)
    for key in other_order:
        if key in params:
            val  = params[key]
            desc = descriptions.get(key, '')
            if key == 'nof_dl_time_res':
                desc += f' (source: {dl_src})'
            if key == 'nof_ul_time_res':
                desc += f' (source: {ul_src})'
            print(f"{key:<35} = {val!s:<6}  # {desc}")

    # Any extra keys not in the ordered lists
    all_ordered_keys = set(sniffer_order + pdcch_order + other_order)
    for key, val in sorted(params.items()):
        if key not in all_ordered_keys and not key.startswith('_'):
            print(f"{key:<35} = {val}")

    print()

    # ── DCI size sanity check ────────────────────────────────────────────────────
    import math
    def ceil_log2(n):
        return 0 if n <= 1 else math.ceil(math.log2(n))

    def fdra_type1_bits(bwp):
        return 0 if bwp == 0 else math.ceil(math.log2(bwp * (bwp + 1) / 2))

    bwp_dl = params.get('bwp_dl_num_prbs', 0)
    bwp_ul = params.get('bwp_ul_num_prbs', 0)
    harq   = params.get('harq_ack_codebook', 1)
    dl_t   = params.get('nof_dl_time_res', 16)
    ul_t   = params.get('nof_ul_time_res', 16)
    n_ack  = params.get('nof_dl_to_ul_ack', 8)

    tdra_dl    = ceil_log2(dl_t)
    tdra_ul    = ceil_log2(ul_t)
    dai_dl     = 2 if harq == 1 else 0
    dai_ul     = 2 if harq == 1 else 1
    harq_fb    = ceil_log2(n_ack)
    fdra_dl    = fdra_type1_bits(bwp_dl)
    fdra_ul    = fdra_type1_bits(bwp_ul)

    dci_1_1 = 1+fdra_dl+tdra_dl+5+1+2+4+dai_dl+2+3+harq_fb+4+2+1          # typical fixed fields
    dci_0_1 = 1+fdra_ul+tdra_ul+5+1+2+4+dai_ul+      2+         3+2+1+1   # typical fixed fields

    print("── DCI size estimate (fixed fields, no optional features) ──")
    print(f"  DCI 1_1 ≈ {dci_1_1} bits  "
          f"(FDRA={fdra_dl}, TDRA={tdra_dl}, DAI={dai_dl}, harq_fb={harq_fb})")
    print(f"  DCI 0_1 ≈ {dci_0_1} bits  "
          f"(FDRA={fdra_ul}, TDRA={tdra_ul}, DAI={dai_ul})")
    #print("  Cross-check these against dci_sizes_list in your TOML.")
    print()


if __name__ == '__main__':
    main()