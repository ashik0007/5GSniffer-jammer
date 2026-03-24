# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

5GSniffer is a passive 5G NR sniffer that captures and decodes PDCCH (Physical Downlink Control Channel) messages from live 5G signals. It can operate with a USRP SDR hardware source or replay from IQ sample files. Developed at SpriteLab @ Northeastern University (AGPL-3.0).

## Build Commands

Requires clang-14, cmake, and dependencies: `libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev libliquid-dev libzmq3-dev libspdlog-dev libfmt-dev libuhd-dev`

```bash
# Standard build (from repo root 5gsniffer/)
mkdir -p build && cd build
cmake -DCMAKE_C_COMPILER=/usr/bin/clang-14 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 ..
make -j8

# Or use the convenience script
./compile.sh

# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=/usr/bin/clang-14 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 ..
make -j8
```

The srsRAN library (`lib/srsRANRF/`) is a git submodule and is built as a CMake ExternalProject automatically.

## Running

```bash
# Run with a config file (defaults to config.toml in CWD)
./build/src/5g_sniffer <path_to_config.toml>

# Control log verbosity
SPDLOG_LEVEL=debug ./build/src/5g_sniffer config.toml
```

Example TOML configs are in `tomls/` and in the repo root (`test-Private5G-n71.toml`, `test-public5G.toml`).

## Running Tests

Tests are built alongside the main binary and run automatically post-build. To run manually:

```bash
./build/test/5gsniffer_test
```

Test source files are in `test/` and use GoogleTest. The test binary links against `5gsnifferlib` (a static lib built from all sources).

## Architecture

### Processing Pipeline

The core abstraction is the `worker` base class (`include/worker.h`). Workers form a directed graph: each worker processes input and calls `send_to_next_workers()` to pass data downstream. Connections are made via `worker::connect(shared_ptr<worker>)`.

Signal flow:
```
SDR/FileSource (sdr.cc / file_source.cc)
  -> syncer         — PSS/SSS detection, cell sync, MIB decode; spawns flow_pool
    -> flow_pool    — ZMQ-based pool of parallel flows for per-frame processing
      -> flow       — per-frame worker dispatching over ZMQ
        -> ofdm     — FFT, CP removal, produces symbols
          -> channel_mapper  — routes symbols to PDCCH decoder
            -> nr::pdcch     — DMRS correlation, DCI blind decoding
              -> DatasetWriter  — writes decoded DCIs to CSV
```

### Key Classes

- **`sniffer`** (`include/sniffer.h`): Entry point. Creates either an SDR or file source worker and wires the pipeline.
- **`syncer`** (`include/syncer.h`): Performs PSS/SSS search, fine sync, MIB decoding. Uses a state machine (`find_pss → fine_sync → find_sss → wait/relay`). On sync, creates a `flow_pool`.
- **`nr::phy`** (`include/phy.h`): Holds cell identity (nid1, nid2), SSB index, and a list of `bandwidth_part` objects describing active BWPs.
- **`bandwidth_part`** (`include/bandwidth_part.h`): Encapsulates all timing/frequency parameters for a given numerology (SCS, FFT size, slots/frame, samples/symbol).
- **`flow` / `flow_pool`** (`include/flow.h`, `include/flow_pool.h`): ZMQ ROUTER/DEALER pattern dispatches sample chunks to a pool of parallel processing flows.
- **`channel_mapper`** (`include/channel_mapper.h`): Receives OFDM symbols, owns an `nr::pdcch` instance, routes symbols to it.
- **`nr::pdcch`** (`include/pdcch.h`): Full PDCCH blind decoder. Searches over RNTI range, scrambling IDs, aggregation levels, and candidates. Uses srsRAN's `srsran_pdcch_nr_decode()`. Shares a static `DatasetWriter` instance.
- **`DatasetWriter`** (`include/dataset_writer.h`): Thread-safe, append-mode CSV writer for decoded DCI records (`dci_dataset.csv`).
- **`dci_parser`** (`include/dci_parser.h`): Parses DCI formats 0_1 (UL) and 1_1 (DL) per 3GPP TS 38.212. Computes TBS, PRB allocation (RIV decode), MCS/modulation. Includes a `HarqStateTracker` for retransmission detection.

### Configuration (TOML)

The `[sniffer]` table sets RF parameters (frequency, sample_rate, rf_args for UHD, or file_path for file replay). Each `[[pdcch]]` table configures one PDCCH decoder instance with its CORESET geometry, RNTI search range, DCI sizes, and correlation thresholds. Multiple `[[pdcch]]` blocks are supported for monitoring multiple CORESETs simultaneously.

Key `[[pdcch]]` parameters:
- `coreset_id`, `coreset_duration`, `coreset_ofdm_symbol_start`, `coreset_interleaving_pattern`
- `subcarrier_offset`: offset from center frequency to CORESET in subcarriers
- `rnti_start`/`rnti_end`: RNTI search range
- `scrambling_id_start`/`scrambling_id_end`: scrambling ID search range
- `dci_sizes_list`: list of DCI bit sizes to attempt decoding
- `AL_corr_thresholds`: per-aggregation-level DMRS correlation thresholds `[AL1, AL2, AL4, AL8, AL16]`
- `num_candidates_per_AL`: search space candidates per aggregation level

### Dependencies

- **srsRAN** (`lib/srsRANRF/`): Provides `srsran_pdcch_nr_decode()`, `srsran_mib_nr_t`, and RF chain. Built as ExternalProject.
- **GoogleTest** (`lib/googletest/`): Unit testing, also built in-tree.
- **liquid-dsp**: Resampling (`resamp_crcf`) used in syncer.
- **libvolk**: SIMD-accelerated DSP primitives.
- **libzmq**: Inter-flow IPC for the flow pool.
- **spdlog**: Structured logging. Log level set via `SPDLOG_LEVEL` env var.
- **toml++**: Header-only TOML parser (included inline).

### Branch Context

The active branch `sniffing_fingerprint_v-0.3` extends the original sniffer with DCI dataset collection for fingerprinting. New files not in upstream: `src/dci_parser.cc`, `src/dataset_writer.cc`, `include/dci_parser.h`, `include/dataset_writer.h`. The `nr::pdcch` class has static members (`dataset_writer_`, `harq_tracker_`, `carrier_config_`) shared across all PDCCH instances.
