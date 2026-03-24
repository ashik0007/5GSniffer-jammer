/**
 * CSV Dataset Writer for DCI messages.
 *
 * Thread-safe, flush-on-write, append-safe.
 * Writes one row per decoded DCI to dci_dataset.csv.
 */

#ifndef DATASET_WRITER_H
#define DATASET_WRITER_H

#include "dci_parser.h"
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

class DatasetWriter {
public:
  // Initialize writer. Opens file in append mode, writes header if file is new/empty.
  explicit DatasetWriter(const std::string& filepath = "../dci_dataset.csv");
  ~DatasetWriter();

  DatasetWriter(const DatasetWriter&) = delete;
  DatasetWriter& operator=(const DatasetWriter&) = delete;

  // Write one parsed DCI record to the CSV.
  void write_record(const DCIFields& fields, uint16_t rnti,
                    const std::string& rnti_type, float sample_time,
                    uint8_t slot_index, uint8_t symbol_index,
                    uint8_t aggregation_level, float correlation,
                    int64_t unix_ts_ms);

private:
  FILE* file_ = nullptr;
  std::mutex mutex_;
  void write_header();
};

#endif // DATASET_WRITER_H
