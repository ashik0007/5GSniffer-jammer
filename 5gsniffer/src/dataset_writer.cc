/**
 * CSV Dataset Writer implementation.
 */

#include "dataset_writer.h"
#include <cinttypes>
#include <spdlog/spdlog.h>
#include <sys/stat.h>

DatasetWriter::DatasetWriter(const std::string& filepath) {
  // Check if file exists and has content (to decide whether to write header)
  struct stat st;
  bool needs_header = (stat(filepath.c_str(), &st) != 0) || (st.st_size == 0);

  file_ = fopen(filepath.c_str(), "a");
  if (!file_) {
    SPDLOG_ERROR("Failed to open dataset file: {}", filepath);
    return;
  }

  if (needs_header) {
    write_header();
  }

  SPDLOG_INFO("Dataset writer initialized: {}", filepath);
}

DatasetWriter::~DatasetWriter() {
  if (file_) {
    fclose(file_);
    file_ = nullptr;
  }
}

void DatasetWriter::write_header() {
  if (!file_) return;
  fprintf(file_,
    "unix_timestamp_ms,sample_time,slot_index,symbol_index,rnti,rnti_type,"
    "dci_format,direction,aggregation_level,correlation,"
    "fdra,tdra,prb_start,nof_prbs,mcs,modulation,code_rate,"
    "ndi,rv,harq_process_id,is_retransmission,tb_size_bytes,"
    "tpc,dai,bwp_id,ports,dmrs_id,"
    "pucch_resource,harq_feedback,srs_request,parse_error\n");
  fflush(file_);
}

void DatasetWriter::write_record(const DCIFields& f, uint16_t rnti,
                                  const std::string& rnti_type, float sample_time,
                                  uint8_t slot_index, uint8_t symbol_index,
                                  uint8_t aggregation_level, float correlation,
                                  int64_t unix_ts_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!file_) return;

  fprintf(file_,
    "%" PRId64 ",%.6f,%u,%u,%u,%s,"
    "%s,%s,%u,%.4f,"
    "%u,%u,%u,%u,%u,%s,%.4f,"
    "%u,%u,%u,%d,%u,"
    "%u,%u,%u,%u,%u,"
    "%u,%u,%u,%s\n",
    unix_ts_ms,
    sample_time,
    static_cast<unsigned>(slot_index),
    static_cast<unsigned>(symbol_index),
    static_cast<unsigned>(rnti),
    rnti_type.c_str(),
    f.dci_format.c_str(),
    f.direction.c_str(),
    static_cast<unsigned>(aggregation_level),
    correlation,
    f.fdra,
    f.tdra,
    f.prb_start,
    f.nof_prbs,
    f.mcs,
    f.modulation.c_str(),
    f.code_rate,
    f.ndi,
    f.rv,
    f.harq_process_id,
    f.is_retransmission ? 1 : 0,
    f.tb_size_bytes,
    f.tpc,
    f.dai,
    f.bwp_id,
    f.ports,
    f.dmrs_id,
    f.pucch_resource,
    f.harq_feedback,
    f.srs_request,
    f.error_msg.empty() ? "" : f.error_msg.c_str()
  );
  fflush(file_);
}
