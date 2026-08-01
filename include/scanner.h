#ifndef SCANNER_H
#define SCANNER_H

#include "common.h"

bool scan_single_file(const char* file_path, const ScanOptions* options, ThreatResult* out_threat, ScanStats* stats);
bool scan_directory(const char* dir_path, const ScanOptions* options, ThreatResult** out_threats_array, size_t* out_threat_count, ScanStats* stats);

#endif // SCANNER_H
