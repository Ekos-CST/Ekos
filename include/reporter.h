#ifndef REPORTER_H
#define REPORTER_H

#include "common.h"

void print_banner(void);
void print_scan_progress(const ScanStats* stats, const char* current_file);
void print_threat_found(const ThreatResult* threat);
void print_scan_summary(const ScanStats* stats, const ScanOptions* options);

bool export_json_report(const char* report_path, const ScanStats* stats, const ThreatResult* threats, size_t threat_count, const ScanOptions* options);
bool export_txt_report(const char* report_path, const ScanStats* stats, const ThreatResult* threats, size_t threat_count, const ScanOptions* options);

#endif // REPORTER_H
