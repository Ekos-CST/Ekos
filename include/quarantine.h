#ifndef QUARANTINE_H
#define QUARANTINE_H

#include "common.h"

// Quarantines infected file by moving it to isolated quarantine folder and neutralizing execution
bool quarantine_file(const char* file_path, const char* quarantine_dir, ThreatResult* threat_info);

#endif // QUARANTINE_H
