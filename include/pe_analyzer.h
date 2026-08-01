#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include "common.h"
#include "sandbox_engine.h"

// Analyzes PE structures (Headers, Sections, Entropy, Import Table, Code Patterns, Sandbox Decrypt/Depack)
bool analyze_pe_executable(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat);

#endif // PE_ANALYZER_H
