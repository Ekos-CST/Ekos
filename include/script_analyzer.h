#ifndef SCRIPT_ANALYZER_H
#define SCRIPT_ANALYZER_H

#include "common.h"

// Analyzes scripts (.bat, .cmd, .ps1, .vbs, .js, .json) for obfuscation & malicious payloads
bool analyze_script_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat);

#endif // SCRIPT_ANALYZER_H
