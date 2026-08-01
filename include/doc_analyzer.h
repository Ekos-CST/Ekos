#ifndef DOC_ANALYZER_H
#define DOC_ANALYZER_H

#include "common.h"

// Analyzes Documents (.pdf, .xls, .xlsx, .pptx, .docx) for macros, JS streams, and exploits
bool analyze_document_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat);

#endif // DOC_ANALYZER_H
