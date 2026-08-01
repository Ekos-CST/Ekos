#ifndef MEDIA_ANALYZER_H
#define MEDIA_ANALYZER_H

#include "common.h"

// Analyzes Media Files (.png, .jpeg, .mp3, .mp4) for steganography, polyglots, and appended EOF payloads
bool analyze_media_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat);

#endif // MEDIA_ANALYZER_H
