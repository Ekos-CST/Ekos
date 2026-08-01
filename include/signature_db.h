#ifndef SIGNATURE_DB_H
#define SIGNATURE_DB_H

#include "common.h"

typedef struct {
    char sha256_hash[65];
    char threat_name[MAX_THREAT_NAME_LEN];
    char threat_type[64];
    ThreatSeverity severity;
    char description[MAX_DESCRIPTION_LEN];
} HashSignature;

typedef struct {
    char threat_name[MAX_THREAT_NAME_LEN];
    char threat_type[64];
    ThreatSeverity severity;
    const uint8_t* pattern_bytes;
    size_t pattern_len;
    char description[MAX_DESCRIPTION_LEN];
} PatternSignature;

void init_signature_database(void);
bool check_hash_signature(const char* sha256_hash, ThreatResult* out_threat);
bool check_byte_pattern_signatures(const uint8_t* data, size_t size, ThreatResult* out_threat);

#endif // SIGNATURE_DB_H
