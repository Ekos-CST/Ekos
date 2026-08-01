#ifndef COMMON_H
#define COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#define MAX_PATH_LEN 1024
#define MAX_THREAT_NAME_LEN 128
#define MAX_DESCRIPTION_LEN 512
#define MAX_HASH_LEN 65

typedef enum {
    SCAN_MODE_QUICK = 1,
    SCAN_MODE_FULL = 2
} ScanMode;

typedef enum {
    SEVERITY_NONE = 0,
    SEVERITY_LOW = 1,
    SEVERITY_MEDIUM = 2,
    SEVERITY_HIGH = 3,
    SEVERITY_CRITICAL = 4
} ThreatSeverity;

typedef struct {
    bool is_threat;
    ThreatSeverity severity;
    char threat_name[MAX_THREAT_NAME_LEN];
    char threat_type[64]; // e.g. PE.Ransomware, Script.Obfuscated, Stego.Payload
    char description[MAX_DESCRIPTION_LEN];
    char file_hash_sha256[MAX_HASH_LEN];
    char file_path[MAX_PATH_LEN];
    char offset_location[128]; // Exact offset/section inside file
    char exact_detail[256];    // Detailed payload hook/API
    double entropy;
} ThreatResult;

typedef struct {
    uint64_t total_files_scanned;
    uint64_t total_files_to_scan;
    uint64_t skipped_certified_files;
    uint64_t threats_detected;
    uint64_t total_bytes_scanned;
    uint64_t total_bytes_to_scan;
    double bytes_per_sec;
    double start_time;
    double end_time;
    uint32_t estimated_seconds_remaining;
} ScanStats;

typedef struct {
    ScanMode mode;
    bool enable_quarantine;
    bool verbose;
    char target_path[MAX_PATH_LEN];
    char quarantine_dir[MAX_PATH_LEN];
    char report_path[MAX_PATH_LEN];
} ScanOptions;

// Utility function prototypes
double get_current_time_seconds(void);
void calculate_sha256_buffer(const uint8_t* data, size_t size, char* out_hash_hex);
void calculate_sha256_hash(const char* file_path, char* out_hash_hex);
double calculate_file_entropy(const uint8_t* data, size_t size);
const char* severity_to_string(ThreatSeverity sev);
const char* get_file_extension(const char* filename);

#endif // COMMON_H
