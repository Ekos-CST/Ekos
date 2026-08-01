#include "scanner.h"
#include "cert_verifier.h"
#include "signature_db.h"
#include "pe_analyzer.h"
#include "script_analyzer.h"
#include "doc_analyzer.h"
#include "media_analyzer.h"
#include "reporter.h"
#include "quarantine.h"

// Utility: Timer
double get_current_time_seconds(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}

// Utility: File Extension
const char* get_file_extension(const char* filename) {
    if (!filename) return "";
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot;
}

// Utility: Severity to String
const char* severity_to_string(ThreatSeverity sev) {
    switch (sev) {
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Utility: Calculate Entropy (Shannon Entropy)
double calculate_file_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    uint64_t count[256] = {0};
    for (size_t i = 0; i < size; i++) {
        count[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (count[i] > 0) {
            double p = (double)count[i] / (double)size;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    return entropy;
}

// Utility: SHA-256 Hash directly from memory buffer (0 extra disk reads)
void calculate_sha256_buffer(const uint8_t* data, size_t size, char* out_hash_hex) {
    if (!out_hash_hex) return;

    strcpy(out_hash_hex, "0000000000000000000000000000000000000000000000000000000000000000");
    if (!data || size == 0) return;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data, (DWORD)size, 0)) {
                BYTE hash_bytes[32];
                DWORD hash_len = sizeof(hash_bytes);
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash_bytes, &hash_len, 0)) {
                    for (DWORD i = 0; i < hash_len; i++) {
                        sprintf(out_hash_hex + (i * 2), "%02x", hash_bytes[i]);
                    }
                    out_hash_hex[64] = '\0';
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

void calculate_sha256_hash(const char* file_path, char* out_hash_hex) {
    (void)file_path;
    if (out_hash_hex) strcpy(out_hash_hex, "0000000000000000000000000000000000000000000000000000000000000000");
}

// Drive Total Used Bytes calculation using Windows System API (Instant 0ms lookup)
static uint64_t get_drive_used_bytes(const char* drive_path) {
    ULARGE_INTEGER free_bytes_available, total_number_of_bytes, total_number_of_free_bytes;
    if (GetDiskFreeSpaceExA(drive_path, &free_bytes_available, &total_number_of_bytes, &total_number_of_free_bytes)) {
        return total_number_of_bytes.QuadPart - total_number_of_free_bytes.QuadPart;
    }
    return 107374182400ULL; // 100 GB fallback
}

// Pre-calculation helper for exact size-based scan estimation in custom directory
static uint64_t calculate_directory_total_bytes(const char* dir_path) {
    if (!dir_path) return 0;

    // Fast disk API lookup for root drives
    if (strlen(dir_path) <= 3 && dir_path[1] == ':') {
        return get_drive_used_bytes(dir_path);
    }

    uint64_t total = 0;
    char search_path[MAX_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            total += calculate_directory_total_bytes(full_path);
        } else {
            uint64_t fsize = ((uint64_t)find_data.nFileSizeHigh << 32) | find_data.nFileSizeLow;
            total += fsize;
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
    return total;
}

// Exact size pre-calculator for Quick Scan (RAM process executables)
static uint64_t calculate_quick_scan_total_bytes(void) {
    uint64_t total = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 67108864ULL;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                char exe_path[MAX_PATH_LEN];
                DWORD path_len = MAX_PATH_LEN;
                if (QueryFullProcessImageNameA(hProc, 0, exe_path, &path_len) && path_len > 0) {
                    WIN32_FILE_ATTRIBUTE_DATA attr;
                    if (GetFileAttributesExA(exe_path, GetFileExInfoStandard, &attr)) {
                        total += ((uint64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return (total > 0) ? total : 67108864ULL;
}

// Memory-Mapped High-Speed Single File Scanning
bool scan_single_file(const char* file_path, const ScanOptions* options, ThreatResult* out_threat, ScanStats* stats) {
    if (!file_path || !options || !out_threat || !stats) return false;

    memset(out_threat, 0, sizeof(ThreatResult));
    strncpy(out_threat->file_path, file_path, MAX_PATH_LEN - 1);

    // 0. Ekos Digital License & Quarantine Exemption Check
    if (is_ekos_licensed_file(file_path)) {
        return false;
    }

    InterlockedIncrement64((LONG64*)&stats->total_files_scanned);

    // Get exact file size beforehand for accurate progress byte tracking
    WIN32_FILE_ATTRIBUTE_DATA attr;
    uint64_t file_size = 0;
    if (GetFileAttributesExA(file_path, GetFileExInfoStandard, &attr)) {
        file_size = ((uint64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
    }

    const char* ext = get_file_extension(file_path);

    // 1. Digital Signature Check: Bypass certified system & software binaries (Quick & Full Scan)
    if (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 || _stricmp(ext, ".sys") == 0 || _stricmp(ext, ".msi") == 0) {
        if (is_certified_system_file(file_path)) {
            InterlockedIncrement64((LONG64*)&stats->skipped_certified_files);
            InterlockedExchangeAdd64((LONG64*)&stats->total_bytes_scanned, (LONG64)file_size);
            return false;
        }
    }

    // 2. Open File with Kernel Disk Cache Optimization Hint
    HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        InterlockedExchangeAdd64((LONG64*)&stats->total_bytes_scanned, (LONG64)file_size);
        return false;
    }

    DWORD file_size_high = 0;
    DWORD file_size_low = GetFileSize(hFile, &file_size_high);
    if (file_size_low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        CloseHandle(hFile);
        InterlockedExchangeAdd64((LONG64*)&stats->total_bytes_scanned, (LONG64)file_size);
        return false;
    }

    file_size = ((uint64_t)file_size_high << 32) | file_size_low;
    InterlockedExchangeAdd64((LONG64*)&stats->total_bytes_scanned, (LONG64)file_size);

    if (stats->total_bytes_to_scan == 0) {
        stats->total_bytes_to_scan = file_size;
    }

    if (file_size > 268435456ULL || file_size == 0) {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    const uint8_t* buffer = (const uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!buffer) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // 3. Fast Extension Pre-filtering for Deep Scans
    bool is_scannable_type = (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 || _stricmp(ext, ".sys") == 0 ||
                              _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".bat") == 0 || _stricmp(ext, ".cmd") == 0 ||
                              _stricmp(ext, ".ps1") == 0 || _stricmp(ext, ".vbs") == 0 || _stricmp(ext, ".js") == 0 ||
                              _stricmp(ext, ".pdf") == 0 || _stricmp(ext, ".png") == 0 || _stricmp(ext, ".jpg") == 0 ||
                              _stricmp(ext, ".jpeg") == 0 || (file_size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z'));

    if (!is_scannable_type) {
        UnmapViewOfFile(buffer);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // 4. Calculate SHA-256 Hash & Check Signature Databases
    calculate_sha256_buffer(buffer, (size_t)file_size, out_threat->file_hash_sha256);
    if (check_hash_signature(out_threat->file_hash_sha256, out_threat)) {
        UnmapViewOfFile(buffer);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        InterlockedIncrement64((LONG64*)&stats->threats_detected);
        return true;
    }

    if (check_byte_pattern_signatures(buffer, (size_t)file_size, out_threat)) {
        UnmapViewOfFile(buffer);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        InterlockedIncrement64((LONG64*)&stats->threats_detected);
        return true;
    }

    // 5. Deep Structural Analysis Routing
    bool detected = false;
    if (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 || _stricmp(ext, ".sys") == 0 || _stricmp(ext, ".scr") == 0 ||
        (file_size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z')) {
        detected = analyze_pe_executable(file_path, buffer, (size_t)file_size, out_threat);
    } else if (_stricmp(ext, ".bat") == 0 || _stricmp(ext, ".cmd") == 0 || _stricmp(ext, ".ps1") == 0 ||
               _stricmp(ext, ".vbs") == 0 || _stricmp(ext, ".js") == 0) {
        detected = analyze_script_file(file_path, buffer, (size_t)file_size, out_threat);
    } else if (_stricmp(ext, ".pdf") == 0) {
        detected = analyze_document_file(file_path, buffer, (size_t)file_size, out_threat);
    } else if (_stricmp(ext, ".png") == 0 || _stricmp(ext, ".jpeg") == 0 || _stricmp(ext, ".jpg") == 0) {
        detected = analyze_media_file(file_path, buffer, (size_t)file_size, out_threat);
    }

    UnmapViewOfFile(buffer);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (detected) {
        InterlockedIncrement64((LONG64*)&stats->threats_detected);
        return true;
    }

    return false;
}

// Quick Scan Submodule: Scan Active Running Background Memory Processes
#define MAX_SCANNED_CACHE 1024
typedef char PathBuffer[MAX_PATH_LEN];

static void scan_running_processes(const ScanOptions* options, ThreatResult** out_threats_array, size_t* out_threat_count, size_t* capacity, ScanStats* stats) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    PathBuffer* scanned_paths = (PathBuffer*)malloc(MAX_SCANNED_CACHE * sizeof(PathBuffer));
    size_t scanned_cache_count = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                char exe_path[MAX_PATH_LEN];
                DWORD path_len = MAX_PATH_LEN;
                if (QueryFullProcessImageNameA(hProc, 0, exe_path, &path_len) && path_len > 0) {
                    bool already_scanned = false;
                    for (size_t i = 0; i < scanned_cache_count; i++) {
                        if (_stricmp(scanned_paths[i], exe_path) == 0) {
                            already_scanned = true;
                            break;
                        }
                    }

                    if (!already_scanned) {
                        if (scanned_cache_count < MAX_SCANNED_CACHE) {
                            strncpy(scanned_paths[scanned_cache_count++], exe_path, MAX_PATH_LEN - 1);
                        }

                        // Emit live progress to GUI stdout
                        print_scan_progress(stats, exe_path);

                        ThreatResult threat;
                        if (scan_single_file(exe_path, options, &threat, stats)) {
                            print_threat_found(&threat);
                            if (*out_threat_count >= *capacity) {
                                *capacity *= 2;
                                *out_threats_array = (ThreatResult*)realloc(*out_threats_array, *capacity * sizeof(ThreatResult));
                            }
                            (*out_threats_array)[*out_threat_count] = threat;
                            (*out_threat_count)++;
                        }
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(hSnap, &pe));
    }
    if (scanned_paths) free(scanned_paths);
    CloseHandle(hSnap);
}

// Quick Scan Submodule: Scan Registry & Startup Folder Shortcuts
static void scan_startup_locations(const ScanOptions* options, ThreatResult** out_threats_array, size_t* out_threat_count, size_t* capacity, ScanStats* stats) {
    HKEY hKey;
    const char* run_keys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    for (int k = 0; k < 2; k++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, run_keys[k], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwValues = 0, dwMaxValLen = 0, dwMaxDataLen = 0;
            if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValues, &dwMaxValLen, &dwMaxDataLen, NULL, NULL) == ERROR_SUCCESS) {
                char* valName = (char*)malloc(dwMaxValLen + 1);
                BYTE* valData = (BYTE*)malloc(dwMaxDataLen + 1);

                for (DWORD i = 0; i < dwValues; i++) {
                    DWORD valLen = dwMaxValLen + 1;
                    DWORD dataLen = dwMaxDataLen + 1;
                    DWORD type = 0;
                    if (RegEnumValueA(hKey, i, valName, &valLen, NULL, &type, valData, &dataLen) == ERROR_SUCCESS) {
                        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                            char path_buf[MAX_PATH_LEN];
                            strncpy(path_buf, (char*)valData, MAX_PATH_LEN - 1);
                            char* clean_path = path_buf;
                            if (clean_path[0] == '"') {
                                clean_path++;
                                char* end_quote = strchr(clean_path, '"');
                                if (end_quote) *end_quote = '\0';
                            }

                            if (GetFileAttributesA(clean_path) != INVALID_FILE_ATTRIBUTES) {
                                // Emit live progress to GUI stdout
                                print_scan_progress(stats, clean_path);

                                ThreatResult threat;
                                if (scan_single_file(clean_path, options, &threat, stats)) {
                                    print_threat_found(&threat);
                                    if (*out_threat_count >= *capacity) {
                                        *capacity *= 2;
                                        *out_threats_array = (ThreatResult*)realloc(*out_threats_array, *capacity * sizeof(ThreatResult));
                                    }
                                    (*out_threats_array)[*out_threat_count] = threat;
                                    (*out_threat_count)++;
                                }
                            }
                        }
                    }
                }
                free(valName);
                free(valData);
            }
            RegCloseKey(hKey);
        }
    }
}

static void scan_all_logical_drives(const ScanOptions* options, ThreatResult** out_threats_array, size_t* out_threat_count, size_t* capacity, ScanStats* stats) {
    char drives_buf[512] = {0};
    DWORD len = GetLogicalDriveStringsA(sizeof(drives_buf) - 1, drives_buf);
    if (len > 0 && len < sizeof(drives_buf)) {
        char* drive = drives_buf;
        while (*drive) {
            UINT drive_type = GetDriveTypeA(drive);
            if (drive_type == DRIVE_FIXED || drive_type == DRIVE_REMOVABLE || drive_type == DRIVE_RAMDISK) {
                char clean_drive[MAX_PATH_LEN];
                strncpy(clean_drive, drive, MAX_PATH_LEN - 1);
                size_t dlen = strlen(clean_drive);
                if (dlen > 0 && clean_drive[dlen - 1] == '\\') {
                    clean_drive[dlen - 1] = '\0';
                }

                ThreatResult* sub_threats = NULL;
                size_t sub_count = 0;
                if (scan_directory(clean_drive, options, &sub_threats, &sub_count, stats)) {
                    for (size_t i = 0; i < sub_count; i++) {
                        if (*out_threat_count >= *capacity) {
                            *capacity *= 2;
                            *out_threats_array = (ThreatResult*)realloc(*out_threats_array, *capacity * sizeof(ThreatResult));
                        }
                        (*out_threats_array)[*out_threat_count] = sub_threats[i];
                        (*out_threat_count)++;
                    }
                    free(sub_threats);
                }
            }
            drive += strlen(drive) + 1;
        }
    }
}

static void console_set_color(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

static void console_reset_color(void) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Dynamic process and startup file counter for Quick Scan
static uint64_t calculate_quick_scan_process_count(void) {
    uint64_t count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe)) {
            do {
                count++;
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    count += 35; // Add Windows Startup registry entries and shortcuts
    return (count > 0) ? count : 150;
}

// Pre-indexing helper to count all files and bytes in target folder/drive before scan starts
static void enumerate_directory_count(const char* dir_path, uint64_t* out_files, uint64_t* out_bytes) {
    if (!dir_path || !out_files || !out_bytes) return;

    char search_path[MAX_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) return;

    static double last_indexing_print = 0.0;

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) continue;

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Avoid symbolic links, junctions, and reparse points to prevent infinite recursive loops
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                enumerate_directory_count(full_path, out_files, out_bytes);
            }
        } else {
            (*out_files)++;
            uint64_t fsize = ((uint64_t)find_data.nFileSizeHigh << 32) | find_data.nFileSizeLow;
            (*out_bytes) += fsize;

            double now = get_current_time_seconds();
            if (now - last_indexing_print >= 0.05) {
                last_indexing_print = now;
                console_set_color(FOREGROUND_GREEN | FOREGROUND_BLUE);
                printf("\r[İNDEKSLEME] Path: %s | İndekslenen: %llu | Sertifikalı Atlanan: 0 | Tehdit: 0 | Tahmini Kalan: Hesaplanıyor...\n",
                       full_path, (unsigned long long)*out_files);
                console_reset_color();
                fflush(stdout);
            }
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
}

bool scan_directory(const char* dir_path, const ScanOptions* options, ThreatResult** out_threats_array, size_t* out_threat_count, ScanStats* stats) {
    if (!dir_path || !options || !out_threats_array || !out_threat_count || !stats) return false;

    size_t capacity = 32;
    *out_threats_array = (ThreatResult*)malloc(capacity * sizeof(ThreatResult));
    *out_threat_count = 0;

    // Phase 1: Pre-Scan Target File & Byte Count Indexing & Exact ETR Calculation
    if (stats->total_files_to_scan == 0 && stats->total_files_scanned == 0) {
        console_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("[İNDEKSLEME] Hedef cihazdaki tüm dosyalar ve toplam boyut taranıp hesaplanıyor...\n");
        console_reset_color();

        uint64_t indexed_files = 0;
        uint64_t indexed_bytes = 0;

        if (options->mode == SCAN_MODE_QUICK) {
            indexed_files = calculate_quick_scan_process_count();
            indexed_bytes = calculate_quick_scan_total_bytes();
        } else if (strcmp(dir_path, "ALL_DRIVES") == 0) {
            char drives_buf[512] = {0};
            DWORD len = GetLogicalDriveStringsA(sizeof(drives_buf) - 1, drives_buf);
            if (len > 0) {
                char* drv = drives_buf;
                while (*drv) {
                    UINT dType = GetDriveTypeA(drv);
                    if (dType == DRIVE_FIXED || dType == DRIVE_REMOVABLE) {
                        char clean_drv[MAX_PATH_LEN];
                        strncpy(clean_drv, drv, MAX_PATH_LEN - 1);
                        size_t dlen = strlen(clean_drv);
                        if (dlen > 0 && clean_drv[dlen - 1] == '\\') clean_drv[dlen - 1] = '\0';
                        enumerate_directory_count(clean_drv, &indexed_files, &indexed_bytes);
                    }
                    drv += strlen(drv) + 1;
                }
            }
        } else {
            enumerate_directory_count(dir_path, &indexed_files, &indexed_bytes);
        }

        stats->total_files_to_scan = (indexed_files > 0) ? indexed_files : 100;
        stats->total_bytes_to_scan = (indexed_bytes > 0) ? indexed_bytes : (stats->total_files_to_scan * 1024ULL * 100ULL);

        // Display initial exact ETR after indexing finishes (based on ~240 files/sec throughput)
        double estimated_fps = 240.0;
        uint32_t init_etr_sec = (uint32_t)(stats->total_files_to_scan / estimated_fps);
        if (init_etr_sec < 3) init_etr_sec = 3;

        uint32_t ih = init_etr_sec / 3600;
        uint32_t im = (init_etr_sec % 3600) / 60;
        uint32_t is = init_etr_sec % 60;

        console_set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("\r[İNDEKSLEME TAMAMLANDI] Path: %s | Dosyalar: %llu | Sertifikalı Atlanan: 0 | Tehdit: 0 | Tahmini Kalan: %02u:%02u:%02u\n",
               dir_path, (unsigned long long)stats->total_files_to_scan, ih, im, is);
        console_reset_color();
        fflush(stdout);
    }

    // Quick Scan mode: Calibrate target size accurately for RAM processes
    if (options->mode == SCAN_MODE_QUICK) {
        printf(" [HIZLI TARAMA] RAM Aktif Bellek Süreçleri Taranıyor...\n");
        scan_running_processes(options, out_threats_array, out_threat_count, &capacity, stats);

        printf(" [HIZLI TARAMA] Windows Başlangıç Kayıt Defteri ve Kısayollar Taranıyor...\n");
        scan_startup_locations(options, out_threats_array, out_threat_count, &capacity, stats);
        return true;
    }

    // Full Scan Mode with ALL_DRIVES or root target path
    static bool is_full_scan_started = false;
    if (options->mode == SCAN_MODE_FULL && !is_full_scan_started && (strcmp(dir_path, "ALL_DRIVES") == 0 || strcmp(dir_path, "C:") == 0 || strcmp(dir_path, "C:\\") == 0)) {
        is_full_scan_started = true;
        scan_all_logical_drives(options, out_threats_array, out_threat_count, &capacity, stats);
        is_full_scan_started = false;
        return true;
    }

    // Traverse directory tree
    char search_path[MAX_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) return false;

    // Console Progress Update Rate Limiter (20 FPS max update rate)
    static double last_ui_update_time = 0.0;

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse subdirectories
            ThreatResult* sub_threats = NULL;
            size_t sub_count = 0;
            if (scan_directory(full_path, options, &sub_threats, &sub_count, stats)) {
                for (size_t i = 0; i < sub_count; i++) {
                    if (*out_threat_count >= capacity) {
                        capacity *= 2;
                        *out_threats_array = (ThreatResult*)realloc(*out_threats_array, capacity * sizeof(ThreatResult));
                    }
                    (*out_threats_array)[*out_threat_count] = sub_threats[i];
                    (*out_threat_count)++;
                }
                free(sub_threats);
            }
        } else {
            // Rate-limited UI progress printing (max once per 50ms to prevent stdout pipe bottleneck)
            double now = get_current_time_seconds();
            if (now - last_ui_update_time >= 0.05) {
                print_scan_progress(stats, full_path);
                last_ui_update_time = now;
            }

            ThreatResult threat;
            if (scan_single_file(full_path, options, &threat, stats)) {
                print_threat_found(&threat);

                if (options->enable_quarantine) {
                    quarantine_file(full_path, options->quarantine_dir, &threat);
                }

                if (*out_threat_count >= capacity) {
                    capacity *= 2;
                    *out_threats_array = (ThreatResult*)realloc(*out_threats_array, capacity * sizeof(ThreatResult));
                }
                (*out_threats_array)[*out_threat_count] = threat;
                (*out_threat_count)++;
            }
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
    return true;
}
