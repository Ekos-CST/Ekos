#include "pe_analyzer.h"
#include "cert_verifier.h"
#include "signature_db.h"
#include <winnt.h>

// High-confidence malicious process injection & thread hijacking APIs
static const char* g_suspicious_apis[] = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "RtlCreateUserThread",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
    "SetThreadContext"
};

static size_t g_suspicious_api_count = sizeof(g_suspicious_apis) / sizeof(g_suspicious_apis[0]);

// Forward declaration for sandbox recursion guard
static bool analyze_pe_internal(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat, bool is_sandbox_pass);

bool analyze_pe_executable(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat) {
    return analyze_pe_internal(file_path, data, size, out_threat, false);
}

static bool analyze_pe_internal(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat, bool is_sandbox_pass) {
    if (!data || size < sizeof(IMAGE_DOS_HEADER) || !out_threat) return false;

    // 0. Digital Signature Trust Check (Only for initial raw binary; sandbox unpacked memory payloads skip sig trust check)
    if (!is_sandbox_pass && file_path) {
        if (is_certified_system_file(file_path)) {
            return false; // Trusted signed binary (Git, SolidWorks, Microsoft, Opera, etc.)
        }
    }

    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)data;
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return false; // Not a valid PE file
    }

    if ((size_t)dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > size) {
        return false;
    }

    PIMAGE_NT_HEADERS32 nt_hdr32 = (PIMAGE_NT_HEADERS32)(data + dos_hdr->e_lfanew);
    if (nt_hdr32->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    bool is_64bit = (nt_hdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    PIMAGE_NT_HEADERS64 nt_hdr64 = (PIMAGE_NT_HEADERS64)nt_hdr32;

    WORD num_sections = nt_hdr32->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER section_hdr = NULL;

    if (is_64bit) {
        section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&nt_hdr64->OptionalHeader + nt_hdr64->FileHeader.SizeOfOptionalHeader);
    } else {
        section_hdr = (PIMAGE_SECTION_HEADER)((uint8_t*)&nt_hdr32->OptionalHeader + nt_hdr32->FileHeader.SizeOfOptionalHeader);
    }

    // Check if filename indicates a software installer (NSIS, Inno, WiX)
    bool is_installer = false;
    if (file_path) {
        char lower_name[MAX_PATH_LEN];
        strncpy(lower_name, file_path, MAX_PATH_LEN - 1);
        lower_name[MAX_PATH_LEN - 1] = '\0';
        for (int i = 0; lower_name[i]; i++) {
            if (lower_name[i] >= 'A' && lower_name[i] <= 'Z') lower_name[i] += 32;
        }
        if (strstr(lower_name, "setup") || strstr(lower_name, "installer") || strstr(lower_name, "-amd64.exe") || strstr(lower_name, "-x64.exe")) {
            is_installer = true;
        }
    }

    // 1. Calculate File Entropy
    double entropy = calculate_file_entropy(data, size);
    out_threat->entropy = entropy;

    int suspicious_score = 0;
    char indicators[MAX_DESCRIPTION_LEN] = "";

    // 2. Inspect Sections
    bool has_packed_section = false;
    bool has_wx_section = false;
    DWORD last_section_end = 0;

    for (WORD i = 0; i < num_sections && i < 32; i++) {
        if ((uint8_t*)&section_hdr[i] + sizeof(IMAGE_SECTION_HEADER) > data + size) break;

        char sec_name[9] = {0};
        memcpy(sec_name, section_hdr[i].Name, 8);

        DWORD sec_raw_end = section_hdr[i].PointerToRawData + section_hdr[i].SizeOfRawData;
        if (sec_raw_end > last_section_end && sec_raw_end <= size) {
            last_section_end = sec_raw_end;
        }

        if (strstr(sec_name, "UPX") || strstr(sec_name, ".aspack") || strstr(sec_name, ".themida") || strstr(sec_name, ".vmp")) {
            has_packed_section = true;
            strncat(indicators, "[Packed Section: ", sizeof(indicators) - strlen(indicators) - 1);
            strncat(indicators, sec_name, sizeof(indicators) - strlen(indicators) - 1);
            strncat(indicators, "] ", sizeof(indicators) - strlen(indicators) - 1);
        }

        // Check for hidden PE binary payload inside .rsrc section
        if (strcmp(sec_name, ".rsrc") == 0 && section_hdr[i].SizeOfRawData >= 512) {
            DWORD rsrc_offset = section_hdr[i].PointerToRawData;
            if (rsrc_offset + 2 < size && data[rsrc_offset] == 'M' && data[rsrc_offset + 1] == 'Z') {
                suspicious_score += 45;
                strncat(indicators, "[Hidden Executable Payload inside .rsrc Resource Section] ", sizeof(indicators) - strlen(indicators) - 1);
            }
        }

        // Section execution permissions check (Writable & Executable)
        if ((section_hdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            has_wx_section = true;
            suspicious_score += 35;
            strncat(indicators, "[Writable & Executable Section] ", sizeof(indicators) - strlen(indicators) - 1);
        }
    }

    if (entropy > 7.50 && !is_installer) {
        suspicious_score += 25;
        strncat(indicators, "[High Entropy / Packed (>7.5)] ", sizeof(indicators) - strlen(indicators) - 1);
    }

    // 3. SANDBOX EMULATION & DEPACK / DECRYPT EXECUTION PASS
    if (!is_sandbox_pass && (has_packed_section || (entropy > 7.0 && !is_installer) || has_wx_section || size > last_section_end + 16)) {
        UnpackedPayload payload;
        if (sandbox_emulate_and_unpack(data, size, &payload)) {
            if (payload.is_unpacked && payload.decrypted_data && payload.decrypted_size > 0) {

                // 3a. Check byte pattern signatures on the decrypted core payload
                if (check_byte_pattern_signatures(payload.decrypted_data, payload.decrypted_size, out_threat)) {
                    strncat(out_threat->description, " ", sizeof(out_threat->description) - strlen(out_threat->description) - 1);
                    strncat(out_threat->description, payload.core_indicators, sizeof(out_threat->description) - strlen(out_threat->description) - 1);
                    strncpy(out_threat->threat_type, payload.packer_type, 63);
                    free_unpacked_payload(&payload);
                    return true;
                }

                // 3b. Inspect decrypted raw core payload for suspicious injection APIs & NOP sleds
                int core_suspicious = 0;
                char core_indicators[MAX_DESCRIPTION_LEN] = "";

                for (size_t a = 0; a < g_suspicious_api_count; a++) {
                    if (strstr((const char*)payload.decrypted_data, g_suspicious_apis[a])) {
                        core_suspicious += 25;
                        strncat(core_indicators, "[Decrypted API: ", sizeof(core_indicators) - strlen(core_indicators) - 1);
                        strncat(core_indicators, g_suspicious_apis[a], sizeof(core_indicators) - strlen(core_indicators) - 1);
                        strncat(core_indicators, "] ", sizeof(core_indicators) - strlen(core_indicators) - 1);
                    }
                }

                for (size_t j = 0; j + 32 < payload.decrypted_size; j++) {
                    if (payload.decrypted_data[j] == 0x90) {
                        int nop_c = 0;
                        while (j + nop_c < payload.decrypted_size && payload.decrypted_data[j + nop_c] == 0x90) nop_c++;
                        if (nop_c >= 16) {
                            core_suspicious += 45;
                            strncat(core_indicators, "[Decrypted NOP Sled] ", sizeof(core_indicators) - strlen(core_indicators) - 1);
                            break;
                        }
                    }
                }

                if (core_suspicious >= 50) {
                    out_threat->is_threat = true;
                    out_threat->severity = (core_suspicious >= 90) ? SEVERITY_CRITICAL : SEVERITY_HIGH;
                    strncpy(out_threat->threat_name, "Heuristic.PE.DecryptedCorePayload", MAX_THREAT_NAME_LEN - 1);
                    strncpy(out_threat->threat_type, payload.packer_type, 63);
                    snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "PE Heuristic Core Score: %d/100. Indicators: %s %s",
                             core_suspicious, core_indicators, payload.core_indicators);
                    snprintf(out_threat->offset_location, sizeof(out_threat->offset_location),
                             "Sandbox Extracted Core Payload | Size: %zu B", payload.decrypted_size);
                    snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail),
                             "Decrypted Core Payload | Packer: %s | Entropy: %.2f",
                             payload.packer_type, payload.decrypted_entropy);
                    free_unpacked_payload(&payload);
                    return true;
                }

                // 3c. If core payload is a full PE binary, run full PE analysis
                ThreatResult core_threat;
                memset(&core_threat, 0, sizeof(ThreatResult));
                if (file_path) strncpy(core_threat.file_path, file_path, MAX_PATH_LEN - 1);

                if (analyze_pe_internal(file_path, payload.decrypted_data, payload.decrypted_size, &core_threat, true)) {
                    *out_threat = core_threat;
                    strncpy(out_threat->threat_type, payload.packer_type, 63);
                    free_unpacked_payload(&payload);
                    return true;
                }

                free_unpacked_payload(&payload);
            }
        }
    }

    if (suspicious_score >= 80) {
        out_threat->is_threat = true;
        out_threat->severity = SEVERITY_HIGH;
        strncpy(out_threat->threat_name, "Heuristic.PE.SuspiciousExecutable", MAX_THREAT_NAME_LEN - 1);
        strncpy(out_threat->threat_type, "PE.HeuristicEngine", 63);
        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "PE Heuristic Score: %d/100. Indicators: %s", suspicious_score, indicators);
        snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "PE Section Header");
        snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Şüpheli PE Nitelikleri: %s", indicators);
        return true;
    }

    return false;
}
