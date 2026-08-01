#include "media_analyzer.h"
#include "pe_analyzer.h"
#include "script_analyzer.h"

bool analyze_media_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat) {
    if (!data || size < 16 || !out_threat) return false;

    const char* ext = get_file_extension(file_path);

    // 1. Extension vs Header Anomaly (Polyglot check)
    // If extension is media (.png, .jpeg, .mp3, .mp4) but magic header is 'MZ' (PE Executable)
    if ((_stricmp(ext, ".png") == 0 || _stricmp(ext, ".jpeg") == 0 || _stricmp(ext, ".jpg") == 0 ||
         _stricmp(ext, ".mp3") == 0 || _stricmp(ext, ".mp4") == 0) &&
        (data[0] == 'M' && data[1] == 'Z')) {

        out_threat->is_threat = true;
        out_threat->severity = SEVERITY_CRITICAL;
        strncpy(out_threat->threat_name, "Stego.Polyglot.DisguisedExecutable", MAX_THREAT_NAME_LEN - 1);
        strncpy(out_threat->threat_type, "Media.PolyglotEngine", 63);
        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "Polyglot Anomaly: File has %s extension but contains executable PE 'MZ' binary header", ext);
        return true;
    }

    // 2. PNG EOF Appended Payload Detection
    // PNG Magic Header: 89 50 4E 47 0D 0A 1A 0A
    if (size > 12 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) {
        // Find 'IEND' chunk tag
        static const uint8_t iend_tag[] = { 'I', 'E', 'N', 'D' };
        for (size_t i = 8; i <= size - 8; i++) {
            if (memcmp(data + i, iend_tag, 4) == 0) {
                size_t expected_end = i + 4 + 4; // IEND tag (4) + CRC (4)
                if (size > expected_end + 16) {
                    size_t appended_bytes = size - expected_end;
                    const uint8_t* appended_data = data + expected_end;

                    // Analyze appended bytes for executable or script signature
                    if (appended_data[0] == 'M' && appended_data[1] == 'Z') {
                        out_threat->is_threat = true;
                        out_threat->severity = SEVERITY_CRITICAL;
                        strncpy(out_threat->threat_name, "Stego.Payload.PNG.AppendedPE", MAX_THREAT_NAME_LEN - 1);
                        strncpy(out_threat->threat_type, "Media.StegoAnalyzer", 63);
                        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "PNG Steganography: %llu bytes of appended PE Executable binary found past IEND chunk marker", (unsigned long long)appended_bytes);
                        snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "PNG IEND Chunk Offset: 0x%08X (%llu. byte)", (unsigned int)expected_end, (unsigned long long)expected_end);
                        snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Resim Bloğu Sonrasına Gizlenmiş PE 'MZ' Çalıştırılabilir Kod (%llu byte)", (unsigned long long)appended_bytes);
                        return true;
                    }

                    // Check for appended scripts
                    ThreatResult sub_threat;
                    memset(&sub_threat, 0, sizeof(sub_threat));
                    if (analyze_script_file(file_path, appended_data, appended_bytes, &sub_threat)) {
                        out_threat->is_threat = true;
                        out_threat->severity = SEVERITY_HIGH;
                        strncpy(out_threat->threat_name, "Stego.Payload.PNG.AppendedScript", MAX_THREAT_NAME_LEN - 1);
                        strncpy(out_threat->threat_type, "Media.StegoAnalyzer", 63);
                        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "PNG Steganography: Appended script payload detected past IEND chunk (%s)", sub_threat.description);
                        return true;
                    }
                }
                break;
            }
        }
    }

    // 3. JPEG EOF Appended Payload Detection
    // JPEG Magic Header: FF D8 FF
    if (size > 10 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
        // Find JPEG End Marker: FF D9
        for (size_t i = size - 2; i >= 3; i--) {
            if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                size_t expected_end = i + 2;
                if (size > expected_end + 32) {
                    size_t appended_bytes = size - expected_end;
                    const uint8_t* appended_data = data + expected_end;

                    if (appended_data[0] == 'M' && appended_data[1] == 'Z') {
                        out_threat->is_threat = true;
                        out_threat->severity = SEVERITY_CRITICAL;
                        strncpy(out_threat->threat_name, "Stego.Payload.JPEG.AppendedPE", MAX_THREAT_NAME_LEN - 1);
                        strncpy(out_threat->threat_type, "Media.StegoAnalyzer", 63);
                        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "JPEG Steganography: %llu bytes of appended executable payload found past FF D9 end marker", (unsigned long long)appended_bytes);
                        return true;
                    }
                }
                break;
            }
        }
    }

    return false;
}
