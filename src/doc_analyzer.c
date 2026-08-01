#include "doc_analyzer.h"

// Key keywords for PDF exploits
static const char* g_pdf_keywords[] = {
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/URI"
};
static size_t g_pdf_keyword_count = sizeof(g_pdf_keywords) / sizeof(g_pdf_keywords[0]);

bool analyze_document_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat) {
    if (!data || size < 8 || !out_threat) return false;

    const char* ext = get_file_extension(file_path);
    int threat_score = 0;
    char indicators[MAX_DESCRIPTION_LEN] = "";

    // 1. PDF Analysis (%PDF- header)
    if (_stricmp(ext, ".pdf") == 0 || (size >= 4 && memcmp(data, "%PDF", 4) == 0)) {
        for (size_t k = 0; k < g_pdf_keyword_count; k++) {
            const char* kw = g_pdf_keywords[k];
            size_t kw_len = strlen(kw);

            if (size < kw_len) continue;
            for (size_t i = 0; i <= size - kw_len; i++) {
                if (memcmp(data + i, kw, kw_len) == 0) {
                    if (strcmp(kw, "/JavaScript") == 0 || strcmp(kw, "/JS") == 0) {
                        threat_score += 20;
                        strncat(indicators, "[Embedded PDF JavaScript Stream] ", sizeof(indicators) - strlen(indicators) - 1);
                    } else if (strcmp(kw, "/OpenAction") == 0 || strcmp(kw, "/AA") == 0) {
                        threat_score += 20;
                        strncat(indicators, "[Auto-Execute OpenAction Trigger] ", sizeof(indicators) - strlen(indicators) - 1);
                    } else if (strcmp(kw, "/Launch") == 0) {
                        threat_score += 55;
                        strncat(indicators, "[PDF Binary Executable Launch Action] ", sizeof(indicators) - strlen(indicators) - 1);
                    } else if (strcmp(kw, "/EmbeddedFile") == 0) {
                        threat_score += 30;
                        strncat(indicators, "[PDF Embedded Binary File] ", sizeof(indicators) - strlen(indicators) - 1);
                    }
                    break;
                }
            }
        }

        if (threat_score >= 80) {
            out_threat->is_threat = true;
            out_threat->severity = SEVERITY_CRITICAL;
            strncpy(out_threat->threat_name, "Exploit.PDF.MaliciousStream", MAX_THREAT_NAME_LEN - 1);
            strncpy(out_threat->threat_type, "Document.PDFParser", 63);
            snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "PDF Exploit Score: %d/100. Indicators: %s", threat_score, indicators);
            snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "PDF Obje Akışı (PDF Object Stream)");
            snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Gizli Executable Launch / Exploit Akışı: %s", indicators);
            return true;
        }
    }

    return false;
}
