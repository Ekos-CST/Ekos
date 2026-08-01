#include "script_analyzer.h"
#include "cert_verifier.h"
#include "signature_db.h"

typedef struct {
    const char* pattern;
    int weight;
    const char* description;
} ScriptRule;

static ScriptRule g_script_rules[] = {
    { "-EncodedCommand", 40, "PowerShell Base64 Encoded Command Execution" },
    { "-enc ", 35, "PowerShell Short Encoded Command Flag" },
    { "-nop -w hidden", 35, "PowerShell Hidden Window Bypass" },
    { "Invoke-Expression", 25, "Dynamic Code Execution (Invoke-Expression)" },
    { "iex(", 25, "Short Dynamic Code Execution (iex)" },
    { "[System.Convert]::FromBase64String", 35, "PowerShell Base64 Decoder Stub" },
    { "certutil -urlcache", 45, "Certutil Abuse for Malware Download" },
    { "certutil -decode", 45, "Certutil Base64 Payload Decoding" },
    { "bitsadmin /transfer", 40, "Bitsadmin Abuse for Payload Transfer" },
    { "vssadmin delete shadows", 50, "Ransomware Shadow Copy Deletion Command" },
    { "wmic shadowcopy delete", 50, "WMI Ransomware Shadow Copy Destruction" },
    { "bcdedit /set {default} recoveryenabled No", 45, "Recovery Disabling Command" },
    { "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 30, "Registry Persistence Installation" },
    { "DownloadString(", 25, "Remote Script Downloader Stub" },
    { "DownloadFile(", 25, "Remote Payload Downloader Stub" },
    { "WScript.Shell", 20, "WScript Object Instantiation" },
    { "CreateObject(\"Shell.Application\")", 20, "COM Shell Application Execution" },
    { "Net.WebClient", 20, "PowerShell WebClient Usage" }
};

static size_t g_script_rule_count = sizeof(g_script_rules) / sizeof(g_script_rules[0]);

bool analyze_script_file(const char* file_path, const uint8_t* data, size_t size, ThreatResult* out_threat) {
    if (!data || size == 0 || !out_threat) return false;

    // 0. Whitelist Trust Check for Application Package Scripts
    if (file_path && is_ekos_licensed_file(file_path)) {
        return false; // Trusted software package script (VS Code, Playwright, Node, Chocolatey, etc.)
    }

    // 1. Convert script buffer to null-terminated string for analysis
    char* text_buf = (char*)malloc(size + 1);
    if (!text_buf) return false;

    memcpy(text_buf, data, size);
    text_buf[size] = '\0';

    int threat_score = 0;
    char indicators[MAX_DESCRIPTION_LEN] = "";

    // Case-insensitive check helper
    char* lower_buf = (char*)malloc(size + 1);
    if (lower_buf) {
        for (size_t i = 0; i < size; i++) {
            lower_buf[i] = (char)tolower((unsigned char)text_buf[i]);
        }
        lower_buf[size] = '\0';
    }

    for (size_t i = 0; i < g_script_rule_count; i++) {
        const ScriptRule* rule = &g_script_rules[i];
        
        char lower_pattern[128];
        size_t plen = strlen(rule->pattern);
        for (size_t p = 0; p < plen && p < 127; p++) {
            lower_pattern[p] = (char)tolower((unsigned char)rule->pattern[p]);
        }
        lower_pattern[plen] = '\0';

        if (lower_buf && strstr(lower_buf, lower_pattern) != NULL) {
            threat_score += rule->weight;
            strncat(indicators, "[", sizeof(indicators) - strlen(indicators) - 1);
            strncat(indicators, rule->description, sizeof(indicators) - strlen(indicators) - 1);
            strncat(indicators, "] ", sizeof(indicators) - strlen(indicators) - 1);
        }
    }

    free(text_buf);
    if (lower_buf) free(lower_buf);

    if (threat_score >= 60) {
        out_threat->is_threat = true;
        out_threat->severity = (threat_score >= 90) ? SEVERITY_CRITICAL : SEVERITY_HIGH;
        strncpy(out_threat->threat_name, "Script.Heuristic.MaliciousBehavior", MAX_THREAT_NAME_LEN - 1);
        strncpy(out_threat->threat_type, "Script.Analyzer", 63);
        snprintf(out_threat->description, MAX_DESCRIPTION_LEN, "Script Threat Score: %d/100. Indicators: %s", threat_score, indicators);
        snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "Script Metin Bloğu (Script Text Block)");
        snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Zararlı Komut Kalıpları: %s", indicators);
        return true;
    }

    return false;
}
