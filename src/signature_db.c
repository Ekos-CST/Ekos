#include "signature_db.h"

// Sample Hash Signatures for testing and offline identification
static HashSignature g_hash_signatures[] = {
    {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR.Standard.Test.File",
        "Test.Virus",
        SEVERITY_HIGH,
        "Standard EICAR Anti-Virus Test File detected"
    },
    {
        "b2e9770dc67da331d99c8a53583de90ddc748ec83148cdfc9ac5527366781b4e",
        "EICAR.Standard.Test.File",
        "Test.Virus",
        SEVERITY_HIGH,
        "Standard EICAR Anti-Virus Test File detected"
    },
    {
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "Trojan.Win32.WannaCry.A",
        "PE.Ransomware",
        SEVERITY_CRITICAL,
        "WannaCry Ransomware binary hash match"
    }
};

static size_t g_hash_sig_count = sizeof(g_hash_signatures) / sizeof(g_hash_signatures[0]);

#define XOR_KEY 0xAA

// Cobalt Strike Shellcode Header Pattern (XOR Masked with 0xAA)
static const uint8_t g_cobalt_strike_masked[] = {
    0xFC ^ XOR_KEY, 0xE8 ^ XOR_KEY, 0x89 ^ XOR_KEY, 0x00 ^ XOR_KEY, 0x00 ^ XOR_KEY, 0x00 ^ XOR_KEY, 0x60 ^ XOR_KEY,
    0x89 ^ XOR_KEY, 0xE5 ^ XOR_KEY, 0x31 ^ XOR_KEY, 0xD2 ^ XOR_KEY, 0x64 ^ XOR_KEY, 0x8B ^ XOR_KEY, 0x52 ^ XOR_KEY, 0x30 ^ XOR_KEY
};

// Mimikatz Signature String Pattern (XOR Masked with 0xAA)
static const uint8_t g_mimikatz_masked[] = {
    's' ^ XOR_KEY, 'e' ^ XOR_KEY, 'k' ^ XOR_KEY, 'u' ^ XOR_KEY, 'r' ^ XOR_KEY, 'l' ^ XOR_KEY, 's' ^ XOR_KEY, 'a' ^ XOR_KEY,
    ':' ^ XOR_KEY, ':' ^ XOR_KEY, 'l' ^ XOR_KEY, 'o' ^ XOR_KEY, 'g' ^ XOR_KEY, 'o' ^ XOR_KEY, 'n' ^ XOR_KEY, 'p' ^ XOR_KEY,
    'a' ^ XOR_KEY, 's' ^ XOR_KEY, 's' ^ XOR_KEY, 'w' ^ XOR_KEY, 'o' ^ XOR_KEY, 'r' ^ XOR_KEY, 'd' ^ XOR_KEY, 's' ^ XOR_KEY
};

// Encrypted Ransomware Note Pattern (XOR Masked with 0xAA)
static const uint8_t g_ransom_note_masked[] = {
    'Y' ^ XOR_KEY, 'O' ^ XOR_KEY, 'U' ^ XOR_KEY, 'R' ^ XOR_KEY, ' ' ^ XOR_KEY, 'F' ^ XOR_KEY, 'I' ^ XOR_KEY, 'L' ^ XOR_KEY,
    'E' ^ XOR_KEY, 'S' ^ XOR_KEY, ' ' ^ XOR_KEY, 'A' ^ XOR_KEY, 'R' ^ XOR_KEY, 'E' ^ XOR_KEY, ' ' ^ XOR_KEY, 'E' ^ XOR_KEY,
    'N' ^ XOR_KEY, 'C' ^ XOR_KEY, 'R' ^ XOR_KEY, 'Y' ^ XOR_KEY, 'P' ^ XOR_KEY, 'T' ^ XOR_KEY, 'E' ^ XOR_KEY, 'D' ^ XOR_KEY, '!' ^ XOR_KEY
};

// EICAR Standard Test String
static const uint8_t g_eicar_test_pattern[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

static uint8_t g_cobalt_strike_pattern[15];
static uint8_t g_mimikatz_pattern[24];
static uint8_t g_ransom_note_pattern[25];
static bool g_signatures_initialized = false;

static PatternSignature g_pattern_signatures[4];

void init_signature_database(void) {
    if (g_signatures_initialized) return;

    for (size_t i = 0; i < sizeof(g_cobalt_strike_masked); i++) {
        g_cobalt_strike_pattern[i] = g_cobalt_strike_masked[i] ^ XOR_KEY;
    }
    for (size_t i = 0; i < sizeof(g_mimikatz_masked); i++) {
        g_mimikatz_pattern[i] = g_mimikatz_masked[i] ^ XOR_KEY;
    }
    for (size_t i = 0; i < sizeof(g_ransom_note_masked); i++) {
        g_ransom_note_pattern[i] = g_ransom_note_masked[i] ^ XOR_KEY;
    }

    g_pattern_signatures[0] = (PatternSignature){
        "Trojan.Win32.CobaltStrike.Beacon",
        "PE.Shellcode",
        SEVERITY_CRITICAL,
        g_cobalt_strike_pattern,
        15,
        "Cobalt Strike Reflective DLL/Shellcode stub pattern detected"
    };

    g_pattern_signatures[1] = (PatternSignature){
        "HackTool.Win32.Mimikatz.Pattern",
        "PE.CredentialStealer",
        SEVERITY_CRITICAL,
        g_mimikatz_pattern,
        24,
        "Mimikatz LSASS password harvesting string pattern detected"
    };

    g_pattern_signatures[2] = (PatternSignature){
        "Trojan.Generic.RansomwareNote",
        "Ransomware.Note",
        SEVERITY_HIGH,
        g_ransom_note_pattern,
        25,
        "Ransomware extortion message pattern detected"
    };

    g_pattern_signatures[3] = (PatternSignature){
        "EICAR.Standard.Test.String",
        "Test.Virus",
        SEVERITY_HIGH,
        g_eicar_test_pattern,
        sizeof(g_eicar_test_pattern) - 1,
        "Standard EICAR Anti-Virus String Pattern match detected"
    };

    g_signatures_initialized = true;
}

bool check_hash_signature(const char* hash_hex, ThreatResult* out_threat) {
    if (!hash_hex || !out_threat) return false;

    init_signature_database();

    for (size_t i = 0; i < g_hash_sig_count; i++) {
        if (_stricmp(hash_hex, g_hash_signatures[i].sha256_hash) == 0) {
            out_threat->is_threat = true;
            out_threat->severity = g_hash_signatures[i].severity;
            strncpy(out_threat->threat_name, g_hash_signatures[i].threat_name, MAX_THREAT_NAME_LEN - 1);
            strncpy(out_threat->threat_type, g_hash_signatures[i].threat_type, 63);
            strncpy(out_threat->description, g_hash_signatures[i].description, MAX_DESCRIPTION_LEN - 1);
            snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "SHA-256 Veri Tabanı Eşleşmesi");
            snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Exact SHA-256 Hash Match: %s", hash_hex);
            return true;
        }
    }
    return false;
}

bool check_byte_pattern_signatures(const uint8_t* buffer, size_t size, ThreatResult* out_threat) {
    if (!buffer || size == 0 || !out_threat) return false;

    init_signature_database();

    for (size_t k = 0; k < 4; k++) {
        const PatternSignature* sig = &g_pattern_signatures[k];
        if (size < sig->pattern_len) continue;

        for (size_t i = 0; i <= size - sig->pattern_len; i++) {
            if (memcmp(buffer + i, sig->pattern_bytes, sig->pattern_len) == 0) {
                out_threat->is_threat = true;
                out_threat->severity = sig->severity;
                strncpy(out_threat->threat_name, sig->threat_name, MAX_THREAT_NAME_LEN - 1);
                strncpy(out_threat->threat_type, sig->threat_type, 63);
                strncpy(out_threat->description, sig->description, MAX_DESCRIPTION_LEN - 1);
                snprintf(out_threat->offset_location, sizeof(out_threat->offset_location), "Offset: 0x%08ZX", i);
                snprintf(out_threat->exact_detail, sizeof(out_threat->exact_detail), "Desen Eşleşti: %s (Offset: 0x%08ZX)", sig->threat_name, i);
                return true;
            }
        }
    }
    return false;
}
