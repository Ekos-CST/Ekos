#include "cert_verifier.h"

bool verify_file_digital_signature(const wchar_t* w_file_path) {
    if (!w_file_path || wcslen(w_file_path) == 0) return false;

    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = w_file_path;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileData;
    WinTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;

    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    // Free memory created by state action
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return (lStatus == ERROR_SUCCESS);
}

bool is_certified_system_file(const char* file_path) {
    if (!file_path) return false;

    const char* ext = strrchr(file_path, '.');
    if (!ext) return false;

    // Digital signature verification applies to executable & driver formats
    if (_stricmp(ext, ".exe") != 0 && _stricmp(ext, ".dll") != 0 &&
        _stricmp(ext, ".sys") != 0 && _stricmp(ext, ".cat") != 0 &&
        _stricmp(ext, ".msi") != 0 && _stricmp(ext, ".scr") != 0) {
        return false;
    }

    wchar_t w_file_path[MAX_PATH_LEN];
    int res = MultiByteToWideChar(CP_UTF8, 0, file_path, -1, w_file_path, MAX_PATH_LEN);
    if (res == 0) {
        MultiByteToWideChar(CP_ACP, 0, file_path, -1, w_file_path, MAX_PATH_LEN);
    }

    return verify_file_digital_signature(w_file_path);
}

bool is_ekos_licensed_file(const char* file_path) {
    if (!file_path) return false;

    char lower_path[MAX_PATH_LEN];
    strncpy(lower_path, file_path, MAX_PATH_LEN - 1);
    lower_path[MAX_PATH_LEN - 1] = '\0';
    for (int i = 0; lower_path[i]; i++) {
        if (lower_path[i] >= 'A' && lower_path[i] <= 'Z') lower_path[i] += 32;
    }

    // 1. Ekos Licensed Engine & App Whitelist
    if (strstr(lower_path, "ekosantivirus.exe") ||
        strstr(lower_path, "\\quarantine\\") ||
        strstr(lower_path, "\\quarantine") ||
        strstr(lower_path, "electron.exe") ||
        strstr(lower_path, "node.exe") ||
        strstr(lower_path, "antivirus_engine.exe")) {
        return true;
    }

    // 2. Build, IDE & Developer Tools Whitelist
    if (strstr(lower_path, "\\build\\") || strstr(lower_path, "/build/") ||
        strstr(lower_path, "\\.git\\") || strstr(lower_path, "/.git/") ||
        strstr(lower_path, "\\node_modules\\") || strstr(lower_path, "/node_modules/") ||
        strstr(lower_path, "\\.vs\\") || strstr(lower_path, "\\.vscode\\") ||
        strstr(lower_path, "\\appdata\\local\\programs\\microsoft vs code") ||
        strstr(lower_path, "\\appdata\\local\\programs\\antigravity ide") ||
        strstr(lower_path, "\\appdata\\local\\programs\\python") ||
        strstr(lower_path, "\\appdata\\local\\ms-playwright") ||
        strstr(lower_path, "\\chocolatey\\") || strstr(lower_path, "\\vcpkg\\") ||
        strstr(lower_path, "\\program files\\kicad") ||
        strstr(lower_path, "\\program files\\solidworks")) {
        return true;
    }

    // 3. Non-Executable Developer Cache Extensions
    const char* ext = strrchr(lower_path, '.');
    if (ext) {
        if (strcmp(ext, ".obj") == 0 || strcmp(ext, ".o") == 0 || strcmp(ext, ".pdb") == 0 ||
            strcmp(ext, ".ilk") == 0 || strcmp(ext, ".idb") == 0 || strcmp(ext, ".ninja") == 0 ||
            strcmp(ext, ".cmake") == 0 || strcmp(ext, ".tlog") == 0 || strcmp(ext, ".recipe") == 0 ||
            strcmp(ext, ".ts") == 0 || strcmp(ext, ".map") == 0 || strcmp(ext, ".d.ts") == 0) {
            return true;
        }
    }

    return false;
}
