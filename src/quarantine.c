#include "quarantine.h"
#include <direct.h>

bool quarantine_file(const char* file_path, const char* quarantine_dir, ThreatResult* threat_info) {
    if (!file_path || !quarantine_dir || !threat_info) return false;

    // Create quarantine directory if it doesn't exist
    _mkdir(quarantine_dir);

    // Extract filename from file_path
    const char* filename = strrchr(file_path, '\\');
    if (!filename) filename = strrchr(file_path, '/');
    if (!filename) filename = file_path;
    else filename++;

    char dest_path[MAX_PATH_LEN];
    snprintf(dest_path, sizeof(dest_path), "%s\\QUARANTINE_%u_%s.vir", quarantine_dir, (unsigned int)time(NULL), filename);

    // Move file to quarantine
    if (MoveFileA(file_path, dest_path)) {
        // Neutralize binary header with simple XOR byte mask (0x5A) so Windows cannot execute it
        FILE* fp = fopen(dest_path, "rb+");
        if (fp) {
            uint8_t buffer[64];
            size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
            if (bytes_read > 0) {
                for (size_t i = 0; i < bytes_read; i++) {
                    buffer[i] ^= 0x5A;
                }
                fseek(fp, 0, SEEK_SET);
                fwrite(buffer, 1, bytes_read, fp);
            }
            fclose(fp);
        }
        return true;
    }

    return false;
}
