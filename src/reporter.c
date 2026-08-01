#include "reporter.h"

static void set_color(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

static void reset_color(void) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void print_banner(void) {
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=====================================================================\n");
    printf("                     EKOS ANTİVİRÜS MOTORU                          \n");
    printf("=====================================================================\n");
    reset_color();
}

static double s_monitored_etr_sec = 0.0;
static double s_last_time_stamp = 0.0;
static uint64_t s_last_scanned_count = 0;

void print_scan_progress(const ScanStats* stats, const char* current_file) {
    if (!stats || !current_file) return;

    double now = get_current_time_seconds();

    // Reset static state on new scan initialization
    if (stats->total_files_scanned <= 1 || s_last_scanned_count > stats->total_files_scanned) {
        s_monitored_etr_sec = 0.0;
        s_last_time_stamp = now;
        s_last_scanned_count = stats->total_files_scanned;
    }

    double elapsed = now - stats->start_time;
    if (elapsed < 0.1) elapsed = 0.1;

    double dt = (s_last_time_stamp > 0.0) ? (now - s_last_time_stamp) : 0.05;
    if (dt < 0.0 || dt > 2.0) dt = 0.05;
    s_last_time_stamp = now;
    s_last_scanned_count = stats->total_files_scanned;

    // Ensure total_files_to_scan is at least as large as total_files_scanned + 1000
    uint64_t target_files = stats->total_files_to_scan;
    if (target_files < stats->total_files_scanned + 1000) {
        target_files = stats->total_files_scanned + 1000;
        ((ScanStats*)stats)->total_files_to_scan = target_files;
    }

    double percent_done = (double)stats->total_files_scanned / (double)target_files;
    if (percent_done > 0.999) percent_done = 0.999;
    if (percent_done < 0.001) percent_done = 0.001;

    // Proportional progress ETR:
    // elapsed / percent_done gives total estimated scan duration in seconds.
    // total_est_duration - elapsed gives remaining seconds!
    double total_est_duration = elapsed / percent_done;
    double raw_sec = total_est_duration - elapsed;
    if (raw_sec < 0.0) raw_sec = 0.0;

    // Initialize or decay
    if (s_monitored_etr_sec <= 0.0) {
        s_monitored_etr_sec = raw_sec;
    } else {
        // Tick down naturally by elapsed dt
        s_monitored_etr_sec -= dt;

        // Smooth EMA adjustment if raw_sec is valid and lower (never jump UP!)
        if (raw_sec < s_monitored_etr_sec) {
            s_monitored_etr_sec = (0.05 * raw_sec) + (0.95 * s_monitored_etr_sec);
        }
    }

    if (s_monitored_etr_sec < 0.0) s_monitored_etr_sec = 0.0;
    if (s_monitored_etr_sec > 86400.0) s_monitored_etr_sec = 86400.0;
    uint32_t remaining_sec = (uint32_t)s_monitored_etr_sec;

    uint32_t hours = remaining_sec / 3600;
    uint32_t minutes = (remaining_sec % 3600) / 60;
    uint32_t seconds = remaining_sec % 60;

    set_color(FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\r[TARANIYOR] Path: %s | Dosyalar: %llu | Sertifikalı Atlanan: %llu | Tehdit: %llu | Tahmini Kalan: %02u:%02u:%02u\n",
           current_file,
           (unsigned long long)stats->total_files_scanned,
           (unsigned long long)stats->skipped_certified_files,
           (unsigned long long)stats->threats_detected,
           hours, minutes, seconds);
    reset_color();
    fflush(stdout);
}

void print_threat_found(const ThreatResult* threat) {
    if (!threat) return;

    printf("\n");
    set_color(BACKGROUND_RED | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf(" [TEHDİT TESPİT EDİLDİ] ");
    reset_color();

    set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf(" %s (%s)\n", threat->threat_name, threat->threat_type);
    reset_color();

    printf("  Dosya Konumu       : %s\n", threat->file_path);
    printf("  Tespit Edilen Yer  : %s\n", threat->offset_location[0] ? threat->offset_location : "Dosya Kod Bloğu");
    printf("  Zararlı Detayı     : %s\n", threat->exact_detail[0] ? threat->exact_detail : threat->description);
    printf("  Tehdit Seviyesi    : %s\n", severity_to_string(threat->severity));
    printf("  SHA-256            : %s\n", threat->file_hash_sha256);
    printf("  Açıklama           : %s\n", threat->description);
    printf("---------------------------------------------------------------------\n");
}

void print_scan_summary(const ScanStats* stats, const ScanOptions* options) {
    if (!stats || !options) return;

    double elapsed = stats->end_time - stats->start_time;

    printf("\n=====================================================================\n");
    set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("                EKOS ANTİVİRÜS MOTORU - TARAMA ÖZETİ                \n");
    reset_color();
    printf("=====================================================================\n");
    printf("  Tarama Modu         : %s\n", (options->mode == SCAN_MODE_QUICK) ? "HIZLI TARAMA (RAM & Başlangıç Kayıtları)" : "KAPSAMLI TARAMA (Tüm Sürücüler & Kısayollar)");
    printf("  Hedef Dizin         : %s\n", options->target_path);
    printf("  Taranan Dosya       : %llu\n", (unsigned long long)stats->total_files_scanned);
    printf("  Atlanan Sertifikalı : %llu\n", (unsigned long long)stats->skipped_certified_files);
    printf("  Tespit Edilen Tehdit: %llu\n", (unsigned long long)stats->threats_detected);
    printf("  Toplam Süre         : %.2f saniye\n", elapsed);
    printf("=====================================================================\n\n");
}

bool export_json_report(const char* report_path, const ScanStats* stats, const ThreatResult* threats, size_t threat_count, const ScanOptions* options) {
    if (!report_path || !stats || !options) return false;

    FILE* fp = fopen(report_path, "w");
    if (!fp) return false;

    double elapsed = stats->end_time - stats->start_time;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"scan_info\": {\n");
    fprintf(fp, "    \"mode\": \"%s\",\n", (options->mode == SCAN_MODE_QUICK) ? "Quick Scan" : "Full Scan");
    fprintf(fp, "    \"target_path\": \"%s\",\n", options->target_path);
    fprintf(fp, "    \"total_files_scanned\": %llu,\n", (unsigned long long)stats->total_files_scanned);
    fprintf(fp, "    \"skipped_certified_files\": %llu,\n", (unsigned long long)stats->skipped_certified_files);
    fprintf(fp, "    \"threats_detected\": %llu,\n", (unsigned long long)stats->threats_detected);
    fprintf(fp, "    \"total_bytes_scanned\": %llu,\n", (unsigned long long)stats->total_bytes_scanned);
    fprintf(fp, "    \"duration_seconds\": %.2f\n", elapsed);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"threats\": [\n");
    for (size_t i = 0; i < threat_count; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"threat_name\": \"%s\",\n", threats[i].threat_name);
        fprintf(fp, "      \"threat_type\": \"%s\",\n", threats[i].threat_type);
        fprintf(fp, "      \"severity\": \"%s\",\n", severity_to_string(threats[i].severity));
        fprintf(fp, "      \"file_path\": \"%s\",\n", threats[i].file_path);
        fprintf(fp, "      \"offset_location\": \"%s\",\n", threats[i].offset_location);
        fprintf(fp, "      \"exact_detail\": \"%s\",\n", threats[i].exact_detail);
        fprintf(fp, "      \"sha256\": \"%s\",\n", threats[i].file_hash_sha256);
        fprintf(fp, "      \"entropy\": %.4f,\n", threats[i].entropy);
        fprintf(fp, "      \"description\": \"%s\"\n", threats[i].description);
        fprintf(fp, "    }%s\n", (i == threat_count - 1) ? "" : ",");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return true;
}

bool export_txt_report(const char* report_path, const ScanStats* stats, const ThreatResult* threats, size_t threat_count, const ScanOptions* options) {
    if (!report_path || !stats || !options) return false;

    FILE* fp = fopen(report_path, "w");
    if (!fp) return false;

    fprintf(fp, "=====================================================================\n");
    fprintf(fp, "                 EKOS ANTIVIRUS SCAN REPORT                          \n");
    fprintf(fp, "=====================================================================\n");
    fprintf(fp, "Scan Mode           : %s\n", (options->mode == SCAN_MODE_QUICK) ? "Quick Scan" : "Full Scan");
    fprintf(fp, "Target Path         : %s\n", options->target_path);
    fprintf(fp, "Total Files Scanned : %llu\n", (unsigned long long)stats->total_files_scanned);
    fprintf(fp, "Skipped Cert Files  : %llu\n", (unsigned long long)stats->skipped_certified_files);
    fprintf(fp, "Threats Detected    : %llu\n", (unsigned long long)stats->threats_detected);
    fprintf(fp, "Scan Duration       : %.2f seconds\n", stats->end_time - stats->start_time);
    fprintf(fp, "=====================================================================\n\n");

    fprintf(fp, "DETECTED THREATS LIST:\n");
    for (size_t i = 0; i < threat_count; i++) {
        fprintf(fp, "[%llu] Threat Name: %s (%s)\n", (unsigned long long)(i + 1), threats[i].threat_name, threats[i].threat_type);
        fprintf(fp, "     File Path       : %s\n", threats[i].file_path);
        fprintf(fp, "     Offset Location : %s\n", threats[i].offset_location);
        fprintf(fp, "     Exact Detail    : %s\n", threats[i].exact_detail);
        fprintf(fp, "     Severity        : %s\n", severity_to_string(threats[i].severity));
        fprintf(fp, "     SHA256          : %s\n", threats[i].file_hash_sha256);
        fprintf(fp, "     Description     : %s\n\n", threats[i].description);
    }

    fclose(fp);
    return true;
}
