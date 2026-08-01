#include "common.h"
#include "scanner.h"
#include "signature_db.h"
#include "reporter.h"
#include "quarantine.h"

static void print_usage(const char* exe_name) {
    printf("Kullanım: %s [Seçenekler]\n", exe_name);
    printf("Seçenekler:\n");
    printf("  --quick             Hızlı Tarama modunu çalıştırır (Sertifikalı sistem dosyalarını atlar)\n");
    printf("  --full              Kapsamlı Tarama modunu çalıştırır (Tüm dosyaları derinlemesine analiz eder)\n");
    printf("  --target <path>     Taranacak özel hedef dizini veya dosya yolunu belirtir\n");
    printf("  --quarantine        Tespit edilen tehditleri otomatik karantinaya alır\n");
    printf("  --report <path>     JSON rapor çıktısı oluşturur (Varsayılan: scan_report.json)\n");
    printf("  --help              Bu yardım menüsünü görüntüler\n");
}

int main(int argc, char* argv[]) {
    // Enable UTF-8 console output
    SetConsoleOutputCP(CP_UTF8);

    init_signature_database();

    ScanOptions options;
    memset(&options, 0, sizeof(options));
    options.mode = SCAN_MODE_QUICK;
    options.enable_quarantine = false;
    options.verbose = false;
    strcpy(options.target_path, ".");
    strcpy(options.quarantine_dir, ".\\quarantine");
    strcpy(options.report_path, "scan_report.json");

    bool command_line_mode = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quick") == 0) {
            options.mode = SCAN_MODE_QUICK;
            command_line_mode = true;
        } else if (strcmp(argv[i], "--full") == 0) {
            options.mode = SCAN_MODE_FULL;
            command_line_mode = true;
        } else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            strncpy(options.target_path, argv[++i], MAX_PATH_LEN - 1);
            command_line_mode = true;
        } else if (strcmp(argv[i], "--quarantine") == 0) {
            options.enable_quarantine = true;
            command_line_mode = true;
        } else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
            strncpy(options.report_path, argv[++i], MAX_PATH_LEN - 1);
            command_line_mode = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            strncpy(options.target_path, argv[i], MAX_PATH_LEN - 1);
            command_line_mode = true;
        }
    }

    if (options.mode == SCAN_MODE_FULL && (strcmp(options.target_path, ".") == 0 || options.target_path[0] == '\0')) {
        strcpy(options.target_path, "ALL_DRIVES");
    }

    print_banner();

    // If no flags passed, present interactive menu
    if (!command_line_mode) {
        printf("\nLütfen bir tarama modu seçiniz:\n");
        printf("  [1] Hızlı Tarama (Quick Scan) - Sertifikalı sistem dosyalarını atlar\n");
        printf("  [2] Kapsamlı Tarama (Full Scan) - Sistem dosyaları ve tüm programları tarar\n");
        printf("  [3] Özel Dizin Taraması (Custom Directory Scan)\n");
        printf("  [4] Çıkış (Exit)\n");
        printf("\nSeçiminiz (1-4): ");

        int choice = 0;
        if (scanf("%d", &choice) != 1) {
            choice = 1;
        }
        getchar(); // consume newline

        if (choice == 1) {
            options.mode = SCAN_MODE_QUICK;
            strncpy(options.target_path, "[RAM Bellek Süreçleri & Başlangıç Kayıtları]", MAX_PATH_LEN - 1);
        } else if (choice == 2) {
            options.mode = SCAN_MODE_FULL;
            strncpy(options.target_path, "C:\\", MAX_PATH_LEN - 1);
        } else if (choice == 3) {
            printf("Taranacak dizin yolunu giriniz (Örn: C:\\ veya C:\\Users): ");
            if (fgets(options.target_path, MAX_PATH_LEN, stdin)) {
                size_t len = strlen(options.target_path);
                if (len > 0 && options.target_path[len - 1] == '\n') {
                    options.target_path[len - 1] = '\0';
                }
            }
            printf("Tarama modunu seçiniz (1: Hızlı Tarama, 2: Kapsamlı Tarama): ");
            int sub_choice = 1;
            scanf("%d", &sub_choice);
            options.mode = (sub_choice == 2) ? SCAN_MODE_FULL : SCAN_MODE_QUICK;
        } else {
            printf("Çıkış yapılıyor...\n");
            return 0;
        }
    }

    printf("\nTarama başlatılıyor...\n");
    printf("  Target Path: %s\n", options.target_path);
    printf("  Scan Mode  : %s\n", (options.mode == SCAN_MODE_QUICK) ? "Quick Scan" : "Full Scan");
    printf("---------------------------------------------------------------------\n\n");

    ScanStats stats;
    memset(&stats, 0, sizeof(stats));
    stats.start_time = get_current_time_seconds();

    ThreatResult* threats = NULL;
    size_t threat_count = 0;

    // Check if target path is file or directory
    DWORD attrib = GetFileAttributesA(options.target_path);
    if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
        // Single file scan
        ThreatResult threat;
        if (scan_single_file(options.target_path, &options, &threat, &stats)) {
            print_threat_found(&threat);
            threats = (ThreatResult*)malloc(sizeof(ThreatResult));
            threats[0] = threat;
            threat_count = 1;

            if (options.enable_quarantine) {
                quarantine_file(options.target_path, options.quarantine_dir, &threat);
            }
        }
    } else {
        // Directory scan
        scan_directory(options.target_path, &options, &threats, &threat_count, &stats);
    }

    stats.end_time = get_current_time_seconds();

    print_scan_summary(&stats, &options);

    // Export Reports
    if (export_json_report(options.report_path, &stats, threats, threat_count, &options)) {
        printf(" [+] JSON Tarama Raporu Kaydedildi : %s\n", options.report_path);
    }

    if (export_txt_report("scan_report.txt", &stats, threats, threat_count, &options)) {
        printf(" [+] TXT Tarama Raporu Kaydedildi  : scan_report.txt\n");
    }

    if (threats) {
        free(threats);
    }

    return 0;
}
