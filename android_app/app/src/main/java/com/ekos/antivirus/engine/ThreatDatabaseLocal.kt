package com.ekos.antivirus.engine

object ThreatDatabaseLocal {

    // Known malicious Android package names (Adware, Spyware, Banking Trojans)
    private val KNOWN_MALICIOUS_PACKAGES = setOf(
        "com.android.system.service.fake",
        "com.security.update.patcher",
        "com.super.cleaner.booster.adware",
        "com.battery.saver.malware",
        "com.whatsapp.gold.update.fake",
        "org.telegram.plus.hacked",
        "com.bank.auth.token.stealer",
        "com.flashtorch.adware.miner"
    )

    // Suspicious permissions combinations (e.g. accessibility + overlay + sms = typical banking trojan)
    fun evaluatePermissionsRisk(permissions: List<String>): Pair<ThreatSeverity, String?> {
        val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSmsRead = permissions.contains("android.permission.READ_SMS") || permissions.contains("android.permission.RECEIVE_SMS")
        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasRecordAudio = permissions.contains("android.permission.RECORD_AUDIO")
        val hasCamera = permissions.contains("android.permission.CAMERA")

        if (hasAccessibility && hasOverlay && hasSmsRead) {
            return Pair(ThreatSeverity.MALICIOUS, "Bankacılık Truva Atı İzin Kombinasyonu (Erişilebilirlik + SMS + Ekran Kaplama)")
        }

        if (hasOverlay && hasSmsRead) {
            return Pair(ThreatSeverity.SUSPICIOUS, "Şüpheli SMS ve Ekran Kaplama İzinleri")
        }

        if (hasRecordAudio && hasCamera && hasOverlay) {
            return Pair(ThreatSeverity.SUSPICIOUS, "Casus Yazılım Şüphesi (Arka Plan Ses/Görüntü ve Ekran İzinleri)")
        }

        return Pair(ThreatSeverity.SAFE, null)
    }

    fun isKnownMaliciousPackage(packageName: String): Boolean {
        return KNOWN_MALICIOUS_PACKAGES.contains(packageName.lowercase())
    }
}
