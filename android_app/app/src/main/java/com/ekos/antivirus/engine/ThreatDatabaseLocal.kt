package com.ekos.antivirus.engine

object ThreatDatabaseLocal {

    // Known trusted package prefixes (Whitelisted against false positive heuristic triggers)
    private val TRUSTED_PREFIXES = listOf(
        "com.google.",
        "com.android.",
        "com.whatsapp",
        "com.facebook.",
        "com.instagram.",
        "com.twitter.",
        "com.spotify.",
        "com.microsoft.",
        "com.realme.",
        "com.coloros.",
        "com.oplus.",
        "com.heytap.",
        "com.nearme.",
        "com.snapchat.",
        "org.telegram.",
        "com.discord",
        "com.turkcell.",
        "com.vodafone.",
        "com.turktelekom.",
        "com.akbank.",
        "com.garanti.",
        "com.ykb.",
        "com.isbank.",
        "com.ziraat.",
        "com.vakifbank.",
        "com.qnbfinansbank.",
        "com.enpara.",
        "com.trendyol.",
        "com.hepsiburada.",
        "com.amazon.",
        "com.netflix.",
        "com.valvesoftware.",
        "com.supercell."
    )

    // Known malicious Android malware package signatures
    private val KNOWN_MALICIOUS_PACKAGES = setOf(
        "com.android.system.service.fake",
        "com.security.update.patcher",
        "com.super.cleaner.booster.adware",
        "com.battery.saver.malware",
        "com.whatsapp.gold.update.fake",
        "org.telegram.plus.hacked",
        "com.bank.auth.token.stealer",
        "com.flashtorch.adware.miner",
        "com.spyware.tracker.hidden",
        "com.rat.android.dropper"
    )

    fun isTrustedPackage(packageName: String): Boolean {
        val lower = packageName.lowercase()
        return TRUSTED_PREFIXES.any { lower.startsWith(it) }
    }

    fun isKnownMaliciousPackage(packageName: String): Boolean {
        return KNOWN_MALICIOUS_PACKAGES.contains(packageName.lowercase())
    }

    // Precise heuristic: only triggers on non-trusted, non-system apps with extreme trojan patterns
    fun evaluatePermissionsRisk(packageName: String, permissions: List<String>): Pair<ThreatSeverity, String?> {
        if (isTrustedPackage(packageName)) {
            return Pair(ThreatSeverity.SAFE, null)
        }

        val hasOverlay = permissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSmsRead = permissions.contains("android.permission.READ_SMS") && permissions.contains("android.permission.RECEIVE_SMS")
        val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasBoot = permissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")

        // Only flag critical Banking Trojan / Remote Access combo
        if (hasAccessibility && hasOverlay && hasSmsRead && hasBoot) {
            return Pair(ThreatSeverity.MALICIOUS, "Kritik Truva Atı İzinleri (Erişilebilirlik + Ekran Kaplama + SMS Dinleme)")
        }

        return Pair(ThreatSeverity.SAFE, null)
    }
}
