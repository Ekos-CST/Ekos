package com.ekos.antivirus.engine

import android.graphics.drawable.Drawable

enum class ThreatSeverity {
    SAFE,
    SUSPICIOUS,
    MALICIOUS
}

data class ScannedAppItem(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val apkPath: String,
    val sha256: String,
    val isSystemApp: Boolean,
    var severity: ThreatSeverity = ThreatSeverity.SAFE,
    var threatName: String? = null,
    var riskDetails: String? = null,
    val icon: Drawable? = null
)

data class UrlScanResult(
    val url: String,
    val isSafe: Boolean,
    val threatScore: Int,
    val categories: List<String>,
    val detectionEngine: String,
    val message: String
)

data class ClipboardAnalysisResult(
    val content: String,
    val isSuspicious: Boolean,
    val threatType: String?,
    val explanation: String?
)
