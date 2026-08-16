package com.ekos.antivirus.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class AppScannerEngine(private val context: Context) {

    // 1. Quick Scan: Installed Applications
    suspend fun performQuickScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            try {
                pm.getInstalledPackages(0)
            } catch (e2: Exception) {
                emptyList()
            }
        }

        val total = if (packages.isNotEmpty()) packages.size else 1
        val results = mutableListOf<ScannedAppItem>()

        for ((index, pkg) in packages.withIndex()) {
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Throwable) {
                pkg.packageName ?: "Bilinmeyen Paket"
            }

            withContext(Dispatchers.Main) {
                onProgress(index + 1, total, appName)
            }

            val apkPath = try { pkg.applicationInfo?.sourceDir ?: "" } catch (e: Throwable) { "" }
            val isSystem = try {
                (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM)) != 0
            } catch (e: Throwable) {
                false
            }
            val sha256 = if (apkPath.isNotBlank()) calculateApkSha256(apkPath) else ""
            val icon = try { pkg.applicationInfo?.loadIcon(pm) } catch (e: Throwable) { null }

            val item = ScannedAppItem(
                appName = appName,
                packageName = pkg.packageName ?: "",
                versionName = pkg.versionName ?: "1.0",
                apkPath = apkPath,
                sha256 = sha256,
                isSystemApp = isSystem,
                icon = icon
            )

            // Heuristic & Local Signature Check
            if (pkg.packageName != null && ThreatDatabaseLocal.isKnownMaliciousPackage(pkg.packageName)) {
                item.severity = ThreatSeverity.MALICIOUS
                item.threatName = "Trojan.Android.Blacklisted"
                item.riskDetails = "Bilinen kara listede yer alan zararlı paket adı."
            } else {
                val permissions = try { pkg.requestedPermissions?.toList() ?: emptyList() } catch (e: Throwable) { emptyList() }
                val (riskSeverity, riskExplanation) = ThreatDatabaseLocal.evaluatePermissionsRisk(permissions)
                if (riskSeverity != ThreatSeverity.SAFE && !isSystem) {
                    item.severity = riskSeverity
                    item.threatName = "Heuristic.Android.SuspiciousPerms"
                    item.riskDetails = riskExplanation
                }
            }

            // Cloud Hash Query for non-system apps
            if (item.severity == ThreatSeverity.SAFE && !isSystem && sha256.isNotBlank()) {
                try {
                    val (cloudThreat, cloudName) = EkosApiClient.checkHash(sha256)
                    if (cloudThreat) {
                        item.severity = ThreatSeverity.MALICIOUS
                        item.threatName = cloudName ?: "Trojan.Android.CloudDetected"
                        item.riskDetails = "EKOS 1.4M+ Bulut Tehdit Veritabanında zararlı olarak işaretlendi."
                    }
                } catch (e: Throwable) {}
            }

            results.add(item)
        }

        results
    }

    // 2. Comprehensive Deep Scan: Apps + Storage & Downloads Payloads
    suspend fun performDeepScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val appResults = performQuickScan(onProgress).toMutableList()

        // Scan Download and Storage Directories
        val candidateFiles = mutableListOf<File>()
        val dirsToScan = listOfNotNull(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            context.getExternalFilesDir(null)
        )

        for (dir in dirsToScan) {
            if (dir.exists() && dir.canRead()) {
                collectSuspiciousFiles(dir, candidateFiles)
            }
        }

        val totalFiles = candidateFiles.size
        for ((idx, file) in candidateFiles.withIndex()) {
            withContext(Dispatchers.Main) {
                onProgress(idx + 1, totalFiles, file.name)
            }

            val sha256 = calculateApkSha256(file.absolutePath)
            val ext = file.extension.lowercase()
            val isScriptOrApk = ext in listOf("apk", "dex", "sh", "exe", "js", "bat", "elf")

            val fileItem = ScannedAppItem(
                appName = file.name,
                packageName = file.absolutePath,
                versionName = "${file.length() / 1024} KB",
                apkPath = file.absolutePath,
                sha256 = sha256,
                isSystemApp = false,
                icon = null
            )

            if (isScriptOrApk && (file.name.contains("mod", ignoreCase = true) || file.name.contains("hack", ignoreCase = true) || file.name.contains("crack", ignoreCase = true))) {
                fileItem.severity = ThreatSeverity.SUSPICIOUS
                fileItem.threatName = "Heuristic.SuspiciousDownload"
                fileItem.riskDetails = "Şüpheli dosya adı ve potansiyel zararlı yük."
            }

            if (sha256.isNotBlank()) {
                try {
                    val (cloudThreat, cloudName) = EkosApiClient.checkHash(sha256)
                    if (cloudThreat) {
                        fileItem.severity = ThreatSeverity.MALICIOUS
                        fileItem.threatName = cloudName ?: "Trojan.Android.Payload"
                        fileItem.riskDetails = "EKOS 1.4M+ Bulut Tehdit Veritabanında zararlı dosya olarak tespit edildi."
                    }
                } catch (e: Throwable) {}
            }

            appResults.add(fileItem)
        }

        appResults
    }

    private fun collectSuspiciousFiles(dir: File, list: MutableList<File>, maxFiles: Int = 100) {
        if (list.size >= maxFiles) return
        val files = dir.listFiles() ?: return
        for (f in files) {
            if (list.size >= maxFiles) break
            if (f.isDirectory && !f.name.startsWith(".")) {
                collectSuspiciousFiles(f, list, maxFiles)
            } else if (f.isFile) {
                val ext = f.extension.lowercase()
                if (ext in listOf("apk", "dex", "sh", "exe", "js", "bat", "elf", "zip")) {
                    list.add(f)
                }
            }
        }
    }

    private fun calculateApkSha256(filePath: String): String {
        if (filePath.isBlank()) return ""
        val file = File(filePath)
        if (!file.exists() || !file.canRead()) return ""

        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { fis ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Throwable) {
            ""
        }
    }
}
