package com.ekos.antivirus.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class AppScannerEngine(private val context: Context) {

    suspend fun performFullScan(
        onProgress: (current: Int, total: Int, currentApp: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            emptyList()
        }

        val total = packages.size
        val results = mutableListOf<ScannedAppItem>()

        for ((index, pkg) in packages.withIndex()) {
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Exception) {
                pkg.packageName
            }

            withContext(Dispatchers.Main) {
                onProgress(index + 1, total, appName)
            }

            val apkPath = pkg.applicationInfo?.sourceDir ?: ""
            val isSystem = (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM)) != 0
            val sha256 = calculateApkSha256(apkPath)
            val icon = try { pkg.applicationInfo?.loadIcon(pm) } catch (e: Exception) { null }

            val item = ScannedAppItem(
                appName = appName,
                packageName = pkg.packageName,
                versionName = pkg.versionName ?: "1.0",
                apkPath = apkPath,
                sha256 = sha256,
                isSystemApp = isSystem,
                icon = icon
            )

            // 1. Check local threat package name
            if (ThreatDatabaseLocal.isKnownMaliciousPackage(pkg.packageName)) {
                item.severity = ThreatSeverity.MALICIOUS
                item.threatName = "Trojan.Android.Blacklisted"
                item.riskDetails = "Bilinen kara listede yer alan zararlı paket adı."
            } 
            // 2. Check local permission heuristics
            else {
                val permissions = pkg.requestedPermissions?.toList() ?: emptyList()
                val (riskSeverity, riskExplanation) = ThreatDatabaseLocal.evaluatePermissionsRisk(permissions)
                if (riskSeverity != ThreatSeverity.SAFE && !isSystem) {
                    item.severity = riskSeverity
                    item.threatName = "Heuristic.Android.SuspiciousPerms"
                    item.riskDetails = riskExplanation
                }
            }

            // 3. Query Cloud Hash if non-system or suspicious
            if (item.severity == ThreatSeverity.SAFE && !isSystem && sha256.isNotBlank()) {
                val (cloudThreat, cloudName) = EkosApiClient.checkHash(sha256)
                if (cloudThreat) {
                    item.severity = ThreatSeverity.MALICIOUS
                    item.threatName = cloudName ?: "Trojan.Android.CloudDetected"
                    item.riskDetails = "EKOS 1.4M+ Bulut Tehdit Veritabanında zararlı olarak işaretlendi."
                }
            }

            results.add(item)
        }

        results
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
        } catch (e: Exception) {
            ""
        }
    }
}
