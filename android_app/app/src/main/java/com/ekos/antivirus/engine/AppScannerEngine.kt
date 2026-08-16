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

    // 1. HIZLI SİSTEM TARAMASI: Yalnızca kullanıcının sonradan yüklediği 3. taraf uygulamaları ve kritik servisleri tarar.
    suspend fun performQuickScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val allPackages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Throwable) {
            try { pm.getInstalledPackages(0) } catch (e2: Throwable) { emptyList() }
        }

        // Hızlı tarama: Sadece kullanıcı uygulamaları (System app olmayanlar)
        val userPackages = allPackages.filter { pkg ->
            val isSystem = try {
                (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM)) != 0
            } catch (e: Throwable) { false }
            !isSystem
        }.ifEmpty { allPackages.take(20) }

        val total = userPackages.size
        val results = mutableListOf<ScannedAppItem>()

        for ((index, pkg) in userPackages.withIndex()) {
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Throwable) {
                pkg.packageName ?: "Uygulama"
            }

            withContext(Dispatchers.Main) {
                onProgress(index + 1, total, appName)
            }

            val apkPath = try { pkg.applicationInfo?.sourceDir ?: "" } catch (e: Throwable) { "" }
            val sha256 = if (apkPath.isNotBlank()) calculateApkSha256(apkPath) else ""
            val icon = try { pkg.applicationInfo?.loadIcon(pm) } catch (e: Throwable) { null }

            val item = ScannedAppItem(
                appName = appName,
                packageName = pkg.packageName ?: "",
                versionName = pkg.versionName ?: "1.0",
                apkPath = apkPath,
                sha256 = sha256,
                isSystemApp = false,
                icon = icon
            )

            // Güvenlik Denetimi
            val pkgName = pkg.packageName ?: ""
            if (ThreatDatabaseLocal.isKnownMaliciousPackage(pkgName)) {
                item.severity = ThreatSeverity.MALICIOUS
                item.threatName = "Trojan.Android.Blacklisted"
                item.riskDetails = "Bilinen kara listedeki zararlı paket imzası."
            } else if (!ThreatDatabaseLocal.isTrustedPackage(pkgName)) {
                val permissions = try { pkg.requestedPermissions?.toList() ?: emptyList() } catch (e: Throwable) { emptyList() }
                val (riskSeverity, riskExplanation) = ThreatDatabaseLocal.evaluatePermissionsRisk(pkgName, permissions)
                if (riskSeverity != ThreatSeverity.SAFE) {
                    item.severity = riskSeverity
                    item.threatName = "Heuristic.Android.Trojan"
                    item.riskDetails = riskExplanation
                }
            }

            results.add(item)
        }

        results
    }

    // 2. KAPSAMLI DERİN TARAMA: Tüm uygulamalar (Kullanıcı + Sistem) + Dahili Depolama (Download, Belgeler, WhatsApp vb.) dizinlerindeki APK/Binary dosyalarını tarar.
    suspend fun performDeepScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val allPackages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Throwable) {
            try { pm.getInstalledPackages(0) } catch (e2: Throwable) { emptyList() }
        }

        // Depolamadaki dosyaları topla
        val candidateFiles = mutableListOf<File>()
        val dirsToScan = listOfNotNull(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            File(Environment.getExternalStorageDirectory(), "Android/media"),
            context.getExternalFilesDir(null)
        )

        for (dir in dirsToScan) {
            if (dir.exists() && dir.canRead()) {
                collectStoragePayloads(dir, candidateFiles)
            }
        }

        val totalWork = allPackages.size + candidateFiles.size
        var completed = 0
        val results = mutableListOf<ScannedAppItem>()

        // Adım 1: Tüm Yüklü Paketlerin Taranması (Sistem + Kullanıcı)
        for (pkg in allPackages) {
            completed++
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Throwable) {
                pkg.packageName ?: "Paket"
            }

            withContext(Dispatchers.Main) {
                onProgress(completed, totalWork, appName)
            }

            val apkPath = try { pkg.applicationInfo?.sourceDir ?: "" } catch (e: Throwable) { "" }
            val isSystem = try {
                (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM)) != 0
            } catch (e: Throwable) { false }
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

            val pkgName = pkg.packageName ?: ""
            if (ThreatDatabaseLocal.isKnownMaliciousPackage(pkgName)) {
                item.severity = ThreatSeverity.MALICIOUS
                item.threatName = "Trojan.Android.Blacklisted"
                item.riskDetails = "Bilinen kara listedeki zararlı paket adı."
            } else if (!isSystem && !ThreatDatabaseLocal.isTrustedPackage(pkgName)) {
                val permissions = try { pkg.requestedPermissions?.toList() ?: emptyList() } catch (e: Throwable) { emptyList() }
                val (riskSeverity, riskExplanation) = ThreatDatabaseLocal.evaluatePermissionsRisk(pkgName, permissions)
                if (riskSeverity != ThreatSeverity.SAFE) {
                    item.severity = riskSeverity
                    item.threatName = "Heuristic.Android.Trojan"
                    item.riskDetails = riskExplanation
                }
            }

            results.add(item)
        }

        // Adım 2: Depolamadaki Dosyaların Taranması
        for (file in candidateFiles) {
            completed++
            withContext(Dispatchers.Main) {
                onProgress(completed, totalWork, file.name)
            }

            val sha256 = calculateApkSha256(file.absolutePath)
            val ext = file.extension.lowercase()
            val isExecutable = ext in listOf("apk", "dex", "sh", "exe", "js", "bat", "elf", "jar")

            val fileItem = ScannedAppItem(
                appName = file.name,
                packageName = file.absolutePath,
                versionName = "${file.length() / 1024} KB",
                apkPath = file.absolutePath,
                sha256 = sha256,
                isSystemApp = false,
                icon = null
            )

            if (isExecutable && (file.name.contains("rat", ignoreCase = true) || file.name.contains("trojan", ignoreCase = true) || file.name.contains("stealer", ignoreCase = true))) {
                fileItem.severity = ThreatSeverity.MALICIOUS
                fileItem.threatName = "Trojan.Android.Payload"
                fileItem.riskDetails = "Şüpheli yürütülebilir ikili dosya deseni."
            } else if (isExecutable && (file.name.contains("mod", ignoreCase = true) || file.name.contains("hack", ignoreCase = true))) {
                fileItem.severity = ThreatSeverity.SUSPICIOUS
                fileItem.threatName = "Riskware.ModifiedApp"
                fileItem.riskDetails = "Modifiye edilmiş potansiyel riskli APK/Dosya."
            }

            results.add(fileItem)
        }

        results
    }

    private fun collectStoragePayloads(dir: File, list: MutableList<File>, maxFiles: Int = 120) {
        if (list.size >= maxFiles) return
        val files = dir.listFiles() ?: return
        for (f in files) {
            if (list.size >= maxFiles) break
            if (f.isDirectory && !f.name.startsWith(".")) {
                collectStoragePayloads(f, list, maxFiles)
            } else if (f.isFile) {
                val ext = f.extension.lowercase()
                if (ext in listOf("apk", "dex", "sh", "exe", "js", "bat", "elf", "zip", "jar")) {
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
