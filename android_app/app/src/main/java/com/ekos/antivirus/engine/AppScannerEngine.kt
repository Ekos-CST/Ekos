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
import java.util.ArrayDeque

class AppScannerEngine(private val context: Context) {

    // 1. HIZLI SİSTEM TARAMASI: Yalnızca kullanıcının sonradan yüklediği 3. taraf uygulamaları seri olarak tarar.
    suspend fun performQuickScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val allPackages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Throwable) {
            try { pm.getInstalledPackages(0) } catch (e2: Throwable) { emptyList() }
        }

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
            val sha256 = if (apkPath.isNotBlank()) calculateSha256(apkPath) else ""
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

    // 2. KAPSAMLI DERİN TARAMA: Tüm paketler + Dahili depolamadaki en ufak dosyaya kadar BÜTÜN dosyaları tarar.
    suspend fun performDeepScan(
        onProgress: (current: Int, total: Int, currentItem: String) -> Unit
    ): List<ScannedAppItem> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val allPackages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Throwable) {
            try { pm.getInstalledPackages(0) } catch (e2: Throwable) { emptyList() }
        }

        // Cihazdaki BÜTÜN dosyaları (tüm depolama alanını sınırsız olarak) topla
        val allFilesOnDevice = mutableListOf<File>()
        collectAllDeviceFilesRecursively(allFilesOnDevice)

        val totalWork = allPackages.size + allFilesOnDevice.size
        var completed = 0
        val results = mutableListOf<ScannedAppItem>()

        // Aşama 1: Bütün Uygulama ve Sistem Paketlerini Tara
        for (pkg in allPackages) {
            completed++
            val appName = try {
                pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
            } catch (e: Throwable) {
                pkg.packageName ?: "Paket"
            }

            if (completed % 5 == 0 || completed == allPackages.size) {
                withContext(Dispatchers.Main) {
                    onProgress(completed, totalWork, appName)
                }
            }

            val apkPath = try { pkg.applicationInfo?.sourceDir ?: "" } catch (e: Throwable) { "" }
            val isSystem = try {
                (pkg.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM)) != 0
            } catch (e: Throwable) { false }
            val sha256 = if (apkPath.isNotBlank()) calculateSha256(apkPath) else ""
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

        // Aşama 2: Cihazdaki BÜTÜN Dosyaları En Ufak Dosyaya Kadar Derinlemesine İncele
        for (file in allFilesOnDevice) {
            completed++
            if (completed % 15 == 0 || completed == totalWork) {
                withContext(Dispatchers.Main) {
                    onProgress(completed, totalWork, file.name)
                }
            }

            val ext = file.extension.lowercase()
            val fileSize = file.length()
            val sizeFormatted = when {
                fileSize < 1024 -> "$fileSize B"
                fileSize < 1024 * 1024 -> "${fileSize / 1024} KB"
                else -> "${fileSize / (1024 * 1024)} MB"
            }

            val isBinaryOrScript = ext in listOf("apk", "dex", "sh", "exe", "js", "bat", "elf", "jar", "bin", "so", "py", "vbs", "ps1", "zip")
            val sha256 = if (isBinaryOrScript || fileSize < 1024 * 1024) calculateSha256(file.absolutePath) else ""

            val fileItem = ScannedAppItem(
                appName = file.name,
                packageName = file.absolutePath,
                versionName = sizeFormatted,
                apkPath = file.absolutePath,
                sha256 = sha256,
                isSystemApp = false,
                icon = null
            )

            // Sezgisel ve imza tabanlı dosya güvenlik denetimi
            val fileNameLower = file.name.lowercase()
            if (isBinaryOrScript && (fileNameLower.contains("rat") || fileNameLower.contains("trojan") || fileNameLower.contains("stealer") || fileNameLower.contains("spyware"))) {
                fileItem.severity = ThreatSeverity.MALICIOUS
                fileItem.threatName = "Trojan.Android.Payload"
                fileItem.riskDetails = "Zararlı dosya adı ve yürütülebilir ikili deseni."
            } else if (ext == "apk" && (fileNameLower.contains("mod") || fileNameLower.contains("hacked") || fileNameLower.contains("crack"))) {
                fileItem.severity = ThreatSeverity.SUSPICIOUS
                fileItem.threatName = "Riskware.ModifiedApk"
                fileItem.riskDetails = "Modifiye edilmiş potansiyel riskli APK paketi."
            }

            results.add(fileItem)
        }

        results
    }

    // Cihazın dahili depolamasındaki tüm dizinleri derinlemesine ve sınırsız gezer
    private fun collectAllDeviceFilesRecursively(fileList: MutableList<File>) {
        val rootDirs = mutableListOf<File>()

        // 1. Ana Dahili Depolama Alanı (/storage/emulated/0)
        val externalStorage = Environment.getExternalStorageDirectory()
        if (externalStorage != null && externalStorage.exists() && externalStorage.canRead()) {
            rootDirs.add(externalStorage)
        }

        // 2. Standart Genel Dizinler
        val publicDirs = listOfNotNull(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC),
            context.getExternalFilesDir(null)
        )
        for (pd in publicDirs) {
            if (pd.exists() && !rootDirs.contains(pd)) {
                rootDirs.add(pd)
            }
        }

        val queue = ArrayDeque<File>()
        for (root in rootDirs) {
            queue.add(root)
        }

        val visitedPaths = HashSet<String>()

        while (queue.isNotEmpty()) {
            val currentDir = queue.poll() ?: continue
            val canonicalPath = try { currentDir.canonicalPath } catch (e: Throwable) { currentDir.absolutePath }
            if (!visitedPaths.add(canonicalPath)) continue

            val children = try { currentDir.listFiles() } catch (e: Throwable) { null } ?: continue

            for (child in children) {
                try {
                    if (child.isDirectory) {
                        // Sistem / korumalı gizli dizinler haricinde tüm alt dizinleri kuyruğa ekle
                        val name = child.name
                        if (!name.startsWith(".trash") && !name.startsWith(".thumb")) {
                            queue.add(child)
                        }
                    } else if (child.isFile && child.canRead()) {
                        fileList.add(child)
                    }
                } catch (e: Throwable) {}
            }
        }
    }

    private fun calculateSha256(filePath: String): String {
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
