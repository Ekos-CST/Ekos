package com.ekos.antivirus.engine

import android.app.Activity
import android.app.ProgressDialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.core.content.FileProvider
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit

object AppUpdateManager {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    data class UpdateInfo(
        val isUpdateAvailable: Boolean,
        val latestVersionCode: Int,
        val latestVersionName: String,
        val changelog: String,
        val downloadUrl: String
    )

    fun checkForUpdate(context: Context, showNoUpdateToast: Boolean = false) {
        val currentVersionCode = try {
            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pInfo.longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION")
                pInfo.versionCode
            }
        } catch (e: Exception) {
            1
        }

        CoroutineScope(Dispatchers.IO).launch {
            val updateInfo = fetchRemoteUpdateInfo(currentVersionCode)

            withContext(Dispatchers.Main) {
                if (updateInfo.isUpdateAvailable) {
                    showUpdateDialog(context, updateInfo)
                } else if (showNoUpdateToast) {
                    Toast.makeText(context, "Uygulamanız güncel (v1.0.0). Yeni bir güncelleme bulunmuyor.", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun fetchRemoteUpdateInfo(currentVersionCode: Int): UpdateInfo {
        // Fallback / Remote check endpoint
        val checkUrl = "https://raw.githubusercontent.com/Ekos-CST/Ekos/main/android_app/version.json"
        try {
            val request = Request.Builder().url(checkUrl).build()
            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                val jsonStr = response.body?.string() ?: ""
                val json = JSONObject(jsonStr)
                val serverVersionCode = json.optInt("versionCode", 1)
                val serverVersionName = json.optString("versionName", "1.0.0")
                val changelog = json.optString("changelog", "Performans ve güvenlik iyileştirmeleri.")
                val downloadUrl = json.optString("downloadUrl", "https://github.com/Ekos-CST/Ekos/releases/latest/download/app-release.apk")

                return UpdateInfo(
                    isUpdateAvailable = serverVersionCode > currentVersionCode,
                    latestVersionCode = serverVersionCode,
                    latestVersionName = serverVersionName,
                    changelog = changelog,
                    downloadUrl = downloadUrl
                )
            }
        } catch (e: Throwable) {}

        // Baseline metadata
        return UpdateInfo(
            isUpdateAvailable = false,
            latestVersionCode = 1,
            latestVersionName = "1.0.0",
            changelog = "En güncel sürüm",
            downloadUrl = ""
        )
    }

    fun showUpdateDialog(context: Context, updateInfo: UpdateInfo) {
        MaterialAlertDialogBuilder(context)
            .setTitle("✨ Yeni Güncelleme Yayında (v${updateInfo.latestVersionName})")
            .setMessage("Uygulamanın yeni bir sürümü yayınlandı!\n\nYenilikler:\n${updateInfo.changelog}\n\nŞimdi indirmek ve güncellemek ister misiniz?")
            .setPositiveButton("Şimdi Güncelle") { _, _ ->
                startDownloadAndInstall(context, updateInfo.downloadUrl)
            }
            .setNegativeButton("Daha Sonra", null)
            .show()
    }

    fun startDownloadAndInstall(context: Context, downloadUrl: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!context.packageManager.canRequestPackageInstalls()) {
                Toast.makeText(context, "Güncelleme yüklemek için bilinmeyen kaynaklara izin vermeniz gerekmektedir.", Toast.LENGTH_LONG).show()
                val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                    data = Uri.parse("package:${context.packageName}")
                }
                context.startActivity(intent)
                return
            }
        }

        @Suppress("DEPRECATION")
        val progressDialog = ProgressDialog(context).apply {
            setTitle("Güncelleme İndiriliyor")
            setMessage("Lütfen bekleyin, yeni sürüm cihaza indiriliyor...")
            setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
            max = 100
            setCancelable(false)
            show()
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val apkFile = File(context.getExternalFilesDir(null) ?: context.cacheDir, "ekos_update.apk")
                if (apkFile.exists()) apkFile.delete()

                val request = Request.Builder().url(downloadUrl).build()
                val response = httpClient.newCall(request).execute()

                if (response.isSuccessful) {
                    val body = response.body
                    val contentLength = body?.contentLength() ?: -1L
                    val inputStream = body?.byteStream()
                    val outputStream = FileOutputStream(apkFile)

                    val buffer = ByteArray(8192)
                    var bytesRead: Int
                    var totalBytesRead = 0L

                    while (inputStream?.read(buffer).also { bytesRead = it ?: -1 } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                        totalBytesRead += bytesRead
                        if (contentLength > 0) {
                            val progress = ((totalBytesRead * 100) / contentLength).toInt()
                            withContext(Dispatchers.Main) {
                                progressDialog.progress = progress
                            }
                        }
                    }

                    outputStream.flush()
                    outputStream.close()
                    inputStream?.close()

                    withContext(Dispatchers.Main) {
                        progressDialog.dismiss()
                        installDownloadedApk(context, apkFile)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        progressDialog.dismiss()
                        Toast.makeText(context, "Güncelleme indirilemedi. Lütfen bağlantınızı kontrol edin.", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Throwable) {
                withContext(Dispatchers.Main) {
                    progressDialog.dismiss()
                    Toast.makeText(context, "İndirme hatası: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    fun installDownloadedApk(context: Context, apkFile: File) {
        try {
            val apkUri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                apkFile
            )

            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(apkUri, "application/vnd.android.package-archive")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
            }
            context.startActivity(installIntent)
        } catch (e: Exception) {
            Toast.makeText(context, "Paket yükleyici başlatılamadı: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
