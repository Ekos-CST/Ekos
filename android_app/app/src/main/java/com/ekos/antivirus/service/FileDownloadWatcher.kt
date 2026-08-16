package com.ekos.antivirus.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import androidx.core.app.NotificationCompat
import com.ekos.antivirus.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class FileDownloadWatcher(private val context: Context) {

    companion object {
        const val DOWNLOAD_THREAT_CHANNEL_ID = "ekos_download_threat_channel"
        private const val SAFE_TEST_TOKEN = "EKOS-TEST-SECURITY-SAMPLE-VALIDATION"
    }

    private var fileObserver: FileObserver? = null

    fun startWatching() {
        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (downloadDir == null || !downloadDir.exists()) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            fileObserver = object : FileObserver(downloadDir, CLOSE_WRITE or MOVED_TO or CREATE) {
                override fun onEvent(event: Int, path: String?) {
                    if (path != null) {
                        val downloadedFile = File(downloadDir, path)
                        scanFileAsync(downloadedFile)
                    }
                }
            }
        } else {
            @Suppress("DEPRECATION")
            fileObserver = object : FileObserver(downloadDir.absolutePath, CLOSE_WRITE or MOVED_TO or CREATE) {
                override fun onEvent(event: Int, path: String?) {
                    if (path != null) {
                        val downloadedFile = File(downloadDir, path)
                        scanFileAsync(downloadedFile)
                    }
                }
            }
        }
        fileObserver?.startWatching()
    }

    fun stopWatching() {
        fileObserver?.stopWatching()
        fileObserver = null
    }

    private fun scanFileAsync(file: File) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (!file.exists() || !file.isFile || !file.canRead()) return@launch

                val nameLower = file.name.lowercase()
                val ext = file.extension.lowercase()
                var isThreat = false
                var threatName = ""

                // 1. Direct Trojan / Malware Pattern Matching
                if (nameLower.contains("trojan") || nameLower.contains("stealer") || nameLower.contains("spyware") || nameLower.contains("rat.apk")) {
                    isThreat = true
                    threatName = "Trojan.Android.GenericPayload"
                }

                // 2. Safe heuristic / token checks without raw EICAR
                if (!isThreat && file.length() in 1..10000000) {
                    try {
                        val content = file.readText(Charsets.ISO_8859_1)
                        if (content.contains(SAFE_TEST_TOKEN)) {
                            isThreat = true
                            threatName = "EKOS.Security.ValidationSample"
                        }
                    } catch (e: Throwable) {}
                }

                if (isThreat) {
                    showDownloadThreatNotification(file.name, file.absolutePath, threatName)
                }
            } catch (e: Throwable) {}
        }
    }

    private fun showDownloadThreatNotification(fileName: String, filePath: String, threatName: String) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                DOWNLOAD_THREAT_CHANNEL_ID,
                "EKOS İndirilen Dosya Alarmları",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "İndirilen zararlı dosya bildirimleri"
                enableVibration(true)
            }
            notificationManager.createNotificationChannel(channel)
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            filePath.hashCode(),
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Strict: NO EMOJIS in title or body
        val notification = NotificationCompat.Builder(context, DOWNLOAD_THREAT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("TEHDİT UYARISI: Zararlı Dosya İndirildi")
            .setContentText("Dosya: $fileName ($threatName). Dosyayı açmayınız.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "İndirilenler klasörüne kaydedilen '$fileName' dosyasında '$threatName' tehdidi tespit edildi.\n\nDosya Yolu: $filePath\n\nCihazınızı korumak için bu dosyayı açmayınız ve derhal siliniz."
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager.notify(filePath.hashCode(), notification)
    }
}
