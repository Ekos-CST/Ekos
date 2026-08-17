package com.ekos.antivirus.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.ekos.antivirus.MainActivity

class BackgroundShieldService : Service() {

    companion object {
        const val CHANNEL_ID = "ekos_shield_channel"
        const val NOTIFICATION_ID = 1001

        fun startService(context: Context) {
            try {
                val intent = Intent(context, BackgroundShieldService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Throwable) {
                // Catch ForegroundServiceStartNotAllowedException gracefully on Android 12+
            }
        }

        fun stopService(context: Context) {
            try {
                val intent = Intent(context, BackgroundShieldService::class.java)
                context.stopService(intent)
            } catch (e: Throwable) {}
        }
    }

    private var fileWatcher: FileDownloadWatcher? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        fileWatcher = FileDownloadWatcher(this).apply {
            startWatching()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val notification = buildForegroundNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Throwable) {
            // Android 12+ Background execution limit guard
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        fileWatcher?.stopWatching()
        fileWatcher = null
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "EKOS Gerçek Zamanlı Koruma",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "EKOS Antivirüs mobil koruma motoru aktif bildirimleri"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Strict: NO EMOJIS
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("EKOS Antivirüs - Canlı Kalkan Aktif")
            .setContentText("Cihazınız, indirilen dosyalar ve uygulamalar sürekli taranıyor.")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
