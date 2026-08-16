package com.ekos.antivirus.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import com.ekos.antivirus.MainActivity
import com.ekos.antivirus.engine.ThreatDatabaseLocal
import com.ekos.antivirus.engine.ThreatSeverity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PackageInstallReceiver : BroadcastReceiver() {

    companion object {
        const val THREAT_CHANNEL_ID = "ekos_threat_alert_channel"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val dataUri = intent.data ?: return
            val packageName = dataUri.schemeSpecificPart ?: return

            if (packageName == context.packageName) return

            CoroutineScope(Dispatchers.IO).launch {
                scanInstalledPackage(context, packageName)
            }
        }
    }

    private fun scanInstalledPackage(context: Context, packageName: String) {
        val pm = context.packageManager
        val appName = try {
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Throwable) {
            packageName
        }

        var isThreat = false
        var threatName = ""
        var threatDetails = ""

        if (ThreatDatabaseLocal.isKnownMaliciousPackage(packageName)) {
            isThreat = true
            threatName = "Trojan.Android.Blacklisted"
            threatDetails = "Kara listedeki zararlı paket imzası tespit edildi."
        } else if (!ThreatDatabaseLocal.isTrustedPackage(packageName)) {
            val permissions = try {
                val pkgInfo = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                pkgInfo.requestedPermissions?.toList() ?: emptyList()
            } catch (e: Throwable) {
                emptyList()
            }

            val (riskSeverity, explanation) = ThreatDatabaseLocal.evaluatePermissionsRisk(packageName, permissions)
            if (riskSeverity != ThreatSeverity.SAFE) {
                isThreat = true
                threatName = "Heuristic.Android.Trojan"
                threatDetails = explanation ?: "Şüpheli truva atı izin kombinasyonu tespit edildi."
            }
        }

        if (isThreat) {
            showThreatAlertNotification(context, appName, packageName, threatName, threatDetails)
        }
    }

    private fun showThreatAlertNotification(
        context: Context,
        appName: String,
        packageName: String,
        threatName: String,
        details: String
    ) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                THREAT_CHANNEL_ID,
                "EKOS Tehdit Alarmları",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Algılanan zararlı uygulama ve dosya bildirimleri"
                enableVibration(true)
            }
            notificationManager.createNotificationChannel(channel)
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Strict: NO EMOJIS in title or body
        val notification = NotificationCompat.Builder(context, THREAT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("TEHDİT UYARISI: Zararlı Uygulama Tespit Edildi")
            .setContentText("Uygulama: $appName ($threatName). Kaldırmak için dokunun.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "Yüklenen '$appName' ($packageName) uygulamasında '$threatName' tehdidi tespit edildi.\n\nAyrıntı: $details\n\nCihaz güvenliğiniz için bu uygulamayı derhal kaldırmanız önerilir."
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager.notify(packageName.hashCode(), notification)
    }
}
