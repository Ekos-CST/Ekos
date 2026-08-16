package com.ekos.antivirus

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PrivacyGuardActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var tvPrivacyScore: TextView
    private lateinit var tvPrivacyVerdict: TextView

    private lateinit var tvCameraAppsCount: TextView
    private lateinit var tvMicAppsCount: TextView
    private lateinit var tvLocationAppsCount: TextView
    private lateinit var tvOverlayAppsCount: TextView
    private lateinit var btnOpenSystemPermissions: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy_guard)

        rootLayout = findViewById(R.id.rootPrivacyLayout)
        btnBack = findViewById(R.id.btnBackFromPrivacy)

        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        analyzePrivacyPermissions()
    }

    private fun initViews() {
        tvPrivacyScore = findViewById(R.id.tvPrivacyScore)
        tvPrivacyVerdict = findViewById(R.id.tvPrivacyVerdict)

        tvCameraAppsCount = findViewById(R.id.tvCameraAppsCount)
        tvMicAppsCount = findViewById(R.id.tvMicAppsCount)
        tvLocationAppsCount = findViewById(R.id.tvLocationAppsCount)
        tvOverlayAppsCount = findViewById(R.id.tvOverlayAppsCount)
        btnOpenSystemPermissions = findViewById(R.id.btnOpenSystemPermissions)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        btnOpenSystemPermissions.setOnClickListener {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS)
                startActivity(intent)
            } catch (e: Throwable) {
                try {
                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.fromParts("package", packageName, null)
                    }
                    startActivity(intent)
                } catch (e2: Throwable) {}
            }
        }
    }

    private fun analyzePrivacyPermissions() {
        lifecycleScope.launch(Dispatchers.IO) {
            val pm = packageManager
            val packages = try {
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            } catch (e: Throwable) {
                emptyList()
            }

            var cameraCount = 0
            var micCount = 0
            var locCount = 0
            var overlayCount = 0

            for (pkg in packages) {
                val perms = pkg.requestedPermissions ?: continue
                val pList = perms.toList()

                if (pList.contains("android.permission.CAMERA")) cameraCount++
                if (pList.contains("android.permission.RECORD_AUDIO")) micCount++
                if (pList.contains("android.permission.ACCESS_FINE_LOCATION") || pList.contains("android.permission.ACCESS_COARSE_LOCATION")) locCount++
                if (pList.contains("android.permission.SYSTEM_ALERT_WINDOW") || pList.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) overlayCount++
            }

            val score = (100 - (overlayCount * 3) - (cameraCount / 4)).coerceIn(85, 99)

            withContext(Dispatchers.Main) {
                tvPrivacyScore.text = "$score / 100"
                tvPrivacyVerdict.text = if (score >= 90) "Gizlilik Koruması Yüksek Düzeyde" else "Orta Düzeyde İzin Erişimi"

                tvCameraAppsCount.text = "$cameraCount Uygulama"
                tvMicAppsCount.text = "$micCount Uygulama"
                tvLocationAppsCount.text = "$locCount Uygulama"
                tvOverlayAppsCount.text = "$overlayCount Riskli"
            }
        }
    }
}
