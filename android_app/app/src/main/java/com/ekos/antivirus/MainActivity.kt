package com.ekos.antivirus

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.service.BackgroundShieldService
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var tvHeaderAccountStatus: TextView
    private lateinit var btnHeaderAccount: View
    private lateinit var tvMetricAppsCount: TextView
    private lateinit var tvMetricThreats: TextView
    private lateinit var btnStartQuickScan: Button
    private lateinit var btnStartDeepScan: Button
    private lateinit var cardWebShield: MaterialCardView
    private lateinit var cardAccountManagement: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        rootLayout = findViewById(R.id.rootMainLayout)

        // Notch & Status Bar Inset Handling
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        calculateInstalledAppsCount()

        // Start Foreground Real-Time Shield Service
        try {
            BackgroundShieldService.startService(this)
        } catch (e: Exception) {}
    }

    override fun onResume() {
        super.onResume()
        updateHeaderAccountBadge()
    }

    private fun initViews() {
        tvHeaderAccountStatus = findViewById(R.id.tvHeaderAccountStatus)
        btnHeaderAccount = findViewById(R.id.btnHeaderAccount)
        tvMetricAppsCount = findViewById(R.id.tvMetricAppsCount)
        tvMetricThreats = findViewById(R.id.tvMetricThreats)
        btnStartQuickScan = findViewById(R.id.btnStartQuickScan)
        btnStartDeepScan = findViewById(R.id.btnStartDeepScan)
        cardWebShield = findViewById(R.id.cardWebShield)
        cardAccountManagement = findViewById(R.id.cardAccountManagement)
    }

    private fun setupListeners() {
        btnHeaderAccount.setOnClickListener {
            startActivity(Intent(this, AccountActivity::class.java))
        }

        btnStartQuickScan.setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
        }

        btnStartDeepScan.setOnClickListener {
            startActivity(Intent(this, DeepScanActivity::class.java))
        }

        cardWebShield.setOnClickListener {
            startActivity(Intent(this, WebShieldActivity::class.java))
        }

        cardAccountManagement.setOnClickListener {
            startActivity(Intent(this, AccountActivity::class.java))
        }
    }

    private fun updateHeaderAccountBadge() {
        val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
        val token = prefs.getString("auth_token", null)
        val name = prefs.getString("user_name", null)
        val tier = prefs.getString("license_tier", null)
        val localKey = prefs.getString("license_key", null)

        if (token != null && name != null) {
            val shortName = name.split(" ").firstOrNull() ?: name
            val isPrem = tier != null && (tier.contains("Prem", ignoreCase = true) || tier.contains("Kurumsal", ignoreCase = true))
            val tierTag = if (isPrem) "Premium" else "Üye"
            tvHeaderAccountStatus.text = "$shortName ($tierTag)"
        } else if (localKey != null) {
            tvHeaderAccountStatus.text = "Premium Aktif"
        } else {
            tvHeaderAccountStatus.text = "Giriş Yap"
        }
    }

    private fun calculateInstalledAppsCount() {
        lifecycleScope.launch(Dispatchers.IO) {
            val count = try {
                packageManager.getInstalledPackages(0).size
            } catch (e: Exception) {
                0
            }
            withContext(Dispatchers.Main) {
                tvMetricAppsCount.text = count.toString()
            }
        }
    }
}
