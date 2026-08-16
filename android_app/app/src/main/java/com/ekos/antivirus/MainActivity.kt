package com.ekos.antivirus

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.service.BackgroundShieldService
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var tvMetricAppsCount: TextView
    private lateinit var tvMetricThreats: TextView
    private lateinit var btnStartQuickScan: Button
    private lateinit var cardWebShield: MaterialCardView
    private lateinit var cardClipboardShield: MaterialCardView
    private lateinit var cardAccountSync: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupListeners()
        calculateInstalledAppsCount()

        // Start Foreground Real-Time Shield Service
        try {
            BackgroundShieldService.startService(this)
        } catch (e: Exception) {}
    }

    private fun initViews() {
        tvMetricAppsCount = findViewById(R.id.tvMetricAppsCount)
        tvMetricThreats = findViewById(R.id.tvMetricThreats)
        btnStartQuickScan = findViewById(R.id.btnStartQuickScan)
        cardWebShield = findViewById(R.id.cardWebShield)
        cardClipboardShield = findViewById(R.id.cardClipboardShield)
        cardAccountSync = findViewById(R.id.cardAccountSync)
    }

    private fun setupListeners() {
        btnStartQuickScan.setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
        }

        cardWebShield.setOnClickListener {
            startActivity(Intent(this, WebShieldActivity::class.java))
        }

        cardClipboardShield.setOnClickListener {
            startActivity(Intent(this, ClipboardShieldActivity::class.java))
        }

        cardAccountSync.setOnClickListener {
            startActivity(Intent(this, AccountSyncActivity::class.java))
        }
    }

    private fun calculateInstalledAppsCount() {
        lifecycleScope.launch(Dispatchers.IO) {
            val count = try {
                packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS).size
            } catch (e: Exception) {
                0
            }
            withContext(Dispatchers.Main) {
                tvMetricAppsCount.text = count.toString()
            }
        }
    }
}
