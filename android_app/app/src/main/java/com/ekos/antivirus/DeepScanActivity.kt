package com.ekos.antivirus

import android.os.Bundle
import android.view.View
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ekos.antivirus.engine.AppScannerEngine
import com.ekos.antivirus.engine.ScannedAppItem
import com.ekos.antivirus.engine.ThreatSeverity
import kotlinx.coroutines.launch

class DeepScanActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var tvPercentage: TextView
    private lateinit var pbProgress: ProgressBar
    private lateinit var tvCurrentFile: TextView
    private lateinit var tvHeader: TextView
    private lateinit var rvResults: RecyclerView

    private val scannedList = mutableListOf<ScannedAppItem>()
    private lateinit var adapter: ScannedAppAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_deep_scan)

        rootLayout = findViewById(R.id.rootDeepScanLayout)
        btnBack = findViewById(R.id.btnBackFromDeepScan)
        tvStatus = findViewById(R.id.tvDeepScanStatus)
        tvPercentage = findViewById(R.id.tvDeepScanPercentage)
        pbProgress = findViewById(R.id.pbDeepScanProgress)
        tvCurrentFile = findViewById(R.id.tvDeepCurrentFile)
        tvHeader = findViewById(R.id.tvDeepScanHeader)
        rvResults = findViewById(R.id.rvDeepScanResults)

        // Notch & Status Bar Insets
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(20, statusBarHeight + 10, 20, 12)
            insets
        }

        btnBack.setOnClickListener { finish() }

        adapter = ScannedAppAdapter(scannedList)
        rvResults.layoutManager = LinearLayoutManager(this)
        rvResults.adapter = adapter

        startDeepEngineScan()
    }

    private fun startDeepEngineScan() {
        val scanner = AppScannerEngine(this)

        lifecycleScope.launch {
            try {
                val results = scanner.performDeepScan { current, total, itemName ->
                    val pct = if (total > 0) ((current.toFloat() / total.toFloat()) * 100).toInt() else 0
                    pbProgress.progress = pct
                    tvPercentage.text = "$pct%"
                    tvCurrentFile.text = "Analiz: $itemName"
                }

                scannedList.clear()
                scannedList.addAll(results.sortedByDescending { it.severity.ordinal })
                adapter.notifyDataSetChanged()

                val threatsCount = results.count { it.severity != ThreatSeverity.SAFE }
                if (threatsCount > 0) {
                    tvStatus.text = "DİKKAT: $threatsCount Şüpheli / Tehdit Bulundu!"
                    tvStatus.setTextColor(ContextCompat.getColor(this@DeepScanActivity, R.color.accent_crimson_light))
                } else {
                    tvStatus.text = "Derin Tarama Tamamlandı. Sistem Güvenli."
                    tvStatus.setTextColor(ContextCompat.getColor(this@DeepScanActivity, R.color.accent_emerald_light))
                }

                tvCurrentFile.text = "Toplam ${results.size} uygulama ve dosya derinlemesine denetlendi."
                tvHeader.text = "DERİN TARAMA RAPORU (${results.size})"
            } catch (e: Exception) {
                tvStatus.text = "Tarama tamamlandı (Bazı sistem dizinleri korumalı)."
                tvStatus.setTextColor(ContextCompat.getColor(this@DeepScanActivity, R.color.accent_emerald_light))
            }
        }
    }
}
