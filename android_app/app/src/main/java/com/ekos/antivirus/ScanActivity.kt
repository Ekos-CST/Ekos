package com.ekos.antivirus

import android.os.Bundle
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ekos.antivirus.engine.AppScannerEngine
import com.ekos.antivirus.engine.ScannedAppItem
import com.ekos.antivirus.engine.ThreatSeverity
import kotlinx.coroutines.launch

class ScanActivity : AppCompatActivity() {

    private lateinit var btnBack: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var tvPercentage: TextView
    private lateinit var pbProgress: ProgressBar
    private lateinit var tvCurrentApp: TextView
    private lateinit var tvHeader: TextView
    private lateinit var rvApps: RecyclerView

    private val scannedList = mutableListOf<ScannedAppItem>()
    private lateinit var adapter: ScannedAppAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)

        btnBack = findViewById(R.id.btnBackFromScan)
        tvStatus = findViewById(R.id.tvScanCurrentStatus)
        tvPercentage = findViewById(R.id.tvScanPercentage)
        pbProgress = findViewById(R.id.pbScanProgress)
        tvCurrentApp = findViewById(R.id.tvCurrentScanningApp)
        tvHeader = findViewById(R.id.tvScanListHeader)
        rvApps = findViewById(R.id.rvScannedApps)

        btnBack.setOnClickListener { finish() }

        adapter = ScannedAppAdapter(scannedList)
        rvApps.layoutManager = LinearLayoutManager(this)
        rvApps.adapter = adapter

        startEngineScan()
    }

    private fun startEngineScan() {
        val scanner = AppScannerEngine(this)

        lifecycleScope.launch {
            val results = scanner.performFullScan { current, total, appName ->
                val pct = if (total > 0) ((current.toFloat() / total.toFloat()) * 100).toInt() else 0
                pbProgress.progress = pct
                tvPercentage.text = "$pct%"
                tvCurrentApp.text = "İnceleniyor: $appName"
            }

            scannedList.clear()
            // Put malicious first, then suspicious, then safe
            scannedList.addAll(results.sortedByDescending { it.severity.ordinal })
            adapter.notifyDataSetChanged()

            val threatsCount = results.count { it.severity != ThreatSeverity.SAFE }
            if (threatsCount > 0) {
                tvStatus.text = "DİKKAT: $threatsCount Şüpheli / Tehdit Tespit Edildi!"
                tvStatus.setTextColor(getColor(R.color.status_red_light))
            } else {
                tvStatus.text = "Tarama Tamamlandı. Tehdit Bulunamadı."
                tvStatus.setTextColor(getColor(R.color.status_green_light))
            }

            tvCurrentApp.text = "Toplam ${results.size} uygulama ve paket başarıyla incelendi."
            tvHeader.text = "TARANAN UYGULAMALAR (${results.size})"
        }
    }
}
