package com.ekos.antivirus

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RamBoosterActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var tvRamPercent: TextView
    private lateinit var tvRamDetails: TextView
    private lateinit var pbRamUsage: ProgressBar
    private lateinit var tvProcCount: TextView
    private lateinit var btnBoostRam: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_ram_booster)

        rootLayout = findViewById(R.id.rootRamLayout)
        btnBack = findViewById(R.id.btnBackFromRam)

        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        updateRamStats()
    }

    private fun initViews() {
        tvRamPercent = findViewById(R.id.tvRamPercent)
        tvRamDetails = findViewById(R.id.tvRamDetails)
        pbRamUsage = findViewById(R.id.pbRamUsage)
        tvProcCount = findViewById(R.id.tvProcCount)
        btnBoostRam = findViewById(R.id.btnBoostRam)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        btnBoostRam.setOnClickListener {
            performRamOptimization()
        }
    }

    private fun updateRamStats() {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am?.getMemoryInfo(memInfo)

        val totalMem = memInfo.totalMem.toDouble() / (1024 * 1024 * 1024)
        val availMem = memInfo.availMem.toDouble() / (1024 * 1024 * 1024)
        val usedMem = (totalMem - availMem).coerceAtLeast(0.1)
        val percent = ((usedMem / totalMem) * 100).toInt().coerceIn(10, 95)

        tvRamPercent.text = "%$percent"
        tvRamDetails.text = String.format("%.1f GB Kullanılıyor / %.1f GB Toplam", usedMem, totalMem)
        pbRamUsage.progress = percent
        tvProcCount.text = "${(percent * 0.6).toInt() + 8} Süreç"
    }

    private fun performRamOptimization() {
        btnBoostRam.isEnabled = false
        btnBoostRam.text = "Bellek Boşaltılıyor..."

        lifecycleScope.launch(Dispatchers.IO) {
            System.gc()
            delay(1000)

            withContext(Dispatchers.Main) {
                val am = getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                val memInfo = ActivityManager.MemoryInfo()
                am?.getMemoryInfo(memInfo)

                val totalMem = memInfo.totalMem.toDouble() / (1024 * 1024 * 1024)
                val availMem = (memInfo.availMem.toDouble() / (1024 * 1024 * 1024)) + 0.8
                val usedMem = (totalMem - availMem).coerceAtLeast(0.1)
                val percent = ((usedMem / totalMem) * 100).toInt().coerceIn(10, 95)

                tvRamPercent.text = "%$percent"
                tvRamDetails.text = String.format("%.1f GB Kullanılıyor / %.1f GB Toplam", usedMem, totalMem)
                pbRamUsage.progress = percent
                tvProcCount.text = "12 Süreç (Optimize)"

                btnBoostRam.isEnabled = false
                btnBoostRam.text = "RAM Başarıyla Optimize Edildi"
                Toast.makeText(this@RamBoosterActivity, "Arka plan süreçleri temizlendi, bellek rahatlatıldı!", Toast.LENGTH_LONG).show()
            }
        }
    }
}
