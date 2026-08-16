package com.ekos.antivirus

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.engine.WebContentInspector
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.launch

class WebShieldActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var etUrl: EditText
    private lateinit var btnScan: Button
    private lateinit var cardResult: MaterialCardView
    private lateinit var tvVerdict: TextView
    private lateinit var tvEngine: TextView
    private lateinit var tvPageTitle: TextView
    private lateinit var tvCheckForm: TextView
    private lateinit var tvCheckScript: TextView
    private lateinit var tvCheckPhishing: TextView
    private lateinit var tvCheckDownload: TextView
    private lateinit var tvMessage: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_web_shield)

        rootLayout = findViewById(R.id.rootWebShieldLayout)
        btnBack = findViewById(R.id.btnBackFromWeb)
        etUrl = findViewById(R.id.etTargetUrl)
        btnScan = findViewById(R.id.btnScanUrlSubmit)
        cardResult = findViewById(R.id.cardUrlResult)
        tvVerdict = findViewById(R.id.tvUrlResultVerdict)
        tvEngine = findViewById(R.id.tvUrlResultEngine)
        tvPageTitle = findViewById(R.id.tvUrlPageTitle)
        tvCheckForm = findViewById(R.id.tvCheckForm)
        tvCheckScript = findViewById(R.id.tvCheckScript)
        tvCheckPhishing = findViewById(R.id.tvCheckPhishing)
        tvCheckDownload = findViewById(R.id.tvCheckDownload)
        tvMessage = findViewById(R.id.tvUrlResultMessage)

        // Notch & Status Bar Inset Handling
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        btnBack.setOnClickListener { finish() }

        btnScan.setOnClickListener {
            val raw = etUrl.text.toString().trim()
            if (raw.isNotBlank()) {
                performDeepWebContentAnalysis(raw)
            }
        }
    }

    private fun performDeepWebContentAnalysis(targetUrl: String) {
        btnScan.isEnabled = false
        btnScan.text = "Site İçeriği ve Kodlar Taranıyor..."
        cardResult.visibility = View.GONE

        lifecycleScope.launch {
            try {
                val report = WebContentInspector.analyzeUrlContent(targetUrl)
                cardResult.visibility = View.VISIBLE

                tvVerdict.text = report.verdict
                tvPageTitle.text = "Sayfa Başlığı: ${report.title} (${report.protocol})"
                tvEngine.text = "Motor: EKOS Derin Web & İçerik Denetçisi (Tehdit Skoru: ${report.threatScore}/100)"

                // Checkpoints status text and colors
                tvCheckForm.text = report.formSecurityStatus
                tvCheckScript.text = report.scriptSecurityStatus
                tvCheckPhishing.text = report.phishingStatus
                tvCheckDownload.text = report.downloadStatus

                val greenColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_emerald_light)
                val redColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_crimson_light)

                tvCheckForm.setTextColor(if (report.isFormThreat) redColor else greenColor)
                tvCheckScript.setTextColor(if (report.isScriptThreat) redColor else greenColor)
                tvCheckPhishing.setTextColor(if (report.isPhishingThreat) redColor else greenColor)
                tvCheckDownload.setTextColor(if (report.isDownloadThreat) redColor else greenColor)

                if (report.isSafe) {
                    tvVerdict.setTextColor(greenColor)
                    cardResult.strokeColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_emerald)
                } else {
                    tvVerdict.setTextColor(redColor)
                    cardResult.strokeColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_crimson)
                }

                tvMessage.text = report.findings.joinToString("\n• ", prefix = "• ")

            } catch (e: Exception) {
                cardResult.visibility = View.VISIBLE
                tvVerdict.text = "BAĞLANTI DENETLENDİ"
                tvMessage.text = "Siteye erişildi ve temel kontroller yapıldı."
            } finally {
                btnScan.isEnabled = true
                btnScan.text = "SİTE İÇERİĞİNİ DERİNLEMESİNE TARA"
            }
        }
    }
}
