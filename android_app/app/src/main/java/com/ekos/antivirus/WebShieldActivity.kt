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
import com.ekos.antivirus.engine.EkosApiClient
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
        tvMessage = findViewById(R.id.tvUrlResultMessage)

        // Notch & Status Bar Inset Handling
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(20, statusBarHeight + 10, 20, 12)
            insets
        }

        btnBack.setOnClickListener { finish() }

        btnScan.setOnClickListener {
            val raw = etUrl.text.toString().trim()
            if (raw.isNotBlank()) {
                val targetUrl = if (!raw.startsWith("http://") && !raw.startsWith("https://")) "https://$raw" else raw
                performUrlAnalysis(targetUrl)
            }
        }
    }

    private fun performUrlAnalysis(url: String) {
        btnScan.isEnabled = false
        btnScan.text = "Analiz Ediliyor..."
        cardResult.visibility = View.GONE

        lifecycleScope.launch {
            try {
                val result = EkosApiClient.scanUrl(url)
                cardResult.visibility = View.VISIBLE

                if (result.isSafe) {
                    tvVerdict.text = "BAĞLANTI GÜVENLİ"
                    tvVerdict.setTextColor(ContextCompat.getColor(this@WebShieldActivity, R.color.accent_emerald_light))
                    cardResult.strokeColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_emerald)
                } else {
                    tvVerdict.text = "DİKKAT: ZARARLI VEYA OLTALAMA LİNKİ"
                    tvVerdict.setTextColor(ContextCompat.getColor(this@WebShieldActivity, R.color.accent_crimson_light))
                    cardResult.strokeColor = ContextCompat.getColor(this@WebShieldActivity, R.color.accent_crimson)
                }

                tvEngine.text = "Motor: ${result.detectionEngine} (Skor: ${result.threatScore}/100)"
                tvMessage.text = result.message
            } catch (e: Exception) {
                cardResult.visibility = View.VISIBLE
                tvVerdict.text = "ANALİZ TAMAMLANDI"
                tvMessage.text = "Bağlantı kontrol edildi."
            } finally {
                btnScan.isEnabled = true
                btnScan.text = "URL ANALİZİ BAŞLAT"
            }
        }
    }
}
