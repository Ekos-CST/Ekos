package com.ekos.antivirus

import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.engine.EkosApiClient
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.launch

class ClipboardShieldActivity : AppCompatActivity() {

    private lateinit var btnBack: ImageButton
    private lateinit var tvSnippet: TextView
    private lateinit var btnAnalyze: Button
    private lateinit var cardResult: MaterialCardView
    private lateinit var tvVerdict: TextView
    private lateinit var tvMessage: TextView

    private var currentClipboardText = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_clipboard_shield)

        btnBack = findViewById(R.id.btnBackFromClipboard)
        tvSnippet = findViewById(R.id.tvClipboardSnippet)
        btnAnalyze = findViewById(R.id.btnAnalyzeClipboard)
        cardResult = findViewById(R.id.cardClipboardResult)
        tvVerdict = findViewById(R.id.tvClipboardResultVerdict)
        tvMessage = findViewById(R.id.tvClipboardResultMessage)

        btnBack.setOnClickListener { finish() }

        readClipboard()

        btnAnalyze.setOnClickListener {
            if (currentClipboardText.isNotBlank()) {
                performClipboardAnalysis(currentClipboardText)
            }
        }
    }

    private fun readClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (clipboard.hasPrimaryClip() && (clipboard.primaryClip?.itemCount ?: 0) > 0) {
            val text = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
            currentClipboardText = text
            tvSnippet.text = if (text.length > 300) text.substring(0, 300) + "..." else text
        } else {
            tvSnippet.text = "Panoda henüz kopyalanmış metin bulunmuyor."
        }
    }

    private fun performClipboardAnalysis(text: String) {
        btnAnalyze.isEnabled = false
        btnAnalyze.text = "İnceleniyor..."
        cardResult.visibility = View.GONE

        lifecycleScope.launch {
            val result = EkosApiClient.analyzePayload(text)
            cardResult.visibility = View.VISIBLE

            if (result.isSuspicious) {
                tvVerdict.text = "DİKKAT: ŞÜPHELİ KOMUT VEYA ENJEKSİYON"
                tvVerdict.setTextColor(ContextCompat.getColor(this@ClipboardShieldActivity, R.color.status_red_light))
                cardResult.strokeColor = ContextCompat.getColor(this@ClipboardShieldActivity, R.color.status_red)
                tvMessage.text = "${result.threatType ?: "Exploit"}: ${result.explanation ?: "Zararlı betik"}"
            } else {
                tvVerdict.text = "PANO GÜVENLİ VE TEMİZ"
                tvVerdict.setTextColor(ContextCompat.getColor(this@ClipboardShieldActivity, R.color.status_green_light))
                cardResult.strokeColor = ContextCompat.getColor(this@ClipboardShieldActivity, R.color.status_green)
                tvMessage.text = "Metin içerisinde herhangi bir zararlı kod, komut tuzağı veya exploit tespit edilmedi."
            }

            btnAnalyze.isEnabled = true
            btnAnalyze.text = "PANODAKİ METNİ ANALİZ ET"
        }
    }
}
