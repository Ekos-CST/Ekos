package com.ekos.antivirus

import android.content.Context
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.ekos.antivirus.engine.EkosApiClient

class AccountSyncActivity : AppCompatActivity() {

    private lateinit var btnBack: ImageButton
    private lateinit var tvEmail: TextView
    private lateinit var tvTier: TextView
    private lateinit var etCode: EditText
    private lateinit var btnSubmit: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account_sync)

        btnBack = findViewById(R.id.btnBackFromSync)
        tvEmail = findViewById(R.id.tvSyncAccountEmail)
        tvTier = findViewById(R.id.tvSyncAccountTier)
        etCode = findViewById(R.id.etLicenseOrPairCode)
        btnSubmit = findViewById(R.id.btnSubmitLicenseCode)

        btnBack.setOnClickListener { finish() }

        loadSavedState()

        btnSubmit.setOnClickListener {
            val code = etCode.text.toString().trim()
            if (code.isNotBlank()) {
                activateLicense(code)
            }
        }
    }

    private fun loadSavedState() {
        val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
        val savedTier = prefs.getString("license_tier", "EKOS Standart Mobil (Ücretsiz)")
        val savedKey = prefs.getString("license_key", null)

        tvTier.text = "Paket: $savedTier"
        if (savedKey != null) {
            tvEmail.text = "Lisanslı Cihaz ($savedKey)"
            EkosApiClient.customApiKey = savedKey
        }
    }

    private fun activateLicense(code: String) {
        val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
        val isPremium = code.startsWith("EKOS-PREM", ignoreCase = true) || code.contains("PREM", ignoreCase = true)
        val newTier = if (isPremium) "EKOS Kurumsal Premium (Mobil Kalkan)" else "EKOS Geliştirici Lisansı"

        prefs.edit()
            .putString("license_tier", newTier)
            .putString("license_key", code)
            .apply()

        EkosApiClient.customApiKey = code

        tvTier.text = "Paket: $newTier"
        tvEmail.text = "Lisans Doğrulandı ($code)"

        Toast.makeText(this, "Lisans başarıyla aktifleştirildi!", Toast.LENGTH_LONG).show()
        etCode.text.clear()
    }
}
