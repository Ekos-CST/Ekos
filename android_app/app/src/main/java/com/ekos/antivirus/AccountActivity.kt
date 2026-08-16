package com.ekos.antivirus

import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.engine.EkosApiClient
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.launch

class AccountActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton

    // Active Premium Badge Card
    private lateinit var cardActivePremium: MaterialCardView
    private lateinit var tvActivePremiumCode: TextView

    // Profile View
    private lateinit var layoutProfileView: MaterialCardView
    private lateinit var tvProfileName: TextView
    private lateinit var tvProfileEmail: TextView
    private lateinit var tvProfileTierBadge: TextView
    private lateinit var btnLogout: Button

    // License Activation
    private lateinit var etProfileLicenseCode: EditText
    private lateinit var btnApplyProfileLicense: Button

    // Auth Form View
    private lateinit var layoutAuthForm: LinearLayout
    private lateinit var tabBtnLogin: Button
    private lateinit var tabBtnRegister: Button
    private lateinit var formLogin: LinearLayout
    private lateinit var formRegister: LinearLayout

    // Login Form
    private lateinit var etLoginEmail: EditText
    private lateinit var etLoginPassword: EditText
    private lateinit var btnSubmitLogin: Button

    // Register Form
    private lateinit var etRegisterName: EditText
    private lateinit var etRegisterEmail: EditText
    private lateinit var etRegisterPassword: EditText
    private lateinit var etRegisterSecAnswer: EditText
    private lateinit var btnSubmitRegister: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account)

        rootLayout = findViewById(R.id.rootAccountLayout)
        btnBack = findViewById(R.id.btnBackFromAccount)

        // Notch & Status Bar Insets
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        checkExistingSession()
    }

    private fun initViews() {
        cardActivePremium = findViewById(R.id.cardActivePremium)
        tvActivePremiumCode = findViewById(R.id.tvActivePremiumCode)

        layoutProfileView = findViewById(R.id.layoutProfileView)
        tvProfileName = findViewById(R.id.tvProfileName)
        tvProfileEmail = findViewById(R.id.tvProfileEmail)
        tvProfileTierBadge = findViewById(R.id.tvProfileTierBadge)
        btnLogout = findViewById(R.id.btnLogout)

        etProfileLicenseCode = findViewById(R.id.etProfileLicenseCode)
        btnApplyProfileLicense = findViewById(R.id.btnApplyProfileLicense)

        layoutAuthForm = findViewById(R.id.layoutAuthForm)
        tabBtnLogin = findViewById(R.id.tabBtnLogin)
        tabBtnRegister = findViewById(R.id.tabBtnRegister)
        formLogin = findViewById(R.id.formLogin)
        formRegister = findViewById(R.id.formRegister)

        etLoginEmail = findViewById(R.id.etLoginEmail)
        etLoginPassword = findViewById(R.id.etLoginPassword)
        btnSubmitLogin = findViewById(R.id.btnSubmitLogin)

        etRegisterName = findViewById(R.id.etRegisterName)
        etRegisterEmail = findViewById(R.id.etRegisterEmail)
        etRegisterPassword = findViewById(R.id.etRegisterPassword)
        etRegisterSecAnswer = findViewById(R.id.etRegisterSecAnswer)
        btnSubmitRegister = findViewById(R.id.btnSubmitRegister)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        tabBtnLogin.setOnClickListener {
            formLogin.visibility = View.VISIBLE
            formRegister.visibility = View.GONE
            tabBtnLogin.background = ContextCompat.getDrawable(this, R.drawable.bg_button_primary)
            tabBtnLogin.setTextColor(ContextCompat.getColor(this, R.color.white))
            tabBtnRegister.setBackgroundColor(0)
            tabBtnRegister.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
        }

        tabBtnRegister.setOnClickListener {
            formLogin.visibility = View.GONE
            formRegister.visibility = View.VISIBLE
            tabBtnRegister.background = ContextCompat.getDrawable(this, R.drawable.bg_button_emerald)
            tabBtnRegister.setTextColor(ContextCompat.getColor(this, R.color.white))
            tabBtnLogin.setBackgroundColor(0)
            tabBtnLogin.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
        }

        btnSubmitLogin.setOnClickListener {
            val email = etLoginEmail.text.toString().trim()
            val pass = etLoginPassword.text.toString().trim()
            if (email.isNotBlank() && pass.isNotBlank()) {
                performLogin(email, pass)
            } else {
                Toast.makeText(this, "E-posta ve şifre gereklidir.", Toast.LENGTH_SHORT).show()
            }
        }

        btnSubmitRegister.setOnClickListener {
            val name = etRegisterName.text.toString().trim()
            val email = etRegisterEmail.text.toString().trim()
            val pass = etRegisterPassword.text.toString().trim()
            val sec = etRegisterSecAnswer.text.toString().trim()
            if (name.isNotBlank() && email.isNotBlank() && pass.length >= 6) {
                performRegister(name, email, pass, sec)
            } else {
                Toast.makeText(this, "Lütfen tüm alanları doldurun (şifre min 6 karakter).", Toast.LENGTH_SHORT).show()
            }
        }

        btnApplyProfileLicense.setOnClickListener {
            val code = etProfileLicenseCode.text.toString().trim()
            if (code.isNotBlank()) {
                val isPrem = code.startsWith("EKOS-PREM", ignoreCase = true) || code.contains("PREM", ignoreCase = true)
                val tierName = if (isPrem) "EKOS Kurumsal Premium" else "EKOS Pro Lisansı"

                val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("license_tier", tierName)
                    .putString("license_key", code)
                    .apply()

                EkosApiClient.customApiKey = code
                checkExistingSession()
                Toast.makeText(this, "Lisans kodu başarıyla aktifleştirildi: $code", Toast.LENGTH_LONG).show()
                etProfileLicenseCode.text.clear()
            } else {
                Toast.makeText(this, "Lütfen geçerli bir lisans kodu giriniz.", Toast.LENGTH_SHORT).show()
            }
        }

        btnLogout.setOnClickListener {
            val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
            prefs.edit().clear().apply()
            EkosApiClient.authToken = null
            EkosApiClient.customApiKey = null
            checkExistingSession()
            Toast.makeText(this, "Oturum kapatıldı.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun checkExistingSession() {
        val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
        val token = prefs.getString("auth_token", null)
        val email = prefs.getString("user_email", null)
        val name = prefs.getString("user_name", null)
        val tier = prefs.getString("license_tier", "EKOS Standart") ?: "EKOS Standart"
        val licenseKey = prefs.getString("license_key", null)

        val isPremium = tier.contains("Prem", ignoreCase = true) || tier.contains("Kurumsal", ignoreCase = true) || (licenseKey != null && licenseKey.contains("PREM", ignoreCase = true))

        // Show/Hide Active Premium Gold Badge Card
        if (isPremium) {
            cardActivePremium.visibility = View.VISIBLE
            tvActivePremiumCode.text = "Lisans Anahtarı: ${licenseKey ?: "Kurumsal Hesap Entegre"}"
        } else {
            cardActivePremium.visibility = View.GONE
        }

        if (token != null && email != null) {
            layoutProfileView.visibility = View.VISIBLE
            layoutAuthForm.visibility = View.GONE
            tvProfileName.text = name ?: "EKOS Kullanıcısı"
            tvProfileEmail.text = email
            tvProfileTierBadge.text = "★ ${tier.uppercase()}"
        } else {
            layoutProfileView.visibility = View.GONE
            layoutAuthForm.visibility = View.VISIBLE
        }
    }

    private fun performLogin(email: String, pass: String) {
        btnSubmitLogin.isEnabled = false
        btnSubmitLogin.text = "Giriş Yapılıyor..."

        lifecycleScope.launch {
            val res = EkosApiClient.login(email, pass)
            btnSubmitLogin.isEnabled = true
            btnSubmitLogin.text = "GİRİŞ YAP VE SENKRONİZE ET"

            if (res.success && res.token != null) {
                val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("auth_token", res.token)
                    .putString("user_email", res.user?.email ?: email)
                    .putString("user_name", res.user?.fullName ?: "EKOS Kullanıcısı")
                    .putString("license_tier", res.user?.licenseTier ?: "EKOS Standart")
                    .apply()

                Toast.makeText(this@AccountActivity, "Giriş başarılı! Hoş geldiniz.", Toast.LENGTH_SHORT).show()
                checkExistingSession()
            } else {
                Toast.makeText(this@AccountActivity, "Hata: ${res.error ?: "Giriş yapılamadı."}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun performRegister(name: String, email: String, pass: String, sec: String) {
        btnSubmitRegister.isEnabled = false
        btnSubmitRegister.text = "Kayıt Yapılıyor..."

        lifecycleScope.launch {
            val res = EkosApiClient.register(name, email, pass, "İlk evcil hayvanınız?", sec)
            btnSubmitRegister.isEnabled = true
            btnSubmitRegister.text = "HESAP OLUŞTUR"

            if (res.success) {
                Toast.makeText(this@AccountActivity, res.message ?: "Kayıt başarılı!", Toast.LENGTH_LONG).show()
                tabBtnLogin.performClick()
                etLoginEmail.setText(email)
                etLoginPassword.setText(pass)
            } else {
                Toast.makeText(this@AccountActivity, "Hata: ${res.error ?: "Kayıt olunamadı."}", Toast.LENGTH_LONG).show()
            }
        }
    }
}
