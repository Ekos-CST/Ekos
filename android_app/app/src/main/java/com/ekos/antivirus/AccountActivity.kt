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
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.ekos.antivirus.engine.EkosApiClient
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.launch

class AccountActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton

    // Digital Membership Card Views
    private lateinit var cardDigitalMembership: MaterialCardView
    private lateinit var tvMembershipTierBadge: TextView
    private lateinit var tvCardUserName: TextView
    private lateinit var tvCardUserEmail: TextView
    private lateinit var tvCardLicenseKey: TextView
    private lateinit var tvCardSyncStatus: TextView

    // Segment Switcher
    private lateinit var tabBtnLicense: Button
    private lateinit var tabBtnAuth: Button
    private lateinit var sectionLicense: LinearLayout
    private lateinit var sectionAuth: LinearLayout

    // License Section
    private lateinit var etProfileLicenseCode: EditText
    private lateinit var btnApplyProfileLicense: Button

    // Auth Section
    private lateinit var layoutProfileView: MaterialCardView
    private lateinit var layoutAuthForm: MaterialCardView
    private lateinit var tvProfileName: TextView
    private lateinit var tvProfileEmail: TextView
    private lateinit var btnLogout: Button
    private lateinit var btnDeleteAccount: Button
    private lateinit var etLoginEmail: EditText
    private lateinit var etLoginPassword: EditText
    private lateinit var btnSubmitLogin: Button
    private lateinit var tvToggleRegisterPrompt: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account)

        rootLayout = findViewById(R.id.rootAccountLayout)
        btnBack = findViewById(R.id.btnBackFromAccount)

        // Notch & Status Bar Inset Handling
        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        updateAccountState()
    }

    private fun initViews() {
        cardDigitalMembership = findViewById(R.id.cardDigitalMembership)
        tvMembershipTierBadge = findViewById(R.id.tvMembershipTierBadge)
        tvCardUserName = findViewById(R.id.tvCardUserName)
        tvCardUserEmail = findViewById(R.id.tvCardUserEmail)
        tvCardLicenseKey = findViewById(R.id.tvCardLicenseKey)
        tvCardSyncStatus = findViewById(R.id.tvCardSyncStatus)

        tabBtnLicense = findViewById(R.id.tabBtnLicense)
        tabBtnAuth = findViewById(R.id.tabBtnAuth)
        sectionLicense = findViewById(R.id.sectionLicense)
        sectionAuth = findViewById(R.id.sectionAuth)

        etProfileLicenseCode = findViewById(R.id.etProfileLicenseCode)
        btnApplyProfileLicense = findViewById(R.id.btnApplyProfileLicense)

        layoutProfileView = findViewById(R.id.layoutProfileView)
        layoutAuthForm = findViewById(R.id.layoutAuthForm)
        tvProfileName = findViewById(R.id.tvProfileName)
        tvProfileEmail = findViewById(R.id.tvProfileEmail)
        btnLogout = findViewById(R.id.btnLogout)
        btnDeleteAccount = findViewById(R.id.btnDeleteAccount)

        val btnCheckAppUpdates = findViewById<Button>(R.id.btnCheckAppUpdates)
        btnCheckAppUpdates?.setOnClickListener {
            com.ekos.antivirus.engine.AppUpdateManager.checkForUpdate(this, showNoUpdateToast = true)
        }

        etLoginEmail = findViewById(R.id.etLoginEmail)
        etLoginPassword = findViewById(R.id.etLoginPassword)
        btnSubmitLogin = findViewById(R.id.btnSubmitLogin)
        tvToggleRegisterPrompt = findViewById(R.id.tvToggleRegisterPrompt)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        tabBtnLicense.setOnClickListener {
            sectionLicense.visibility = View.VISIBLE
            sectionAuth.visibility = View.GONE
            tabBtnLicense.background = ContextCompat.getDrawable(this, R.drawable.bg_button_primary)
            tabBtnLicense.setTextColor(ContextCompat.getColor(this, R.color.white))
            tabBtnAuth.setBackgroundColor(0)
            tabBtnAuth.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
        }

        tabBtnAuth.setOnClickListener {
            sectionLicense.visibility = View.GONE
            sectionAuth.visibility = View.VISIBLE
            tabBtnAuth.background = ContextCompat.getDrawable(this, R.drawable.bg_button_primary)
            tabBtnAuth.setTextColor(ContextCompat.getColor(this, R.color.white))
            tabBtnLicense.setBackgroundColor(0)
            tabBtnLicense.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
        }

        btnApplyProfileLicense.setOnClickListener {
            val code = etProfileLicenseCode.text.toString().trim()
            if (code.isNotBlank()) {
                val isPrem = code.startsWith("EKOS-PREM", ignoreCase = true) || code.contains("PREM", ignoreCase = true)
                val tierName = if (isPrem) "EKOS Kurumsal Premium" else "EKOS Pro"

                val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("license_tier", tierName)
                    .putString("license_key", code)
                    .apply()

                EkosApiClient.customApiKey = code
                updateAccountState()
                Toast.makeText(this, "Lisans başarıyla aktifleştirildi.", Toast.LENGTH_SHORT).show()
                etProfileLicenseCode.text.clear()
            } else {
                Toast.makeText(this, "Lütfen geçerli bir lisans kodu giriniz.", Toast.LENGTH_SHORT).show()
            }
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

        btnLogout.setOnClickListener {
            MaterialAlertDialogBuilder(this)
                .setTitle("Oturumu Kapat")
                .setMessage("Hesabınızdan çıkış yapmak istediğinize emin misiniz?")
                .setPositiveButton("Çıkış Yap") { _, _ ->
                    val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
                    prefs.edit().clear().apply()
                    EkosApiClient.authToken = null
                    EkosApiClient.customApiKey = null
                    updateAccountState()
                    Toast.makeText(this, "Oturum başarıyla kapatıldı.", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Vazgeç", null)
                .show()
        }

        btnDeleteAccount.setOnClickListener {
            val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
            val email = prefs.getString("user_email", null) ?: "kullanici@ekoscst.com"
            val token = prefs.getString("auth_token", null)

            MaterialAlertDialogBuilder(this)
                .setTitle("Hesabı Kalıcı Olarak Sil")
                .setMessage("Bu işlem geri alınamaz. Hesabınız, kayıtlı lisanslarınız ve bulut eşleme verileriniz kalıcı olarak silinecektir. Devam etmek istiyor musunuz?")
                .setPositiveButton("Hesabı Sil") { _, _ ->
                    btnDeleteAccount.isEnabled = false
                    btnDeleteAccount.text = "Hesap Siliniyor..."

                    lifecycleScope.launch {
                        val res = EkosApiClient.deleteAccount(email, token)
                        prefs.edit().clear().apply()
                        EkosApiClient.authToken = null
                        EkosApiClient.customApiKey = null
                        updateAccountState()
                        btnDeleteAccount.isEnabled = true
                        btnDeleteAccount.text = "Hesabı Kalıcı Olarak Sil"
                        Toast.makeText(this@AccountActivity, res.message ?: "Hesabınız başarıyla silindi.", Toast.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton("Vazgeç", null)
                .show()
        }

        tvToggleRegisterPrompt.setOnClickListener {
            Toast.makeText(this, "Yeni hesap oluşturmak için web panelimizi (ekoscst.com) ziyaret edebilirsiniz.", Toast.LENGTH_LONG).show()
        }
    }

    private fun updateAccountState() {
        val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
        val token = prefs.getString("auth_token", null)
        val email = prefs.getString("user_email", null)
        val name = prefs.getString("user_name", null)
        val tier = prefs.getString("license_tier", "Standart Mobil") ?: "Standart Mobil"
        val licenseKey = prefs.getString("license_key", null)

        val isPremium = tier.contains("Prem", ignoreCase = true) || tier.contains("Kurumsal", ignoreCase = true) || (licenseKey != null && licenseKey.contains("PREM", ignoreCase = true))

        // Update Digital Membership Card
        if (isPremium) {
            tvMembershipTierBadge.text = "PREMIUM"
            tvMembershipTierBadge.setTextColor(ContextCompat.getColor(this, R.color.accent_emerald_light))
            cardDigitalMembership.strokeColor = ContextCompat.getColor(this, R.color.accent_emerald)
        } else {
            tvMembershipTierBadge.text = "STANDART"
            tvMembershipTierBadge.setTextColor(ContextCompat.getColor(this, R.color.text_subtle))
            cardDigitalMembership.strokeColor = ContextCompat.getColor(this, R.color.border_hover)
        }

        tvCardUserName.text = name ?: if (licenseKey != null) "Lisanslı Kullanıcı" else "Misafir Kullanıcı"
        tvCardUserEmail.text = email ?: if (licenseKey != null) "Yerel Cihaz Koruması Aktif" else "Oturum Açılmadı"
        tvCardLicenseKey.text = licenseKey ?: "LİSANS BAĞLANMADI"
        tvCardSyncStatus.text = if (token != null) "BULUT EŞLENDİ" else if (licenseKey != null) "AKTİF" else "STANDART"

        // Auth Section visibility
        if (token != null && email != null) {
            layoutProfileView.visibility = View.VISIBLE
            layoutAuthForm.visibility = View.GONE
            tvProfileName.text = name ?: "EKOS Kullanıcısı"
            tvProfileEmail.text = email
        } else {
            layoutProfileView.visibility = View.GONE
            layoutAuthForm.visibility = View.VISIBLE
        }
    }

    private fun performLogin(email: String, pass: String) {
        btnSubmitLogin.isEnabled = false
        btnSubmitLogin.text = "Giriş Yapılıyor..."

        lifecycleScope.launch {
            val res = EkosApiClient.login(email, pass, this@AccountActivity)
            btnSubmitLogin.isEnabled = true
            btnSubmitLogin.text = "Giriş Yap"

            if (res.success && res.token != null) {
                val prefs = getSharedPreferences("EKOS_MOBILE_PREFS", Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("auth_token", res.token)
                    .putString("user_email", res.user?.email ?: email)
                    .putString("user_name", res.user?.fullName ?: "EKOS Kullanıcısı")
                    .putString("license_tier", res.user?.licenseTier ?: "EKOS Standart")
                    .apply()

                Toast.makeText(this@AccountActivity, "Giriş başarılı.", Toast.LENGTH_SHORT).show()
                updateAccountState()
            } else {
                Toast.makeText(this@AccountActivity, "Hata: ${res.error ?: "Giriş yapılamadı."}", Toast.LENGTH_LONG).show()
            }
        }
    }
}
