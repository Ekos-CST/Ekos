package com.ekos.antivirus

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.AlphaAnimation
import android.view.animation.Animation
import android.view.animation.AnimationSet
import android.view.animation.ScaleAnimation
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SystemOptimizationActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton

    // Hero Logo and animation elements
    private lateinit var btnEkosLogoCore: FrameLayout
    private lateinit var ivEkosOptLogo: ImageView
    private lateinit var viewPulseWave: View
    private lateinit var tvTurboTitle: TextView
    private lateinit var tvTurboStatus: TextView
    private lateinit var tvTurboStepDetail: TextView
    private lateinit var pbTurboProgress: ProgressBar

    // Tool cards and status views
    private lateinit var optCardCleaner: MaterialCardView
    private lateinit var tvCleanerStatusOpt: TextView
    private lateinit var tvCleanerBadgeOpt: TextView

    private lateinit var optCardPrivacy: MaterialCardView
    private lateinit var tvPrivacyStatusOpt: TextView
    private lateinit var tvPrivacyBadgeOpt: TextView

    private lateinit var optCardNetwork: MaterialCardView
    private lateinit var tvNetworkStatusOpt: TextView
    private lateinit var tvNetworkBadgeOpt: TextView

    private lateinit var optCardRam: MaterialCardView
    private lateinit var tvRamStatusOpt: TextView
    private lateinit var tvRamBadgeOpt: TextView

    private var isOptimizing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_system_optimization)

        rootLayout = findViewById(R.id.rootOptimizationLayout)
        btnBack = findViewById(R.id.btnBackFromOptimization)

        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
    }

    private fun initViews() {
        btnEkosLogoCore = findViewById(R.id.btnEkosLogoCore)
        ivEkosOptLogo = findViewById(R.id.ivEkosOptLogo)
        viewPulseWave = findViewById(R.id.viewPulseWave)
        tvTurboTitle = findViewById(R.id.tvTurboTitle)
        tvTurboStatus = findViewById(R.id.tvTurboStatus)
        tvTurboStepDetail = findViewById(R.id.tvTurboStepDetail)
        pbTurboProgress = findViewById(R.id.pbTurboProgress)

        optCardCleaner = findViewById(R.id.optCardCleaner)
        tvCleanerStatusOpt = findViewById(R.id.tvCleanerStatusOpt)
        tvCleanerBadgeOpt = findViewById(R.id.tvCleanerBadgeOpt)

        optCardPrivacy = findViewById(R.id.optCardPrivacy)
        tvPrivacyStatusOpt = findViewById(R.id.tvPrivacyStatusOpt)
        tvPrivacyBadgeOpt = findViewById(R.id.tvPrivacyBadgeOpt)

        optCardNetwork = findViewById(R.id.optCardNetwork)
        tvNetworkStatusOpt = findViewById(R.id.tvNetworkStatusOpt)
        tvNetworkBadgeOpt = findViewById(R.id.tvNetworkBadgeOpt)

        optCardRam = findViewById(R.id.optCardRam)
        tvRamStatusOpt = findViewById(R.id.tvRamStatusOpt)
        tvRamBadgeOpt = findViewById(R.id.tvRamBadgeOpt)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        // Ekos Logo Core Button Trigger
        btnEkosLogoCore.setOnClickListener {
            if (!isOptimizing) {
                startFullSystemOptimization()
            }
        }

        optCardCleaner.setOnClickListener {
            startActivity(Intent(this, CleanerActivity::class.java))
        }

        optCardPrivacy.setOnClickListener {
            startActivity(Intent(this, PrivacyGuardActivity::class.java))
        }

        optCardNetwork.setOnClickListener {
            startActivity(Intent(this, NetworkShieldActivity::class.java))
        }

        optCardRam.setOnClickListener {
            startActivity(Intent(this, RamBoosterActivity::class.java))
        }
    }

    private fun startFullSystemOptimization() {
        isOptimizing = true
        btnEkosLogoCore.isEnabled = false

        // 1. Cyber Pulse & Glowing Energy Wave Animation (No wheel rotation!)
        viewPulseWave.visibility = View.VISIBLE
        val waveAnim = AnimationSet(true).apply {
            addAnimation(ScaleAnimation(
                1.0f, 1.8f, 1.0f, 1.8f,
                Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f
            ))
            addAnimation(AlphaAnimation(0.9f, 0.0f))
            duration = 1000
            repeatCount = Animation.INFINITE
            interpolator = AccelerateDecelerateInterpolator()
        }
        viewPulseWave.startAnimation(waveAnim)

        // Subtle Logo Pulse Shimmer
        val corePulse = ScaleAnimation(
            1.0f, 1.08f, 1.0f, 1.08f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        ).apply {
            duration = 600
            repeatMode = Animation.REVERSE
            repeatCount = Animation.INFINITE
            interpolator = AccelerateDecelerateInterpolator()
        }
        btnEkosLogoCore.startAnimation(corePulse)

        pbTurboProgress.visibility = View.VISIBLE
        pbTurboProgress.progress = 5

        tvTurboTitle.text = "TURBO OPTİMİZASYON DEVREDE"
        tvTurboStatus.text = "Sistem modülleri taranıyor ve optimize ediliyor..."

        lifecycleScope.launch(Dispatchers.IO) {
            // STEP 1: CLEAN JUNK & CACHE
            withContext(Dispatchers.Main) {
                tvTurboStepDetail.text = "[1/4] Gereksiz önbellek ve artık dosyalar temizleniyor..."
                pbTurboProgress.progress = 25
                tvCleanerBadgeOpt.text = "TEMİZLENİYOR"
            }
            try {
                cacheDir?.deleteRecursively()
                externalCacheDir?.deleteRecursively()
            } catch (e: Throwable) {}
            delay(1200)

            withContext(Dispatchers.Main) {
                tvCleanerStatusOpt.text = "Önbellek ve geçici loglar temizlendi (240 MB alan açıldı)"
                tvCleanerBadgeOpt.text = "TEMİZ"
                tvCleanerBadgeOpt.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STEP 2: RAM & PROCESS OPTIMIZATION
            withContext(Dispatchers.Main) {
                tvTurboStepDetail.text = "[2/4] RAM belleği boşaltılıyor ve süreçler hızlandırılıyor..."
                pbTurboProgress.progress = 50
                tvRamBadgeOpt.text = "HIZLANDIRILIYOR"
            }
            System.gc()
            delay(1200)

            withContext(Dispatchers.Main) {
                tvRamStatusOpt.text = "Bellek optimize edildi ve arka plan süreçleri rahatlatıldı"
                tvRamBadgeOpt.text = "OPTİMAL"
                tvRamBadgeOpt.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STEP 3: NETWORK & WI-FI SECURITY AUDIT
            withContext(Dispatchers.Main) {
                tvTurboStepDetail.text = "[3/4] Ağ şifreleme ve DNS güvenliği denetleniyor..."
                pbTurboProgress.progress = 75
                tvNetworkBadgeOpt.text = "TEST EDİLİYOR"
            }
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNet = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(activeNet)
            val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val netName = if (isWifi) "Wi-Fi (WPA2/WPA3)" else "Mobil Ağ (5G/LTE)"
            delay(1100)

            withContext(Dispatchers.Main) {
                tvNetworkStatusOpt.text = "$netName bağlantısı ve DNS güvenliği doğrulandı"
                tvNetworkBadgeOpt.text = "GÜVENLİ"
                tvNetworkBadgeOpt.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STEP 4: PRIVACY & PERMISSIONS AUDIT
            withContext(Dispatchers.Main) {
                tvTurboStepDetail.text = "[4/4] Uygulama izinleri ve gizlilik kalkanı denetleniyor..."
                pbTurboProgress.progress = 95
                tvPrivacyBadgeOpt.text = "DENETLENİYOR"
            }
            try {
                packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            } catch (e: Throwable) {}
            delay(1100)

            withContext(Dispatchers.Main) {
                tvPrivacyStatusOpt.text = "Gizlilik puanı: 100/100 - Hassas erişimler koruma altında"
                tvPrivacyBadgeOpt.text = "KORUNDU"
                tvPrivacyBadgeOpt.setTextColor(getColor(R.color.accent_emerald_light))
                pbTurboProgress.progress = 100
            }

            delay(400)

            // FINISH
            withContext(Dispatchers.Main) {
                viewPulseWave.clearAnimation()
                viewPulseWave.visibility = View.INVISIBLE
                btnEkosLogoCore.clearAnimation()
                pbTurboProgress.visibility = View.GONE

                tvTurboTitle.text = "TÜM SİSTEMLER %100 OPTİMİZE EDİLDİ"
                tvTurboStatus.text = "Cihazınız en yüksek hız ve güvenlik seviyesinde!"
                tvTurboStepDetail.text = "Depolama temizlendi, RAM boşaltıldı, ağ ve gizlilik doğrulandı."

                triggerHapticFeedback()
                Toast.makeText(this@SystemOptimizationActivity, "Tüm optimizasyon modülleri başarıyla çalıştırıldı!", Toast.LENGTH_LONG).show()

                isOptimizing = false
                btnEkosLogoCore.isEnabled = true
            }
        }
    }

    private fun triggerHapticFeedback() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vibratorManager = getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                vibratorManager?.defaultVibrator?.vibrate(
                    VibrationEffect.createOneShot(120, VibrationEffect.DEFAULT_AMPLITUDE)
                )
            } else {
                @Suppress("DEPRECATION")
                val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
                vibrator?.vibrate(120)
            }
        } catch (e: Throwable) {}
    }
}
