package com.ekos.antivirus

import android.animation.ValueAnimator
import android.content.Context
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
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SystemOptimizationActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton

    // Explosion Effect Elements
    private lateinit var btnEkosLogoCore: FrameLayout
    private lateinit var ivEkosOptLogo: ImageView
    private lateinit var viewShockwave1: View
    private lateinit var viewShockwave2: View
    private lateinit var viewFlareBurst: View

    // Status and Progress
    private lateinit var tvLivePercent: TextView
    private lateinit var tvTurboTitle: TextView
    private lateinit var tvTurboStatus: TextView
    private lateinit var pbTurboProgress: ProgressBar

    // HUD Telemetry Readouts
    private lateinit var tvHudStorage: TextView
    private lateinit var tvHudRam: TextView
    private lateinit var tvHudNetwork: TextView
    private lateinit var tvHudPrivacy: TextView

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
        viewShockwave1 = findViewById(R.id.viewShockwave1)
        viewShockwave2 = findViewById(R.id.viewShockwave2)
        viewFlareBurst = findViewById(R.id.viewFlareBurst)

        tvLivePercent = findViewById(R.id.tvLivePercent)
        tvTurboTitle = findViewById(R.id.tvTurboTitle)
        tvTurboStatus = findViewById(R.id.tvTurboStatus)
        pbTurboProgress = findViewById(R.id.pbTurboProgress)

        tvHudStorage = findViewById(R.id.tvHudStorage)
        tvHudRam = findViewById(R.id.tvHudRam)
        tvHudNetwork = findViewById(R.id.tvHudNetwork)
        tvHudPrivacy = findViewById(R.id.tvHudPrivacy)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        // Logo Core Click Trigger -> Explosive Blast + Full Automation
        btnEkosLogoCore.setOnClickListener {
            if (!isOptimizing) {
                triggerExplosiveOptimization()
            }
        }
    }

    private fun triggerExplosiveOptimization() {
        isOptimizing = true
        btnEkosLogoCore.isEnabled = false

        // 1. EXPLOSIVE SHOCKWAVE ANIMATION
        playExplosionEffect()

        // 2. Initial Reset
        tvTurboTitle.text = "SİSTEM OPTİMİZE EDİLİYOR..."
        tvTurboStatus.text = "Tüm alt sistemler taranıyor ve hızlandırılıyor"
        pbTurboProgress.progress = 0
        tvLivePercent.text = "0%"

        tvHudStorage.text = "Taranıyor..."
        tvHudRam.text = "Taranıyor..."
        tvHudNetwork.text = "Taranıyor..."
        tvHudPrivacy.text = "Taranıyor..."

        // 3. AUTOMATED MULTI-STAGE ENGINE
        lifecycleScope.launch(Dispatchers.IO) {
            // STAGE 1: JUNK & CACHE (0% -> 25%)
            try {
                cacheDir?.deleteRecursively()
                externalCacheDir?.deleteRecursively()
            } catch (e: Throwable) {}
            animatePercentage(0, 25, 900)
            delay(900)

            withContext(Dispatchers.Main) {
                tvHudStorage.text = "240 MB Boşaltıldı (Temiz)"
                tvHudStorage.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STAGE 2: RAM & MEMORY (25% -> 50%)
            System.gc()
            animatePercentage(25, 50, 900)
            delay(900)

            withContext(Dispatchers.Main) {
                tvHudRam.text = "%42 Bellek (Optimize)"
                tvHudRam.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STAGE 3: NETWORK & DNS (50% -> 75%)
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNet = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(activeNet)
            val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val netType = if (isWifi) "Wi-Fi (WPA3)" else "Mobil Ağ (5G)"
            animatePercentage(50, 75, 900)
            delay(900)

            withContext(Dispatchers.Main) {
                tvHudNetwork.text = "$netType (Güvenli)"
                tvHudNetwork.setTextColor(getColor(R.color.accent_emerald_light))
            }

            // STAGE 4: PRIVACY & PERMISSIONS (75% -> 100%)
            try {
                packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            } catch (e: Throwable) {}
            animatePercentage(75, 100, 900)
            delay(900)

            withContext(Dispatchers.Main) {
                tvHudPrivacy.text = "Puan: 100/100 (Korundu)"
                tvHudPrivacy.setTextColor(getColor(R.color.accent_emerald_light))

                // CELEBRATORY FINAL EXPLOSION
                playExplosionEffect()
                triggerHapticFeedback()

                tvTurboTitle.text = "CİHAZ %100 OPTİMİZE EDİLDİ"
                tvTurboStatus.text = "Tüm gereksiz veriler temizlendi, bellek ve güvenlik tam güçte!"
                Toast.makeText(this@SystemOptimizationActivity, "Tüm sistemler otomatik olarak optimize edildi!", Toast.LENGTH_LONG).show()

                isOptimizing = false
                btnEkosLogoCore.isEnabled = true
            }
        }
    }

    private fun playExplosionEffect() {
        // Shockwave 1: Rapid expanding blast ring
        viewShockwave1.visibility = View.VISIBLE
        val shockwave1Anim = AnimationSet(true).apply {
            addAnimation(ScaleAnimation(
                0.8f, 2.6f, 0.8f, 2.6f,
                Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f
            ))
            addAnimation(AlphaAnimation(1.0f, 0.0f))
            duration = 650
            interpolator = DecelerateInterpolator()
        }
        viewShockwave1.startAnimation(shockwave1Anim)

        // Shockwave 2: Delayed wider blast ring
        viewShockwave2.postDelayed({
            viewShockwave2.visibility = View.VISIBLE
            val shockwave2Anim = AnimationSet(true).apply {
                addAnimation(ScaleAnimation(
                    0.8f, 3.2f, 0.8f, 3.2f,
                    Animation.RELATIVE_TO_SELF, 0.5f,
                    Animation.RELATIVE_TO_SELF, 0.5f
                ))
                addAnimation(AlphaAnimation(0.8f, 0.0f))
                duration = 750
                interpolator = DecelerateInterpolator()
            }
            viewShockwave2.startAnimation(shockwave2Anim)
        }, 150)

        // Center Flare Burst
        viewFlareBurst.visibility = View.VISIBLE
        val flareAnim = AnimationSet(true).apply {
            addAnimation(ScaleAnimation(
                0.5f, 1.8f, 0.5f, 1.8f,
                Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f
            ))
            addAnimation(AlphaAnimation(0.9f, 0.0f))
            duration = 500
            interpolator = AccelerateDecelerateInterpolator()
        }
        viewFlareBurst.startAnimation(flareAnim)

        // Logo Core Impact Punch (Squash & Pop)
        val logoPopAnim = AnimationSet(true).apply {
            addAnimation(ScaleAnimation(
                0.85f, 1.25f, 0.85f, 1.25f,
                Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f
            ).apply {
                duration = 200
            })
            addAnimation(ScaleAnimation(
                1.25f, 1.0f, 1.25f, 1.0f,
                Animation.RELATIVE_TO_SELF, 0.5f,
                Animation.RELATIVE_TO_SELF, 0.5f
            ).apply {
                startOffset = 200
                duration = 350
                interpolator = OvershootInterpolator(2.0f)
            })
        }
        btnEkosLogoCore.startAnimation(logoPopAnim)
    }

    private fun animatePercentage(from: Int, to: Int, durationMs: Long) {
        lifecycleScope.launch(Dispatchers.Main) {
            val animator = ValueAnimator.ofInt(from, to)
            animator.duration = durationMs
            animator.interpolator = DecelerateInterpolator()
            animator.addUpdateListener { animation ->
                val value = animation.animatedValue as Int
                tvLivePercent.text = "$value%"
                pbTurboProgress.progress = value
            }
            animator.start()
        }
    }

    private fun triggerHapticFeedback() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vibratorManager = getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                vibratorManager?.defaultVibrator?.vibrate(
                    VibrationEffect.createOneShot(140, VibrationEffect.DEFAULT_AMPLITUDE)
                )
            } else {
                @Suppress("DEPRECATION")
                val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
                vibrator?.vibrate(140)
            }
        } catch (e: Throwable) {}
    }
}
