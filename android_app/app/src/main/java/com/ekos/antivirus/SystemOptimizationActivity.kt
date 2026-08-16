package com.ekos.antivirus

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageButton
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.material.card.MaterialCardView

class SystemOptimizationActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var optCardCleaner: MaterialCardView
    private lateinit var optCardPrivacy: MaterialCardView
    private lateinit var optCardNetwork: MaterialCardView
    private lateinit var optCardRam: MaterialCardView

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
        optCardCleaner = findViewById(R.id.optCardCleaner)
        optCardPrivacy = findViewById(R.id.optCardPrivacy)
        optCardNetwork = findViewById(R.id.optCardNetwork)
        optCardRam = findViewById(R.id.optCardRam)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

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
}
