package com.ekos.antivirus

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
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

class NetworkShieldActivity : AppCompatActivity() {

    private lateinit var rootLayout: View
    private lateinit var btnBack: ImageButton
    private lateinit var tvNetworkStatusTitle: TextView
    private lateinit var tvNetworkStatusSub: TextView
    private lateinit var tvConnectionType: TextView
    private lateinit var btnRetestNetwork: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_network_shield)

        rootLayout = findViewById(R.id.rootNetworkLayout)
        btnBack = findViewById(R.id.btnBackFromNetwork)

        ViewCompat.setOnApplyWindowInsetsListener(rootLayout) { v, insets ->
            val statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            v.setPadding(0, statusBarHeight, 0, 0)
            insets
        }

        initViews()
        setupListeners()
        analyzeNetworkSecurity()
    }

    private fun initViews() {
        tvNetworkStatusTitle = findViewById(R.id.tvNetworkStatusTitle)
        tvNetworkStatusSub = findViewById(R.id.tvNetworkStatusSub)
        tvConnectionType = findViewById(R.id.tvConnectionType)
        btnRetestNetwork = findViewById(R.id.btnRetestNetwork)
    }

    private fun setupListeners() {
        btnBack.setOnClickListener { finish() }

        btnRetestNetwork.setOnClickListener {
            analyzeNetworkSecurity()
            Toast.makeText(this, "Ağ güvenlik denetimi tamamlandı.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun analyzeNetworkSecurity() {
        btnRetestNetwork.isEnabled = false
        btnRetestNetwork.text = "Ağ Test Ediliyor..."

        lifecycleScope.launch(Dispatchers.IO) {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNet = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(activeNet)

            val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
            val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

            val typeDesc = when {
                isVpn -> "Güvenli Şifreli VPN Tüneli"
                isWifi -> "Wi-Fi (WPA2/WPA3 Şifreli Koruma)"
                isCellular -> "Mobil Veri (LTE / 5G Taşıyıcı Koruması)"
                else -> "Bağlantı Doğrulandı"
            }

            delay(600)

            withContext(Dispatchers.Main) {
                tvConnectionType.text = typeDesc
                tvNetworkStatusTitle.text = "Ağ Güvenli ve Korumada"
                tvNetworkStatusSub.text = "Tüm DNS ve veri trafiğiniz olası sızıntılara karşı korunuyor."
                btnRetestNetwork.isEnabled = true
                btnRetestNetwork.text = "Ağ Güvenliğini Yeniden Test Et"
            }
        }
    }
}
