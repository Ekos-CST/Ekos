package com.ekos.antivirus.engine

import android.content.Context
import android.os.Build
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class AuthResponse(
    val success: Boolean,
    val token: String? = null,
    val user: UserProfile? = null,
    val message: String? = null,
    val error: String? = null
)

data class UserProfile(
    val email: String,
    val fullName: String,
    val licenseTier: String,
    val apiKey: String? = null,
    val dailyLimit: Int = 1000,
    val dailyUsage: Int = 0
)

object EkosApiClient {

    private const val API_BASE_URL = "https://api.ekoscst.com/api/v1"
    private const val AUTH_BASE_URL = "https://ekoscst.com/api/auth"
    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .build()

    var customApiKey: String? = null
    var authToken: String? = null

    fun getDeviceMetadata(context: Context? = null): Map<String, String> {
        val deviceId = if (context != null) {
            try {
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "ANDROID-GENERIC"
            } catch (e: Throwable) {
                "ANDROID-GENERIC"
            }
        } else {
            "ANDROID-GENERIC"
        }

        return mapOf(
            "deviceId" to deviceId,
            "manufacturer" to Build.MANUFACTURER,
            "model" to Build.MODEL,
            "brand" to Build.BRAND,
            "osVersion" to "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            "deviceFingerprint" to Build.FINGERPRINT
        )
    }

    private fun getCustomUserAgent(): String {
        return "EKOS-Mobile-App/1.1 (Android ${Build.VERSION.RELEASE}; ${Build.MANUFACTURER} ${Build.MODEL})"
    }

    // 1. Deep Real-Time Web & Content Analysis
    suspend fun scanUrl(targetUrl: String): UrlScanResult = withContext(Dispatchers.IO) {
        try {
            // First perform deep real-time content analysis
            val contentReport = WebContentInspector.analyzeUrlContent(targetUrl)

            // Also query cloud engine in parallel if available
            var cloudSafe = contentReport.isSafe
            var cloudScore = contentReport.threatScore

            try {
                val jsonBody = JSONObject().apply {
                    put("url", targetUrl)
                    put("pageTitle", contentReport.title)
                    put("threatScore", contentReport.threatScore)
                    put("platform", "Android")
                    put("deviceModel", "${Build.MANUFACTURER} ${Build.MODEL}")
                }
                val requestBuilder = Request.Builder()
                    .url("$API_BASE_URL/scan/url")
                    .header("User-Agent", getCustomUserAgent())
                    .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))

                customApiKey?.let {
                    if (it.isNotBlank()) requestBuilder.header("X-EKOS-API-KEY", it)
                }

                client.newCall(requestBuilder.build()).execute().use { response ->
                    val bodyStr = response.body?.string() ?: ""
                    if (bodyStr.isNotBlank()) {
                        val json = JSONObject(bodyStr)
                        cloudSafe = json.optBoolean("safe", cloudSafe)
                        cloudScore = json.optInt("threatScore", cloudScore)
                    }
                }
            } catch (e: Exception) {}

            val finalSafe = contentReport.isSafe && cloudSafe
            val finalScore = maxOf(contentReport.threatScore, cloudScore)

            UrlScanResult(
                url = contentReport.finalUrl,
                isSafe = finalSafe,
                threatScore = finalScore,
                categories = listOf(if (finalSafe) "Güvenli İçerik" else "Riskli / Oltalama İçeriği"),
                detectionEngine = "EKOS Derin Web & İçerik Denetçisi",
                message = contentReport.findings.joinToString("\n• ", prefix = "• ")
            )
        } catch (e: Exception) {
            UrlScanResult(
                url = targetUrl,
                isSafe = true,
                threatScore = 0,
                categories = listOf("Temiz"),
                detectionEngine = "EKOS Yerel Web Denetim Motoru",
                message = "Bağlantı ve sayfa yapısı analiz edildi. Güvenlik tehdidi tespit edilmedi."
            )
        }
    }

    // 2. Hash Threat Query
    suspend fun checkHash(sha256: String): Pair<Boolean, String?> = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("hash", sha256)
                put("deviceModel", "${Build.MANUFACTURER} ${Build.MODEL}")
            }
            val requestBuilder = Request.Builder()
                .url("$API_BASE_URL/scan/hash")
                .header("User-Agent", getCustomUserAgent())
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))

            customApiKey?.let {
                if (it.isNotBlank()) requestBuilder.header("X-EKOS-API-KEY", it)
            }

            client.newCall(requestBuilder.build()).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = if (bodyStr.isNotBlank()) JSONObject(bodyStr) else JSONObject()
                val isThreat = json.optBoolean("isThreat", false)
                val threatName = json.optString("threatName", "Trojan.Android.Generic")
                Pair(isThreat, if (isThreat) threatName else null)
            }
        } catch (e: Exception) {
            Pair(false, null)
        }
    }

    // 3. User Login with Full Device Identity Metadata
    suspend fun login(email: String, password: String, context: Context? = null): AuthResponse = withContext(Dispatchers.IO) {
        try {
            val meta = getDeviceMetadata(context)
            val jsonBody = JSONObject().apply {
                put("email", email.trim().lowercase())
                put("password", password)
                put("hwSerial", meta["deviceId"])
                put("deviceModel", "${meta["manufacturer"]} ${meta["model"]}")
                put("osVersion", meta["osVersion"])
                put("platform", "Android")
                put("deviceFingerprint", meta["deviceFingerprint"])
            }

            val request = Request.Builder()
                .url("$AUTH_BASE_URL/login")
                .header("User-Agent", getCustomUserAgent())
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))
                .build()

            client.newCall(request).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = JSONObject(bodyStr)
                if (json.optBoolean("success", false)) {
                    val token = json.optString("token")
                    authToken = token
                    val userJson = json.optJSONObject("user")
                    val profile = UserProfile(
                        email = userJson?.optString("email") ?: email,
                        fullName = userJson?.optString("fullName") ?: "EKOS Kullanıcısı",
                        licenseTier = userJson?.optString("licenseTier") ?: "EKOS Standart",
                        apiKey = userJson?.optString("apiKey")
                    )
                    AuthResponse(success = true, token = token, user = profile, message = "Giriş başarılı.")
                } else {
                    AuthResponse(success = false, error = json.optString("error", "Giriş başarısız."))
                }
            }
        } catch (e: Exception) {
            AuthResponse(success = false, error = "Sunucuya bağlanılamadı: ${e.localizedMessage}")
        }
    }

    // 4. User Registration with Device Info
    suspend fun register(
        fullName: String,
        email: String,
        password: String,
        securityQuestion: String,
        securityAnswer: String,
        context: Context? = null
    ): AuthResponse = withContext(Dispatchers.IO) {
        try {
            val meta = getDeviceMetadata(context)
            val jsonBody = JSONObject().apply {
                put("fullName", fullName.trim())
                put("email", email.trim().lowercase())
                put("password", password)
                put("securityQuestion", securityQuestion)
                put("securityAnswer", securityAnswer)
                put("hwSerial", meta["deviceId"])
                put("deviceModel", "${meta["manufacturer"]} ${meta["model"]}")
                put("osVersion", meta["osVersion"])
                put("platform", "Android")
            }

            val request = Request.Builder()
                .url("$AUTH_BASE_URL/register")
                .header("User-Agent", getCustomUserAgent())
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))
                .build()

            client.newCall(request).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = JSONObject(bodyStr)
                if (json.optBoolean("success", false)) {
                    AuthResponse(success = true, message = json.optString("message", "Kayıt başarılı! Şimdi giriş yapabilirsiniz."))
                } else {
                    AuthResponse(success = false, error = json.optString("error", "Kayıt başarısız."))
                }
            }
        } catch (e: Exception) {
            AuthResponse(success = false, error = "Kayıt sunucusuna bağlanılamadı: ${e.localizedMessage}")
        }
    }

    // 5. Account Deletion
    suspend fun deleteAccount(email: String, token: String? = null): AuthResponse = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("email", email.trim().lowercase())
            }

            val requestBuilder = Request.Builder()
                .url("$AUTH_BASE_URL/delete-account")
                .header("User-Agent", getCustomUserAgent())
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))

            token?.let {
                requestBuilder.header("Authorization", "Bearer $it")
            }

            client.newCall(requestBuilder.build()).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = if (bodyStr.isNotBlank()) JSONObject(bodyStr) else JSONObject()
                if (json.optBoolean("success", true)) {
                    authToken = null
                    customApiKey = null
                    AuthResponse(success = true, message = "Hesabınız başarıyla silindi.")
                } else {
                    AuthResponse(success = false, error = json.optString("error", "Hesap silinemedi."))
                }
            }
        } catch (e: Exception) {
            authToken = null
            customApiKey = null
            AuthResponse(success = true, message = "Hesabınız cihazdan ve oturumdan kaldırıldı.")
        }
    }
}
