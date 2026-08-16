package com.ekos.antivirus.engine

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

    // 1. URL Analysis
    suspend fun scanUrl(targetUrl: String): UrlScanResult = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("url", targetUrl)
            }
            val requestBuilder = Request.Builder()
                .url("$API_BASE_URL/scan/url")
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))

            customApiKey?.let {
                if (it.isNotBlank()) requestBuilder.header("X-EKOS-API-KEY", it)
            }

            client.newCall(requestBuilder.build()).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = if (bodyStr.isNotBlank()) JSONObject(bodyStr) else JSONObject()
                
                val safe = json.optBoolean("safe", true)
                val score = json.optInt("threatScore", if (safe) 0 else 85)
                val msg = json.optString("analysis", if (safe) "Bağlantı güvenli ve doğrulanmış." else "Oltalama veya şüpheli içerik tespit edildi.")
                
                UrlScanResult(
                    url = targetUrl,
                    isSafe = safe,
                    threatScore = score,
                    categories = listOf(json.optString("verdict", if (safe) "Clean" else "Suspicious")),
                    detectionEngine = "EKOS Derin Sinirsel Bulut Motoru",
                    message = msg
                )
            }
        } catch (e: Exception) {
            val lower = targetUrl.lowercase()
            val isPhish = lower.contains("login") && (lower.contains("gift") || lower.contains("free") || lower.contains("verify-account"))
            UrlScanResult(
                url = targetUrl,
                isSafe = !isPhish,
                threatScore = if (isPhish) 90 else 0,
                categories = listOf(if (isPhish) "Yerel Sezgisel Oltalama" else "Clean"),
                detectionEngine = "EKOS Yerel Kural Motoru",
                message = if (isPhish) "Şüpheli oltalama yapısı tespit edildi." else "Bağlantı analizi tamamlandı."
            )
        }
    }

    // 2. Hash Threat Query
    suspend fun checkHash(sha256: String): Pair<Boolean, String?> = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("hash", sha256)
            }
            val requestBuilder = Request.Builder()
                .url("$API_BASE_URL/scan/hash")
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

    // 3. Payload & Script Analysis
    suspend fun analyzePayload(text: String): ClipboardAnalysisResult = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("payload", text)
            }
            val requestBuilder = Request.Builder()
                .url("$API_BASE_URL/analyze/payload")
                .post(jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE))

            client.newCall(requestBuilder.build()).execute().use { response ->
                val bodyStr = response.body?.string() ?: ""
                val json = if (bodyStr.isNotBlank()) JSONObject(bodyStr) else JSONObject()
                val isMalicious = json.optBoolean("isMalicious", false)
                val threatType = json.optString("threatType", "Suspicious Script Payload")
                val explanation = json.optString("explanation", "Panoda şüpheli komut yürütme deseni tespit edildi.")

                ClipboardAnalysisResult(
                    content = text,
                    isSuspicious = isMalicious,
                    threatType = if (isMalicious) threatType else null,
                    explanation = if (isMalicious) explanation else "Pano içeriği temiz."
                )
            }
        } catch (e: Exception) {
            val isSusp = text.contains("powershell -enc", ignoreCase = true) ||
                    text.contains("cmd.exe /c", ignoreCase = true) ||
                    text.contains("certutil -urlcache", ignoreCase = true)
            ClipboardAnalysisResult(
                content = text,
                isSuspicious = isSusp,
                threatType = if (isSusp) "Local.CommandInjection" else null,
                explanation = if (isSusp) "Zararlı komut çalıştırma kalıbı bulundu." else "İçerik temiz."
            )
        }
    }

    // 4. User Login
    suspend fun login(email: String, password: String): AuthResponse = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("email", email.trim().toLowerCase())
                put("password", password)
                put("hwSerial", "ANDROID-REALME")
            }

            val request = Request.Builder()
                .url("$AUTH_BASE_URL/login")
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

    // 5. User Registration
    suspend fun register(
        fullName: String,
        email: String,
        password: String,
        securityQuestion: String,
        securityAnswer: String
    ): AuthResponse = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("fullName", fullName.trim())
                put("email", email.trim().toLowerCase())
                put("password", password)
                put("securityQuestion", securityQuestion)
                put("securityAnswer", securityAnswer)
            }

            val request = Request.Builder()
                .url("$AUTH_BASE_URL/register")
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
}
