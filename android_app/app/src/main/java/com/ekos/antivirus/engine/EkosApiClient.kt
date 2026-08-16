package com.ekos.antivirus.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object EkosApiClient {

    private const val BASE_URL = "https://api.ekoscst.com/api/v1"
    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    var customApiKey: String? = null

    suspend fun scanUrl(targetUrl: String): UrlScanResult = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("url", targetUrl)
            }
            val requestBuilder = Request.Builder()
                .url("$BASE_URL/scan/url")
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
                    detectionEngine = "EKOS Deep Neural & Heuristic Cloud Engine",
                    message = msg
                )
            }
        } catch (e: Exception) {
            // Local fallback heuristic
            val lower = targetUrl.lowercase()
            val isPhish = lower.contains("login") && (lower.contains("gift") || lower.contains("free") || lower.contains("verify-account"))
            UrlScanResult(
                url = targetUrl,
                isSafe = !isPhish,
                threatScore = if (isPhish) 90 else 0,
                categories = listOf(if (isPhish) "Local-Heuristic-Phishing" else "Clean"),
                detectionEngine = "EKOS Local Offline Heuristic",
                message = if (isPhish) "Şüpheli oltalama yapısı tespit edildi." else "Bağlantı analizi tamamlandı."
            )
        }
    }

    suspend fun checkHash(sha256: String): Pair<Boolean, String?> = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("hash", sha256)
            }
            val requestBuilder = Request.Builder()
                .url("$BASE_URL/scan/hash")
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

    suspend fun analyzePayload(text: String): ClipboardAnalysisResult = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("payload", text)
            }
            val requestBuilder = Request.Builder()
                .url("$BASE_URL/analyze/payload")
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
            // Local fallback
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
}
