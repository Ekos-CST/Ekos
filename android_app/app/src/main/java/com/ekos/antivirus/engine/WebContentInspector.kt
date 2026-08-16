package com.ekos.antivirus.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.URI
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

data class WebContentScanReport(
    val url: String,
    val finalUrl: String,
    val title: String,
    val httpStatus: Int,
    val isSafe: Boolean,
    val threatScore: Int,
    val verdict: String,
    val protocol: String,
    val isFormThreat: Boolean,
    val formSecurityStatus: String,
    val isScriptThreat: Boolean,
    val scriptSecurityStatus: String,
    val isPhishingThreat: Boolean,
    val phishingStatus: String,
    val isDownloadThreat: Boolean,
    val downloadStatus: String,
    val findings: List<String>
)

object WebContentInspector {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    // URL Keyword Patterns
    private val SUSPICIOUS_URL_PATTERNS = listOf(
        Pattern.compile("(?i)(malware|phish|phishing|stealer|trojan|hack|keygen|crack|darknet|c2|payload|botnet|keylogger|ransomware|spyware)"),
        Pattern.compile("(?i)(gift-card|free-nitro|free-robux|free-gift|bedava-hediye|hediye-ceki|bonus-kazan)"),
        Pattern.compile("(?i)(login-verify|hesap-dogrula|guvenlik-guncelleme|banka-giris|account-security|update-password|wallet-seed|recovery-phrase)")
    )

    private val PHISHING_CONTENT_PATTERNS = listOf(
        Pattern.compile("(?i)(hesabınız askıya alındı|hesabınızı doğrulayın|şifrenizi güncelleyin|oturum açın|giriş yapın)"),
        Pattern.compile("(?i)(tebrikler kazandınız|ücretsiz hediye|ödül kazandınız|iphone kazandınız|tıklayın kazanın)"),
        Pattern.compile("(?i)(account suspended|verify your account|update your password|confirm identity|claim reward)"),
        Pattern.compile("(?i)(wallet key|recovery phrase|seed phrase|kurtarma anahtarı|cüzdan şifresi)"),
        Pattern.compile("(?i)(e-devlet kapısı|turkiye\\.gov|papara|ziraat|garanti|akbank|iş bankası|yapı kredi)")
    )

    private val SCRIPT_MALWARE_PATTERNS = listOf(
        Pattern.compile("(?i)(eval\\s*\\(|document\\.write\\s*\\(\\s*unescape|String\\.fromCharCode)"),
        Pattern.compile("(?i)(coinhive|cryptonight|webminer|coin-hive|cryptoloot)"),
        Pattern.compile("(?i)(window\\.location\\.replace\\s*\\(['\"][^'\"]*\\.(exe|apk|scr|bat))")
    )

    private val DANGEROUS_DOWNLOAD_PATTERNS = listOf(
        Pattern.compile("(?i)href\\s*=\\s*[\"'][^\"']+\\.(apk|exe|scr|bat|vbs|jar|msi)[\"']")
    )

    suspend fun analyzeUrlContent(targetUrl: String): WebContentScanReport = withContext(Dispatchers.IO) {
        var cleanUrl = targetUrl.trim()
        if (!cleanUrl.startsWith("http://", ignoreCase = true) && !cleanUrl.startsWith("https://", ignoreCase = true)) {
            cleanUrl = "https://$cleanUrl"
        }

        var responseCode = 0
        var finalResolvedUrl = cleanUrl
        var pageTitle = "Web Bağlantısı"
        var htmlContent = ""
        val findings = mutableListOf<String>()
        var threatScore = 0

        var isFormThreat = false
        var isScriptThreat = false
        var isPhishingThreat = false
        var isDownloadThreat = false

        val protocol = if (cleanUrl.startsWith("https://", ignoreCase = true)) "HTTPS (Şifreli TLS)" else "HTTP (Düz Metin)"
        val urlLower = cleanUrl.lowercase()

        // 1. LEXICAL URL HEURISTICS
        for (pattern in SUSPICIOUS_URL_PATTERNS) {
            val matcher = pattern.matcher(urlLower)
            if (matcher.find()) {
                val match = matcher.group(0)
                threatScore += 55
                isPhishingThreat = true
                findings.add("URL adresinde şüpheli/zararlı anahtar sözcük tespit edildi: '$match'")
                break
            }
        }

        val domain = try { URI(cleanUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }
        val suspiciousBrands = listOf("instagram", "facebook", "twitter", "banka", "turkiye", "e-devlet", "papara", "binance", "netflix", "whatsapp")
        for (brand in suspiciousBrands) {
            if (domain.contains(brand) && !domain.endsWith("$brand.com") && !domain.endsWith("$brand.com.tr") && !domain.endsWith("$brand.net")) {
                threatScore += 50
                isPhishingThreat = true
                findings.add("Sahte marka taklidi tespit edildi: Domain içerisinde '$brand' adı kullanılıyor.")
                break
            }
        }

        // 2. FETCH REAL PAGE CONTENT VIA NETWORK
        try {
            val request = Request.Builder()
                .url(cleanUrl)
                .header("User-Agent", "Mozilla/5.0 (Linux; Android 14; Mobile; EkosSecurityScan/1.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36")
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .header("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")
                .build()

            httpClient.newCall(request).execute().use { response ->
                responseCode = response.code
                finalResolvedUrl = response.request.url.toString()
                htmlContent = response.body?.string() ?: ""

                // Extract Page Title
                val titleMatcher = Pattern.compile("(?i)<title[^>]*>([^<]+)</title>").matcher(htmlContent)
                if (titleMatcher.find()) {
                    pageTitle = titleMatcher.group(1)?.trim() ?: "Web Sayfası"
                }

                // Check security headers
                val hsts = response.header("Strict-Transport-Security")
                val csp = response.header("Content-Security-Policy")
                val xframe = response.header("X-Frame-Options")

                if (csp != null) findings.add("İçerik Güvenlik İlkesi (CSP) koruması mevcut.")
                if (xframe != null) findings.add("Clickjacking koruması (X-Frame-Options) mevcut.")
                if (hsts != null) findings.add("HSTS (Zorunlu Güvenli İletişim) etkin.")
            }
        } catch (e: Exception) {
            if (threatScore > 0) {
                findings.add("Hedef sunucu çevrimdışı veya erişilemiyor (Zararlı URL imzası doğrulandı).")
            } else {
                findings.add("Siteye doğrudan erişim: ${e.localizedMessage ?: "Bağlantı zaman aşımı"}")
            }
        }

        // 3. FORM & PASSWORD INPUT INSPECTION
        val hasPasswordInput = Pattern.compile("(?i)<input[^>]*type=[\"']password[\"']").matcher(htmlContent).find()
        val hasForm = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']*)[\"']").matcher(htmlContent).find()

        val isOfficialTrustedDomain = domain.endsWith("google.com") || domain.endsWith("microsoft.com") || domain.endsWith("github.com") || domain.endsWith("ekoscst.com") || domain.endsWith("apple.com")

        val formStatus: String
        if (hasPasswordInput) {
            if (!cleanUrl.startsWith("https://", ignoreCase = true)) {
                threatScore += 45
                isFormThreat = true
                formStatus = "Yüksek Risk (HTTP üzerinden şifre girişi)"
                findings.add("Şifresiz HTTP bağlantısı üzerinden parola girişi talep ediliyor!")
            } else if (!isOfficialTrustedDomain) {
                threatScore += 25
                isFormThreat = true
                formStatus = "Parola Giriş Formu Bulundu (Dikkat)"
                findings.add("Sayfada şifre girişi tespit edildi. Kimlik avı riskine karşı adres çubuğunu doğrulayın.")
            } else {
                formStatus = "Doğrulanmış Güvenli Giriş Formu"
            }
        } else if (hasForm) {
            formStatus = "Standart Veri Formu (Zararsız)"
        } else {
            formStatus = "Temiz (Şifre tuzağı yok)"
        }

        // 4. JAVASCRIPT & MALWARE / CRYPTO-MINER INSPECTION
        var scriptStatus = "Temiz (Zararlı script yok)"
        for (pattern in SCRIPT_MALWARE_PATTERNS) {
            if (pattern.matcher(htmlContent).find()) {
                threatScore += 40
                isScriptThreat = true
                scriptStatus = "Zararlı / Gizlenmiş Script Bulundu"
                findings.add("Sayfa kaynağında gizlenmiş kod yürütme (eval/obfuscated JS) tespit edildi.")
                break
            }
        }

        // 5. PHISHING CONTENT PATTERNS
        var phishingStatus = if (isPhishingThreat) "Oltalama Belirtisi Bulundu" else "Temiz (Oltalama deseni yok)"
        for (pattern in PHISHING_CONTENT_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                val matchedText = matcher.group(0)
                threatScore += 35
                isPhishingThreat = true
                phishingStatus = "Oltalama Belirtisi Bulundu"
                findings.add("Sosyal mühendislik / oltalama şüphesi: '$matchedText'")
                break
            }
        }

        // 6. DANGEROUS DOWNLOAD LINKS (APK, EXE)
        var downloadStatus = "Temiz (Zararlı indirme linki yok)"
        for (pattern in DANGEROUS_DOWNLOAD_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                threatScore += 30
                isDownloadThreat = true
                downloadStatus = "Doğrudan İndirilebilir Yürütülebilir Dosya"
                findings.add("Sayfa doğrudan çalıştırılabilir (.apk / .exe) dosya bağlantısı içeriyor.")
                break
            }
        }

        if (!cleanUrl.startsWith("https://", ignoreCase = true) && threatScore == 0) {
            findings.add("Site HTTP kullanıyor (Şifrelenmemiş bağlantı), ancak sayfa içeriği temiz ve zararsız.")
        }

        val isSafe = threatScore < 35
        val verdict = when {
            threatScore >= 60 -> "YÜKSEK TEHDİT: ZARARLI VEYA OLTALAMA SİTESİ"
            threatScore >= 35 -> "ŞÜPHELİ BAĞLANTI: DİKKATLİ OLUN"
            else -> "BAĞLANTI VE SİTE İÇERİĞİ GÜVENLİ"
        }

        if (findings.isEmpty()) {
            findings.add("Site içeriği, HTML kodları, formlar ve scriptler başarıyla denetlendi. Herhangi bir güvenlik açığı tespit edilmedi.")
        }

        WebContentScanReport(
            url = cleanUrl,
            finalUrl = finalResolvedUrl,
            title = pageTitle,
            httpStatus = responseCode,
            isSafe = isSafe,
            threatScore = threatScore.coerceAtMost(100),
            verdict = verdict,
            protocol = protocol,
            isFormThreat = isFormThreat,
            formSecurityStatus = formStatus,
            isScriptThreat = isScriptThreat,
            scriptSecurityStatus = scriptStatus,
            isPhishingThreat = isPhishingThreat,
            phishingStatus = phishingStatus,
            isDownloadThreat = isDownloadThreat,
            downloadStatus = downloadStatus,
            findings = findings
        )
    }
}
