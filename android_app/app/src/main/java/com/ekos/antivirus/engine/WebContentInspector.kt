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
    val formSecurityStatus: String,
    val scriptSecurityStatus: String,
    val phishingStatus: String,
    val downloadStatus: String,
    val findings: List<String>
)

object WebContentInspector {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    private val PHISHING_PATTERNS = listOf(
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
        var pageTitle = "Web Sayfası"
        var htmlContent = ""
        val findings = mutableListOf<String>()
        var threatScore = 0

        val protocol = if (cleanUrl.startsWith("https://", ignoreCase = true)) "HTTPS (Şifreli TLS)" else "HTTP (Düz Metin)"

        try {
            val request = Request.Builder()
                .url(cleanUrl)
                .header("User-Agent", "Mozilla/5.0 (Linux; Android 14; Mobile; EkosSecurityScan/1.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36")
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

                if (csp != null) findings.add("İçerik Güvenlik İlkesi (CSP) aktif.")
                if (xframe != null) findings.add("Clickjacking koruması (X-Frame-Options) mevcut.")
                if (hsts != null) findings.add("HSTS (Zorunlu Güvenli İletişim) etkin.")
            }
        } catch (e: Exception) {
            // If direct network failed or URL is unreachable
            findings.add("Siteye doğrudan erişim: ${e.localizedMessage ?: "Bağlantı zaman aşımı"}")
        }

        val domain = try { URI(finalResolvedUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }

        // 1. FORM & PASSWORD INPUT INSPECTION
        var formStatus = "Temiz (Şifre veya form tuzağı yok)"
        val hasPasswordInput = Pattern.compile("(?i)<input[^>]*type=[\"']password[\"']").matcher(htmlContent).find()
        val hasForm = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']*)[\"']").matcher(htmlContent).find()

        if (hasPasswordInput) {
            val isOfficialTrustedDomain = domain.endsWith("google.com") || domain.endsWith("microsoft.com") || domain.endsWith("github.com") || domain.endsWith("ekoscst.com") || domain.endsWith("apple.com")
            if (!cleanUrl.startsWith("https://", ignoreCase = true)) {
                threatScore += 45
                formStatus = "Yüksek Risk (HTTP üzerinden şifre girişi)"
                findings.add("Şifresiz HTTP bağlantısı üzerinden parola girişi talep ediliyor!")
            } else if (!isOfficialTrustedDomain) {
                threatScore += 25
                formStatus = "Parola Giriş Formu Bulundu (Dikkat)"
                findings.add("Sayfada şifre girişi tespit edildi. Kimlik avı riskine karşı adres çubuğunu doğrulayın.")
            } else {
                formStatus = "Doğrulanmış Güvenli Giriş Formu"
            }
        } else if (hasForm) {
            formStatus = "Standart Veri Formu (Zararsız)"
        }

        // 2. JAVASCRIPT & MALWARE / CRYPTO-MINER INSPECTION
        var scriptStatus = "Güvenli (Zararlı script tespit edilmedi)"
        for (pattern in SCRIPT_MALWARE_PATTERNS) {
            if (pattern.matcher(htmlContent).find()) {
                threatScore += 40
                scriptStatus = "Tehlikeli / Gizlenmiş Script Tespit Edildi"
                findings.add("Sayfa kaynağında gizlenmiş kod yürütme (eval/obfuscated JS) tespit edildi.")
                break
            }
        }

        // 3. PHISHING & SOCIAL ENGINEERING PATTERNS
        var phishingStatus = "Güvenli (Oltalama deseni yok)"
        for (pattern in PHISHING_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                val matchedText = matcher.group(0)
                threatScore += 35
                phishingStatus = "Oltalama Belirtisi Bulundu"
                findings.add("Sosyal mühendislik / oltalama şüphesi: '$matchedText'")
                break
            }
        }

        // Check if URL has deceptive brand name in subdomain (e.g. instagram.login-verify.xyz)
        val suspiciousBrands = listOf("instagram", "facebook", "twitter", "banka", "turkiye", "e-devlet", "papara", "binance", "netflix", "whatsapp")
        for (brand in suspiciousBrands) {
            if (domain.contains(brand) && !domain.endsWith("$brand.com") && !domain.endsWith("$brand.com.tr") && !domain.endsWith("$brand.net")) {
                threatScore += 50
                phishingStatus = "Marka Taklidi / Sahte Domain Tespit Edildi"
                findings.add("Sahte marka taklidi tespit edildi: Domain içerisinde '$brand' adı kullanılıyor.")
                break
            }
        }

        // 4. DANGEROUS DOWNLOAD LINKS (APK, EXE)
        var downloadStatus = "Temiz (Zararlı indirme linki yok)"
        for (pattern in DANGEROUS_DOWNLOAD_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                threatScore += 30
                downloadStatus = "Doğrudan İndirilebilir Yürütülebilir Dosya"
                findings.add("Sayfa doğrudan çalıştırılabilir (.apk / .exe) dosya bağlantısı içeriyor.")
                break
            }
        }

        // Base protocol note (HTTP does not mean threat if content is clean)
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
            formSecurityStatus = formStatus,
            scriptSecurityStatus = scriptStatus,
            phishingStatus = phishingStatus,
            downloadStatus = downloadStatus,
            findings = findings
        )
    }
}
