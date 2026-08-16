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
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    // 1. Critical Malware / Trojan / Stealer Signatures
    private val MALWARE_EXPLOIT_PATTERNS = listOf(
        Pattern.compile("(?i)(malware|trojan|stealer|rat|c2|payload|exploit|keylogger|ransomware|spyware|botnet|dropper|injector|darknet|onion|crack|keygen|patcher|hacktool|ddos|miner|coinhive|crypto-drainer|grabber|infostealer|redline|lumma|raccoon|vidar|agenttesla|asyncrat|njrat|remcos|danabot|qakbot|cobaltstrike|shellcode|backdoor|rootkit|zeroday|vulnerability|bypass|unauthorized)"),
        Pattern.compile("(?i)(cryptojack|xmr-miner|xmrig|stratum\\+tcp|webminer|cpuminer)")
    )

    // 2. Phishing & Credential Theft Signatures
    private val PHISHING_URL_PATTERNS = listOf(
        Pattern.compile("(?i)(phish|phishing|gift-card|free-nitro|free-robux|free-gift|bedava-hediye|hediye-ceki|bonus-kazan|odul-kazan|iphone-kazan|airdrop|claim-reward|survey-reward)"),
        Pattern.compile("(?i)(login-verify|hesap-dogrula|guvenlik-guncelleme|banka-giris|account-security|update-password|wallet-seed|recovery-phrase|seedphrase|metamask-verify|binance-claim|papara-hediye|e-devlet-kapisi|fatura-odeme-sorgula|kredi-basvuru-onay|borc-yapilandirma|verify-identity|suspended-account|update-billing)")
    )

    // 3. Executable & Dangerous Download Patterns in URL
    private val DANGEROUS_FILE_URL_PATTERN = Pattern.compile("(?i)\\.(apk|exe|dll|bat|vbs|ps1|scr|jar|iso|img|dmg|sh|bin|msi|cmd)(\\?|#|$)")

    // 4. Double Extension Obfuscation (e.g. image.jpg.exe, invoice.pdf.apk)
    private val DOUBLE_EXTENSION_PATTERN = Pattern.compile("(?i)\\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|zip|rar|txt|mp3)\\.(exe|apk|bat|vbs|scr|msi|cmd)(\\?|#|$)")

    // 5. High-Risk TLDs
    private val HIGH_RISK_TLD_PATTERN = Pattern.compile("(?i)\\.(xyz|top|click|monster|cfd|rest|buzz|club|work|tk|ml|ga|cf|gq|pw|cc|ru|su)(/|:|\$|\\?)")

    // 6. Direct IP as Host (e.g. http://192.168.1.1/malware)
    private val IP_HOST_PATTERN = Pattern.compile("(?i)^https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    // 7. In-Page Content Phishing Patterns
    private val PHISHING_CONTENT_PATTERNS = listOf(
        Pattern.compile("(?i)(hesabınız askıya alındı|hesabınızı doğrulayın|şifrenizi güncelleyin|oturum açın|giriş yapın|güvenlik doğrulaması)"),
        Pattern.compile("(?i)(tebrikler kazandınız|ücretsiz hediye|ödül kazandınız|iphone kazandınız|tıklayın kazanın|faturanız gecikti)"),
        Pattern.compile("(?i)(account suspended|verify your account|update your password|confirm identity|claim reward|unauthorized activity)"),
        Pattern.compile("(?i)(wallet key|recovery phrase|seed phrase|kurtarma anahtarı|cüzdan şifresi|private key)"),
        Pattern.compile("(?i)(e-devlet kapısı|turkiye\\.gov|papara|ziraat|garanti|akbank|iş bankası|yapı kredi|vakıfbank|halkbank)")
    )

    // 8. In-Page JavaScript Malware & Crypto Miners
    private val SCRIPT_MALWARE_PATTERNS = listOf(
        Pattern.compile("(?i)(eval\\s*\\(|document\\.write\\s*\\(\\s*unescape|String\\.fromCharCode)"),
        Pattern.compile("(?i)(coinhive|cryptonight|webminer|coin-hive|cryptoloot|miner\\.start)"),
        Pattern.compile("(?i)(window\\.location\\.replace\\s*\\(['\"][^'\"]*\\.(exe|apk|scr|bat))"),
        Pattern.compile("(?i)discord\\.com/api/webhooks")
    )

    // 9. Dangerous Download Links in HTML DOM
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

        // 1. LEXICAL URL HEURISTICS & SIGNATURE DETECTION
        for (pattern in MALWARE_EXPLOIT_PATTERNS) {
            val matcher = pattern.matcher(urlLower)
            if (matcher.find()) {
                val match = matcher.group(0)
                threatScore += 80
                isPhishingThreat = true
                findings.add("KRİTİK TEHDİT: URL adresinde bilinen zararlı yazılım/istismar anahtarı tespit edildi: '$match'")
                break
            }
        }

        for (pattern in PHISHING_URL_PATTERNS) {
            val matcher = pattern.matcher(urlLower)
            if (matcher.find()) {
                val match = matcher.group(0)
                threatScore += 70
                isPhishingThreat = true
                findings.add("OLTALAMA ŞÜPHESİ: URL adresinde kimlik avı / sahte ödül deseni tespit edildi: '$match'")
                break
            }
        }

        if (DANGEROUS_FILE_URL_PATTERN.matcher(urlLower).find()) {
            threatScore += 65
            isDownloadThreat = true
            findings.add("ZARARLI İNDİRME: Bağlantı doğrudan çalıştırılabilir ikili dosya (.apk/.exe/.bat vb.) barındırıyor.")
        }

        if (DOUBLE_EXTENSION_PATTERN.matcher(urlLower).find()) {
            threatScore += 85
            isDownloadThreat = true
            findings.add("GİZLENMİŞ ÇİFT UZANTI: Dosya adında sahte çift uzantı hilesi (örn: .pdf.exe) tespit edildi!")
        }

        if (HIGH_RISK_TLD_PATTERN.matcher(urlLower).find()) {
            threatScore += 25
            findings.add("Yüksek riskli geçici/ücretsiz TLD uzantısı (.xyz, .top vb.) kullanılıyor.")
        }

        if (IP_HOST_PATTERN.matcher(urlLower).find()) {
            threatScore += 35
            findings.add("Alan adı yerine doğrudan ham IP adresi kullanılıyor (Şüpheli C2 / Saldırı sunucusu).")
        }

        // Brand Impersonation in Domain / Subdomain
        val domain = try { URI(cleanUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }
        val brandKeywords = listOf(
            "ziraat", "garanti", "akbank", "isbank", "yapikredi", "vakifbank", "halkbank",
            "papara", "binance", "paribu", "btcturk", "turkiye-gov", "edevlet", "e-devlet",
            "apple", "icloud", "netflix", "instagram", "whatsapp", "telegram", "facebook", "paypal"
        )
        for (brand in brandKeywords) {
            if (domain.contains(brand)) {
                val isOfficial = domain == "$brand.com" || domain == "$brand.com.tr" || domain == "$brand.net" ||
                        domain == "$brand.gov.tr" || domain == "$brand.org" || domain.endsWith(".$brand.com") ||
                        domain.endsWith(".$brand.com.tr") || domain.endsWith(".$brand.gov.tr")
                if (!isOfficial) {
                    threatScore += 70
                    isPhishingThreat = true
                    findings.add("MARKA TAKLİDİ (PHISHING): '$brand' resmi alan adı dışında şüpheli adreste kullanılıyor.")
                    break
                }
            }
        }

        // 2. FETCH REAL PAGE CONTENT VIA NETWORK (If reachable)
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
                findings.add("Hedef sunucuya erişilemedi ancak URL sezgisel imza tablosunda zararlı desen doğrulandı.")
            } else {
                findings.add("Siteye doğrudan erişim: ${e.localizedMessage ?: "Bağlantı zaman aşımı"}")
            }
        }

        // 3. FORM & PASSWORD INPUT INSPECTION
        val hasPasswordInput = Pattern.compile("(?i)<input[^>]*type=[\"']password[\"']").matcher(htmlContent).find()
        val hasCreditCardInput = Pattern.compile("(?i)(cardnumber|creditcard|cvv|sonkullanma|cc-num|kartno)").matcher(htmlContent).find()
        val hasForm = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']*)[\"']").matcher(htmlContent).find()

        val isOfficialTrustedDomain = domain.endsWith("google.com") || domain.endsWith("microsoft.com") || domain.endsWith("github.com") || domain.endsWith("ekoscst.com") || domain.endsWith("apple.com")

        val formStatus: String
        if (hasCreditCardInput) {
            threatScore += 55
            isFormThreat = true
            formStatus = "Kredi Kartı / Ödeme Formu Bulundu"
            findings.add("Sayfa kodlarında hassas kredi kartı veya ödeme bilgisi toplayan form alanları tespit edildi.")
        } else if (hasPasswordInput) {
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
                threatScore += 50
                isScriptThreat = true
                scriptStatus = "Zararlı / Gizlenmiş Script Bulundu"
                findings.add("Sayfa kaynağında gizlenmiş kod yürütme veya veri sızdırma betiği tespit edildi.")
                break
            }
        }

        // 5. PHISHING CONTENT PATTERNS IN HTML
        var phishingStatus = if (isPhishingThreat) "Oltalama Belirtisi Bulundu" else "Temiz (Oltalama deseni yok)"
        for (pattern in PHISHING_CONTENT_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                val matchedText = matcher.group(0)
                threatScore += 40
                isPhishingThreat = true
                phishingStatus = "Oltalama Belirtisi Bulundu"
                findings.add("Sosyal mühendislik / kimlik avı metni: '$matchedText'")
                break
            }
        }

        // 6. DANGEROUS DOWNLOAD LINKS (APK, EXE) IN HTML
        var downloadStatus = if (isDownloadThreat) "Doğrudan İndirilebilir Yürütülebilir Dosya" else "Temiz (Zararlı indirme linki yok)"
        for (pattern in DANGEROUS_DOWNLOAD_PATTERNS) {
            val matcher = pattern.matcher(htmlContent)
            if (matcher.find()) {
                threatScore += 35
                isDownloadThreat = true
                downloadStatus = "Doğrudan İndirilebilir Yürütülebilir Dosya"
                findings.add("Sayfa doğrudan çalıştırılabilir (.apk / .exe) dosya indirme bağlantısı içeriyor.")
                break
            }
        }

        if (!cleanUrl.startsWith("https://", ignoreCase = true) && threatScore == 0) {
            findings.add("Site HTTP kullanıyor (Şifrelenmemiş bağlantı), ancak sayfa içeriği temiz ve zararsız.")
        }

        val isSafe = threatScore < 30
        val verdict = when {
            threatScore >= 60 -> "YÜKSEK TEHDİT: ZARARLI VEYA OLTALAMA SİTESİ"
            threatScore >= 30 -> "ŞÜPHELİ BAĞLANTI: DİKKATLİ OLUN"
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
