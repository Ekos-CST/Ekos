package com.ekos.antivirus.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.URI
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import kotlin.math.abs

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

data class ProtectedBrand(
    val name: String,
    val canonicalKey: String,
    val officialDomains: List<String>
)

object WebContentInspector {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    // Protected Global and Local Brands for Typosquatting / Homoglyph / Impersonation Detection
    private val PROTECTED_BRANDS = listOf(
        ProtectedBrand("Roblox", "roblox", listOf("roblox.com", "rbx.com")),
        ProtectedBrand("Steam", "steam", listOf("steampowered.com", "steamcommunity.com")),
        ProtectedBrand("Discord", "discord", listOf("discord.com", "discord.gg", "discordapp.com")),
        ProtectedBrand("Epic Games", "epicgames", listOf("epicgames.com", "unrealengine.com")),
        ProtectedBrand("Valorant", "valorant", listOf("playvalorant.com", "riotgames.com")),
        ProtectedBrand("Riot Games", "riotgames", listOf("riotgames.com", "leagueoflegends.com")),
        ProtectedBrand("Minecraft", "minecraft", listOf("minecraft.net", "mojang.com")),
        ProtectedBrand("Twitch", "twitch", listOf("twitch.tv")),
        ProtectedBrand("Spotify", "spotify", listOf("spotify.com")),
        ProtectedBrand("Netflix", "netflix", listOf("netflix.com")),
        ProtectedBrand("Google", "google", listOf("google.com", "google.com.tr", "gmail.com", "youtube.com")),
        ProtectedBrand("Microsoft", "microsoft", listOf("microsoft.com", "live.com", "outlook.com", "office.com")),
        ProtectedBrand("Apple", "apple", listOf("apple.com", "icloud.com")),
        ProtectedBrand("Amazon", "amazon", listOf("amazon.com", "amazon.com.tr")),
        ProtectedBrand("PayPal", "paypal", listOf("paypal.com")),
        ProtectedBrand("Instagram", "instagram", listOf("instagram.com")),
        ProtectedBrand("Facebook", "facebook", listOf("facebook.com", "fb.com", "meta.com")),
        ProtectedBrand("WhatsApp", "whatsapp", listOf("whatsapp.com")),
        ProtectedBrand("Telegram", "telegram", listOf("telegram.org", "t.me")),
        ProtectedBrand("Twitter", "twitter", listOf("twitter.com", "x.com")),
        ProtectedBrand("TikTok", "tiktok", listOf("tiktok.com")),
        ProtectedBrand("Binance", "binance", listOf("binance.com", "binance.tr")),
        ProtectedBrand("Papara", "papara", listOf("papara.com")),
        ProtectedBrand("Paribu", "paribu", listOf("paribu.com")),
        ProtectedBrand("BtcTurk", "btcturk", listOf("btcturk.com", "btcturk.pro")),
        ProtectedBrand("MetaMask", "metamask", listOf("metamask.io")),
        ProtectedBrand("TrustWallet", "trustwallet", listOf("trustwallet.com")),
        ProtectedBrand("Ziraat Bankası", "ziraat", listOf("ziraatbank.com.tr", "ziraatbankasi.com.tr", "ziraatkatilim.com.tr")),
        ProtectedBrand("Garanti BBVA", "garanti", listOf("garantibbva.com.tr", "garanti.com.tr")),
        ProtectedBrand("İş Bankası", "isbank", listOf("isbank.com.tr")),
        ProtectedBrand("Akbank", "akbank", listOf("akbank.com", "akbank.com.tr")),
        ProtectedBrand("Yapı Kredi", "yapikredi", listOf("yapikredi.com.tr")),
        ProtectedBrand("Vakıfbank", "vakifbank", listOf("vakifbank.com.tr")),
        ProtectedBrand("Halkbank", "halkbank", listOf("halkbank.com.tr")),
        ProtectedBrand("QNB Finansbank", "qnbfinansbank", listOf("qnbfinansbank.com", "qnb.com.tr")),
        ProtectedBrand("Denizbank", "denizbank", listOf("denizbank.com")),
        ProtectedBrand("Enpara", "enpara", listOf("enpara.com")),
        ProtectedBrand("e-Devlet", "edevlet", listOf("turkiye.gov.tr", "turkiye.gov"))
    )

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

    // 4. Double Extension Obfuscation
    private val DOUBLE_EXTENSION_PATTERN = Pattern.compile("(?i)\\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|zip|rar|txt|mp3)\\.(exe|apk|bat|vbs|scr|msi|cmd)(\\?|#|$)")

    // 5. High-Risk TLDs
    private val HIGH_RISK_TLD_PATTERN = Pattern.compile("(?i)\\.(xyz|top|click|monster|cfd|rest|buzz|club|work|tk|ml|ga|cf|gq|pw|cc|ru|su)(/|:|\$|\\?)")

    // 6. Direct IP as Host
    private val IP_HOST_PATTERN = Pattern.compile("(?i)^https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    // 7. In-Page Content Phishing Patterns
    private val PHISHING_CONTENT_PATTERNS = listOf(
        Pattern.compile("(?i)(hesabınız askıya alındı|hesabınızı doğrulayın|şifrenizi güncelleyin|oturum açın|giriş yapın|güvenlik doğrulaması)"),
        Pattern.compile("(?i)(tebrikler kazandınız|ücretsiz hediye|ödül kazandınız|iphone kazandınız|tıklayın kazanın|faturanız gecikti|robux kazandınız)"),
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

    /**
     * Calculates the Levenshtein Distance between two strings
     */
    private fun computeLevenshteinDistance(s1: String, s2: String): Int {
        val dp = Array(s1.length + 1) { IntArray(s2.length + 1) }
        for (i in 0..s1.length) dp[i][0] = i
        for (j in 0..s2.length) dp[0][j] = j
        for (i in 1..s1.length) {
            for (j in 1..s2.length) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost
                )
            }
        }
        return dp[s1.length][s2.length]
    }

    /**
     * Extracts Second-Level Domain (SLD) / main brand label from hostname
     * e.g., "www.robloz.com" -> "robloz", "login.steampowered.com" -> "steampowered"
     */
    private fun extractDomainLabel(hostname: String): String {
        var clean = hostname.lowercase().trim()
        if (clean.startsWith("www.")) clean = clean.substring(4)
        val parts = clean.split(".")
        return if (parts.size >= 2) {
            if (parts.size >= 3 && (parts[parts.size - 2] == "com" || parts[parts.size - 2] == "gov" || parts[parts.size - 2] == "org" || parts[parts.size - 2] == "net" || parts[parts.size - 2] == "co")) {
                parts[parts.size - 3]
            } else {
                parts[parts.size - 2]
            }
        } else {
            clean
        }
    }

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

        // 2. INTELLIGENT TYPOSQUATTING & BRAND IMPERSONATION DETECTION ENGINE
        val rawHost = try { URI(cleanUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }
        val domainLabel = extractDomainLabel(rawHost)

        for (brand in PROTECTED_BRANDS) {
            val isOfficialDomain = brand.officialDomains.any { official ->
                rawHost == official || rawHost.endsWith(".$official")
            }

            if (!isOfficialDomain) {
                // A) Exact substring match or brand contained in untrusted domain
                if (rawHost.contains(brand.canonicalKey)) {
                    threatScore += 75
                    isPhishingThreat = true
                    findings.add("MARKA TAKLİDİ (PHISHING): '${brand.name}' adı resmi olmayan şüpheli alan adında ($rawHost) tespit edildi.")
                    break
                }

                // B) Algorithmic Typosquatting (Levenshtein Distance <= 2 on SLD label, e.g. robloz -> roblox)
                if (domainLabel.length >= 4 && abs(domainLabel.length - brand.canonicalKey.length) <= 2) {
                    val dist = computeLevenshteinDistance(domainLabel, brand.canonicalKey)
                    if (dist in 1..2) {
                        threatScore += 90
                        isPhishingThreat = true
                        findings.add("KRİTİK OLTALAMA (TYPOSQUATTING): '$domainLabel' alan adı, resmi '${brand.name}' markasını $dist harf farkıyla taklit ediyor ($domainLabel ➔ ${brand.canonicalKey})!")
                        break
                    }
                }

                // C) Number / Homoglyph substitution check (e.g. r0bl0x -> roblox, g00gle -> google)
                val dehomoglyph = domainLabel
                    .replace("0", "o")
                    .replace("1", "l")
                    .replace("3", "e")
                    .replace("4", "a")
                    .replace("5", "s")
                    .replace("z", "x")

                if (dehomoglyph != domainLabel && dehomoglyph == brand.canonicalKey) {
                    threatScore += 90
                    isPhishingThreat = true
                    findings.add("KRİTİK OLTALAMA (HOMOGLYPH): '$domainLabel' alan adı rakam/harf değiştirme hilesiyle '${brand.name}' markasını taklit ediyor!")
                    break
                }
            }
        }

        // 3. FETCH REAL PAGE CONTENT VIA NETWORK (If reachable)
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
                findings.add("Hedef sunucuya erişilemedi ancak alan adı sezgisel imza tablosunda zararlı/oltalama deseni doğrulandı.")
            } else {
                findings.add("Siteye doğrudan erişim: ${e.localizedMessage ?: "Bağlantı zaman aşımı"}")
            }
        }

        // 4. FORM & PASSWORD INPUT INSPECTION
        val hasPasswordInput = Pattern.compile("(?i)<input[^>]*type=[\"']password[\"']").matcher(htmlContent).find()
        val hasCreditCardInput = Pattern.compile("(?i)(cardnumber|creditcard|cvv|sonkullanma|cc-num|kartno)").matcher(htmlContent).find()
        val hasForm = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']*)[\"']").matcher(htmlContent).find()

        val isOfficialTrustedDomain = rawHost.endsWith("google.com") || rawHost.endsWith("microsoft.com") || rawHost.endsWith("github.com") || rawHost.endsWith("ekoscst.com") || rawHost.endsWith("apple.com")

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

        // 5. JAVASCRIPT & MALWARE / CRYPTO-MINER INSPECTION
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

        // 6. PHISHING CONTENT PATTERNS IN HTML
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

        // 7. DANGEROUS DOWNLOAD LINKS (APK, EXE) IN HTML
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
