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

    // Protected Brands for Typosquatting / Homoglyph / Impersonation
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

    private val MALWARE_EXPLOIT_PATTERNS = listOf(
        Pattern.compile("(?i)(malware|trojan|stealer|rat|c2|payload|exploit|keylogger|ransomware|spyware|botnet|dropper|injector|darknet|onion|crack|keygen|patcher|hacktool|ddos|miner|coinhive|crypto-drainer|grabber|infostealer|redline|lumma|raccoon|vidar|agenttesla|asyncrat|njrat|remcos|danabot|qakbot|cobaltstrike|shellcode|backdoor|rootkit|zeroday|vulnerability|bypass|unauthorized)"),
        Pattern.compile("(?i)(cryptojack|xmr-miner|xmrig|stratum\\+tcp|webminer|cpuminer)")
    )

    private val PHISHING_URL_PATTERNS = listOf(
        Pattern.compile("(?i)(phish|phishing|gift-card|free-nitro|free-robux|free-gift|bedava-hediye|hediye-ceki|bonus-kazan|odul-kazan|iphone-kazan|airdrop|claim-reward|survey-reward)"),
        Pattern.compile("(?i)(login-verify|hesap-dogrula|guvenlik-guncelleme|banka-giris|account-security|update-password|wallet-seed|recovery-phrase|seedphrase|metamask-verify|binance-claim|papara-hediye|e-devlet-kapisi|fatura-odeme-sorgula|kredi-basvuru-onay|borc-yapilandirma|verify-identity|suspended-account|update-billing)")
    )

    private val DANGEROUS_FILE_URL_PATTERN = Pattern.compile("(?i)\\.(apk|exe|dll|bat|vbs|ps1|scr|jar|iso|img|dmg|sh|bin|msi|cmd)(\\?|#|$)")
    private val DOUBLE_EXTENSION_PATTERN = Pattern.compile("(?i)\\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|zip|rar|txt|mp3)\\.(exe|apk|bat|vbs|scr|msi|cmd)(\\?|#|$)")
    private val HIGH_RISK_TLD_PATTERN = Pattern.compile("(?i)\\.(xyz|top|click|monster|cfd|rest|buzz|club|work|tk|ml|ga|cf|gq|pw|cc|ru|su)(/|:|\$|\\?)")
    private val IP_HOST_PATTERN = Pattern.compile("(?i)^https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    // 1. Script Malware, Exfiltration, Keyloggers
    private val SCRIPT_MALWARE_PATTERNS = listOf(
        Pattern.compile("(?i)(eval\\s*\\(|document\\.write\\s*\\(\\s*unescape|String\\.fromCharCode)"),
        Pattern.compile("(?i)(coinhive|cryptonight|webminer|coin-hive|cryptoloot|miner\\.start)"),
        Pattern.compile("(?i)(window\\.location\\.replace\\s*\\(['\"][^'\"]*\\.(exe|apk|scr|bat))"),
        Pattern.compile("(?i)discord\\.com/api/webhooks"),
        Pattern.compile("(?i)(document\\.cookie|localStorage\\.getItem|sessionStorage\\.getItem).*fetch\\("),
        Pattern.compile("(?i)addEventListener\\(['\"]keydown['\"].*keyCode"),
        Pattern.compile("(?i)document\\.createElement\\(['\"]script['\"]\\)")
    )

    // 2. Aggressive Pop-Up, Pop-Under, Notification & Clickjacking Patterns
    private val POPUP_HIJACK_PATTERNS = listOf(
        Pattern.compile("(?i)window\\.open\\s*\\([^)]*\\)"),
        Pattern.compile("(?i)setInterval\\s*\\([^)]*window\\.open"),
        Pattern.compile("(?i)(onbeforeunload|addEventListener\\(['\"]beforeunload['\"])"),
        Pattern.compile("(?i)Notification\\.requestPermission"),
        Pattern.compile("(?i)(requestFullscreen|webkitRequestFullscreen)"),
        Pattern.compile("(?i)navigator\\.clipboard\\.writeText")
    )

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
        val gatewayChain = mutableListOf<String>()
        var threatScore = 0

        var isFormThreat = false
        var isScriptThreat = false
        var isPhishingThreat = false
        var isDownloadThreat = false

        val protocol = if (cleanUrl.startsWith("https://", ignoreCase = true)) "HTTPS (Şifreli TLS)" else "HTTP (Düz Metin)"
        val urlLower = cleanUrl.lowercase()
        gatewayChain.add(cleanUrl)

        // 1. INITIAL LEXICAL & REPUTATION CHECKS
        for (pattern in MALWARE_EXPLOIT_PATTERNS) {
            val matcher = pattern.matcher(urlLower)
            if (matcher.find()) {
                val match = matcher.group(0)
                threatScore += 80
                isPhishingThreat = true
                findings.add("KRİTİK TEHDİT: URL adresinde bilinen zararlı yazılım anahtarı bulundu: '$match'")
                break
            }
        }

        for (pattern in PHISHING_URL_PATTERNS) {
            val matcher = pattern.matcher(urlLower)
            if (matcher.find()) {
                val match = matcher.group(0)
                threatScore += 70
                isPhishingThreat = true
                findings.add("OLTALAMA ŞÜPHESİ: URL adresinde kimlik avı / sahte ödül deseni bulundu: '$match'")
                break
            }
        }

        if (DANGEROUS_FILE_URL_PATTERN.matcher(urlLower).find()) {
            threatScore += 65
            isDownloadThreat = true
            findings.add("ZARARLI İNDİRME: Bağlantı doğrudan çalıştırılabilir ikili dosya barındırıyor.")
        }

        if (DOUBLE_EXTENSION_PATTERN.matcher(urlLower).find()) {
            threatScore += 85
            isDownloadThreat = true
            findings.add("GİZLENMİŞ ÇİFT UZANTI: Dosya adında sahte çift uzantı hilesi (.pdf.exe vb.) tespit edildi!")
        }

        if (HIGH_RISK_TLD_PATTERN.matcher(urlLower).find()) {
            threatScore += 25
            findings.add("Yüksek riskli geçici/ücretsiz TLD uzantısı (.xyz, .top vb.) kullanılıyor.")
        }

        if (IP_HOST_PATTERN.matcher(urlLower).find()) {
            threatScore += 35
            findings.add("Alan adı yerine doğrudan ham IP adresi kullanılıyor (Şüpheli C2 sunucusu).")
        }

        // Typosquatting Check on Initial Domain
        val initialHost = try { URI(cleanUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }
        val initialDomainLabel = extractDomainLabel(initialHost)
        for (brand in PROTECTED_BRANDS) {
            val isOfficial = brand.officialDomains.any { initialHost == it || initialHost.endsWith(".$it") }
            if (!isOfficial) {
                if (initialHost.contains(brand.canonicalKey)) {
                    threatScore += 75
                    isPhishingThreat = true
                    findings.add("MARKA TAKLİDİ (PHISHING): '${brand.name}' adı yetkisiz adreste ($initialHost) tespit edildi.")
                    break
                }
                if (initialDomainLabel.length >= 4 && abs(initialDomainLabel.length - brand.canonicalKey.length) <= 2) {
                    val dist = computeLevenshteinDistance(initialDomainLabel, brand.canonicalKey)
                    if (dist in 1..2) {
                        threatScore += 90
                        isPhishingThreat = true
                        findings.add("KRİTİK OLTALAMA (TYPOSQUATTING): '$initialDomainLabel' alan adı '${brand.name}' markasını $dist harf farkıyla taklit ediyor ($initialDomainLabel ➔ ${brand.canonicalKey})!")
                        break
                    }
                }
            }
        }

        // 2. LIVE FETCH & GATEWAY REDIRECTION TRAVERSAL (HTTP & JS Gateways)
        try {
            val request = Request.Builder()
                .url(cleanUrl)
                .header("User-Agent", "Mozilla/5.0 (Linux; Android 14; Mobile; EkosSecurityScan/2.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36")
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .header("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")
                .build()

            httpClient.newCall(request).execute().use { response ->
                responseCode = response.code
                finalResolvedUrl = response.request.url.toString()
                htmlContent = response.body?.string() ?: ""

                if (finalResolvedUrl != cleanUrl) {
                    gatewayChain.add(finalResolvedUrl)
                }

                val titleMatcher = Pattern.compile("(?i)<title[^>]*>([^<]+)</title>").matcher(htmlContent)
                if (titleMatcher.find()) {
                    pageTitle = titleMatcher.group(1)?.trim() ?: "Web Sayfası"
                }

                val finalHost = try { URI(finalResolvedUrl).host?.lowercase() ?: "" } catch (e: Exception) { "" }
                if (finalHost.isNotEmpty() && finalHost != initialHost) {
                    threatScore += 45
                    findings.add("GİZLİ AĞ GEÇİDİ (GATEWAY): İstek ilk adresten ($initialHost) farklı olan '$finalHost' adresine yönlendirildi (Gateway Traversal).")

                    val finalDomainLabel = extractDomainLabel(finalHost)
                    for (brand in PROTECTED_BRANDS) {
                        val isOfficial = brand.officialDomains.any { finalHost == it || finalHost.endsWith(".$it") }
                        if (!isOfficial && (finalHost.contains(brand.canonicalKey) || computeLevenshteinDistance(finalDomainLabel, brand.canonicalKey) in 1..2)) {
                            threatScore += 80
                            isPhishingThreat = true
                            findings.add("HEDEF GEÇİTTE MARKA TAKLİDİ: Yönlendirilen '$finalHost' adresi '${brand.name}' markasını taklit ediyor!")
                            break
                        }
                    }
                }
            }
        } catch (e: Exception) {
            if (threatScore > 0) {
                findings.add("Hedef sunucuya doğrudan erişilemedi ancak alan adı ve ağ imzalarında tehdit deseni doğrulandı.")
            } else {
                findings.add("Ağ Erişimi: ${e.localizedMessage ?: "Bağlantı zaman aşımı"}")
            }
        }

        // 3. JAVASCRIPT & META REFRESH CLIENT-SIDE GATEWAY DETECTION
        val jsRedirectMatcher = Pattern.compile("(?i)(window\\.location(\\.replace)?|location\\.href|self\\.location|top\\.location)\\s*=\\s*['\"]([^'\"]+)['\"]").matcher(htmlContent)
        if (jsRedirectMatcher.find()) {
            val destJsUrl = jsRedirectMatcher.group(3) ?: ""
            if (destJsUrl.startsWith("http://", ignoreCase = true) || destJsUrl.startsWith("https://", ignoreCase = true)) {
                threatScore += 50
                gatewayChain.add(destJsUrl)
                findings.add("JAVASCRIPT AĞ GEÇİDİ (JS REDIRECT): Sayfa kodlarında otomatik yönlendirme ağ geçidi bulundu: '$destJsUrl'")
            }
        }

        val metaRefreshMatcher = Pattern.compile("(?i)<meta[^>]*http-equiv=[\"']refresh[\"'][^>]*content=[\"'][0-9]+;\\s*url=([^\"']+)[\"']").matcher(htmlContent)
        if (metaRefreshMatcher.find()) {
            val metaUrl = metaRefreshMatcher.group(1) ?: ""
            threatScore += 45
            gatewayChain.add(metaUrl)
            findings.add("META REFRESH GEÇİDİ: Sayfa otomatik olarak '$metaUrl' adresine yönlendirme kodu içeriyor.")
        }

        // 4. POP-UP, POP-UNDER, NOTIFICATION & BROWSER HIJACK AUDIT
        if (Pattern.compile("(?i)setInterval\\s*\\([^)]*window\\.open").matcher(htmlContent).find() ||
            Pattern.compile("(?i)(window\\.open\\s*\\([^)]*\\)[^;]*;\\s*){2,}").matcher(htmlContent).find()) {
            threatScore += 55
            isScriptThreat = true
            findings.add("AGRESİF POP-UP DÖNGÜSÜ (SPAM POPUP): Sayfa kullanıcıdan habersiz çoklu veya döngüsel açılır pencere (pop-up) üretiyor!")
        } else if (Pattern.compile("(?i)window\\.open\\s*\\(").matcher(htmlContent).find()) {
            findings.add("Sayfa kodlarında dinamik açılır pencere (window.open) kullanımı tespit edildi.")
        }

        if (Pattern.compile("(?i)(onbeforeunload|addEventListener\\(['\"]beforeunload['\"])").matcher(htmlContent).find()) {
            threatScore += 35
            findings.add("SAYFA TERKİ ENGELLEME TUZAĞI (UNLOAD TRAP): Ziyaretçinin sayfayı kapatmasını veya geri gitmesini engelleyen kilitleyici kod bulundu.")
        }

        if (Pattern.compile("(?i)Notification\\.requestPermission").matcher(htmlContent).find()) {
            threatScore += 30
            findings.add("BİLDİRİM İZNİ ZORLAMASI (NOTIFICATION SPAM): Sayfa tarayıcı bildirim izni talep eden kod barındırıyor.")
        }

        if (Pattern.compile("(?i)(navigator\\.clipboard\\.writeText|document\\.execCommand\\(['\"]copy['\"])").matcher(htmlContent).find()) {
            threatScore += 40
            findings.add("PANO MÜDAHALESİ (CLIPBOARD HIJACK): Sayfa kullanıcının panosunu sessizce değiştirme yeteneğine sahip kod içeriyor.")
        }

        // 5. DEEP SOFTWARE & EMBEDDED BINARY SCANNING
        val softwareLinks = mutableListOf<String>()
        val binaryMatcher = Pattern.compile("(?i)href\\s*=\\s*[\"']([^\"']+\\.(apk|exe|dll|bat|vbs|ps1|scr|jar|iso|img|dmg|sh|bin|msi|cmd)(\\?[^\"']*)?)[\"']").matcher(htmlContent)
        while (binaryMatcher.find()) {
            val rawLink = binaryMatcher.group(1)
            if (rawLink != null && !softwareLinks.contains(rawLink)) {
                softwareLinks.add(rawLink)
            }
        }

        if (softwareLinks.isNotEmpty()) {
            threatScore += 50
            isDownloadThreat = true
            for (sLink in softwareLinks.take(3)) {
                val sLower = sLink.lowercase()
                var sThreatDesc = "Doğrudan İndirilebilir Yazılım Bağlantısı: '$sLink'"

                if (sLower.contains("crack") || sLower.contains("keygen") || sLower.contains("patch") || sLower.contains("stealer") || sLower.contains("cheat") || sLower.contains("injector") || sLower.contains("robux") || sLower.contains("nitro")) {
                    threatScore += 35
                    sThreatDesc = "ZARARLI / İSTİSMAR YAZILIMI İNDİRME BAĞLANTISI: '$sLink'"
                } else if (DOUBLE_EXTENSION_PATTERN.matcher(sLower).find()) {
                    threatScore += 45
                    sThreatDesc = "GİZLENMİŞ ÇİFT UZANTI TUZAĞI: '$sLink'"
                }

                findings.add(sThreatDesc)
            }
        }

        // 6. EXTERNAL SCRIPT SECURITY AUDIT (<script src="...">)
        val externalScripts = mutableListOf<String>()
        val scriptSrcMatcher = Pattern.compile("(?i)<script[^>]*src=[\"']([^\"']+)[\"']").matcher(htmlContent)
        while (scriptSrcMatcher.find()) {
            val src = scriptSrcMatcher.group(1)
            if (src != null && (src.startsWith("http://") || src.startsWith("https://"))) {
                externalScripts.add(src)
            }
        }

        if (externalScripts.isNotEmpty()) {
            for (scriptUrl in externalScripts.take(3)) {
                val sUrlLower = scriptUrl.lowercase()
                if (sUrlLower.contains("coinhive") || sUrlLower.contains("miner") || sUrlLower.contains("stealer") || sUrlLower.contains("payload") || sUrlLower.contains("keylogger")) {
                    threatScore += 60
                    isScriptThreat = true
                    findings.add("ZARARLI HARİCİ BETİK (MALICIOUS JS): Sayfaya harici olarak yüklenen tehlikeli script: '$scriptUrl'")
                }
            }
        }

        // 7. FORM & DATA EXFILTRATION AUDIT
        val hasPasswordInput = Pattern.compile("(?i)<input[^>]*type=[\"']password[\"']").matcher(htmlContent).find()
        val hasCreditCardInput = Pattern.compile("(?i)(cardnumber|creditcard|cvv|sonkullanma|cc-num|kartno)").matcher(htmlContent).find()
        val formActionMatcher = Pattern.compile("(?i)<form[^>]*action=[\"']([^\"']*)[\"']").matcher(htmlContent)

        var formActionUrl = ""
        if (formActionMatcher.find()) {
            formActionUrl = formActionMatcher.group(1) ?: ""
        }

        var formStatus = "Temiz (Şifre tuzağı yok)"
        if (hasCreditCardInput) {
            threatScore += 55
            isFormThreat = true
            formStatus = "Kredi Kartı / Ödeme Formu Bulundu"
            findings.add("Sayfa kodlarında hassas kredi kartı veya ödeme bilgisi toplayan form alanları tespit edildi.")
        } else if (hasPasswordInput) {
            if (formActionUrl.startsWith("http://") || formActionUrl.startsWith("https://")) {
                val actionHost = try { URI(formActionUrl).host?.lowercase() ?: "" } catch(e: Exception) { "" }
                if (actionHost.isNotEmpty() && actionHost != initialHost) {
                    threatScore += 75
                    isFormThreat = true
                    isPhishingThreat = true
                    formStatus = "Çapraz Sunucuya Veri Sızdırma (Data Exfiltration)"
                    findings.add("HASSAS VERİ SIZDIRMA (CROSS-DOMAIN FORM): Giriş formundaki şifreler farklı bir harici sunucuya ($actionHost) gönderiliyor!")
                }
            }

            if (!cleanUrl.startsWith("https://", ignoreCase = true)) {
                threatScore += 45
                isFormThreat = true
                formStatus = "Yüksek Risk (HTTP üzerinden şifre girişi)"
                findings.add("Şifresiz HTTP bağlantısı üzerinden parola girişi talep ediliyor!")
            } else if (!formStatus.contains("Sızdırma")) {
                formStatus = "Giriş Formu Bulundu"
            }
        }

        // 8. IN-PAGE SCRIPT & PHISHING PATTERN CHECKS
        var scriptStatus = "Temiz (Zararlı script yok)"
        for (pattern in SCRIPT_MALWARE_PATTERNS) {
            if (pattern.matcher(htmlContent).find()) {
                threatScore += 50
                isScriptThreat = true
                scriptStatus = "Zararlı / Gizlenmiş Script Bulundu"
                findings.add("Sayfa kaynağında veri sızdırma, tuş kaydedici veya gizlenmiş kod yürütme betiği tespit edildi.")
                break
            }
        }

        var phishingStatus = if (isPhishingThreat) "Oltalama Belirtisi Bulundu" else "Temiz (Oltalama deseni yok)"
        var downloadStatus = if (isDownloadThreat || softwareLinks.isNotEmpty()) "Tespit Edildi (İndirilebilir Yazılım/İkili Dosya)" else "Temiz (Zararlı indirme linki yok)"

        val isSafe = threatScore < 30
        val verdict = when {
            threatScore >= 60 -> "YÜKSEK TEHDİT: ZARARLI VEYA OLTALAMA SİTESİ"
            threatScore >= 30 -> "ŞÜPHELİ BAĞLANTI: DİKKATLİ OLUN"
            else -> "BAĞLANTI VE SİTE İÇERİĞİ GÜVENLİ"
        }

        if (findings.isEmpty()) {
            findings.add("Site içeriği, açılır pencereler (pop-up), ağ geçitleri, bağlı yazılımlar ve scriptler denetlendi. Güvenlik açığı bulunamadı.")
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
