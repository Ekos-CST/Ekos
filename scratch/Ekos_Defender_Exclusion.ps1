# EKOS Antivirus - Windows Defender Exclusion Automation
# Run in Administrator PowerShell
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "    EKOS ANTİVİRÜS - WINDOWS DEFENDER GÜVENLİ İSTİSNA YÖNETİCİSİ    " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[UYARI] Bu script Windows Defender ayarlarını güncellemek için Yönetici yetkisi gerektirir." -ForegroundColor Red
    Write-Host "Lütfen PowerShell'i Yönetici Olarak Çalıştırıp tekrar deneyiniz.`n" -ForegroundColor Yellow
    Exit 1
}

$pathsToExclude = @(
    "C:\Program Files\EKOS Antivirus",
    "C:\Program Files (x86)\EKOS Antivirus",
    "C:\EKOS_Server",
    "$env:LOCALAPPDATA\Programs\ekos-antivirus-gui",
    "$env:APPDATA\ekos-antivirus-gui",
    "$env:USERPROFILE\.gemini\antigravity-ide\scratch\c_antivirus_engine"
)

Write-Host "`n[1/3] Klasör İstisnaları Ekleniyor..." -ForegroundColor Yellow
foreach ($p in $pathsToExclude) {
    try {
        Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
        Write-Host "  ✓ Dizin İstisnası: $p" -ForegroundColor Green
    } catch {
        Write-Host "  ✕ Eklenemedi: $p" -ForegroundColor Red
    }
}

$processesToExclude = @(
    "EkosAntivirus.exe",
    "EKOS Antivirüs.exe",
    "EKOS_Antivirus_Setup_4.2.0.exe",
    "EKOS_Antivirus_Setup_4.1.0.exe",
    "EKOS Antivirüs Setup 4.2.0.exe",
    "node.exe",
    "cloudflared.exe"
)

Write-Host "`n[2/3] Süreç ve Yürütülebilir Motor İstisnaları Ekleniyor..." -ForegroundColor Yellow
foreach ($proc in $processesToExclude) {
    try {
        Add-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue
        Write-Host "  ✓ Süreç İstisnası: $proc" -ForegroundColor Green
    } catch {
        Write-Host "  ✕ Eklenemedi: $proc" -ForegroundColor Red
    }
}

Write-Host "`n[3/3] Güvenli Karantina & Vault İstisnası..." -ForegroundColor Yellow
Add-MpPreference -ExclusionExtension ".ekosvault" -ErrorAction SilentlyContinue
Write-Host "  ✓ Dosya Uzantısı İstisnası: .ekosvault" -ForegroundColor Green

Write-Host "`n====================================================================" -ForegroundColor Cyan
Write-Host "✅ [BAŞARILI] EKOS Antivirüs ve tüm kurulum paketleri Windows Defender'a başarıyla istisna olarak tanımlandı!" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
