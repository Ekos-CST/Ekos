@echo off
:: EKOS Antivirus - Windows Defender Exclusion Installer
:: Run as Administrator
chcp 65001 >nul
title EKOS Antivirüs - Windows Defender İstisna Tanımlayıcı

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ====================================================================
    echo [UYARI] Yönetici yetkisi gerekiyor!
    echo Lütfen bu dosyaya Sağ Tıklayıp "Yönetici Olarak Çalıştır"ı seçiniz.
    echo ====================================================================
    pause
    exit /b 1
)

echo ====================================================================
echo     EKOS ANTİVİRÜS - WINDOWS DEFENDER GÜVENLİ İSTİSNA TANIMLAYICI
echo ====================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Write-Host '[1/3] Klasör İstisnaları Ekleniyor...' -ForegroundColor Cyan; " ^
  "Add-MpPreference -ExclusionPath 'C:\Program Files\EKOS Antivirus' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionPath 'C:\Program Files (x86)\EKOS Antivirus' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionPath 'C:\EKOS_Server' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionPath \"$env:LOCALAPPDATA\Programs\ekos-antivirus-gui\" -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionPath \"$env:APPDATA\ekos-antivirus-gui\" -ErrorAction SilentlyContinue; " ^
  "Write-Host '[2/3] Süreç ve Motor İstisnaları Ekleniyor...' -ForegroundColor Cyan; " ^
  "Add-MpPreference -ExclusionProcess 'EkosAntivirus.exe' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionProcess 'EKOS Antivirüs.exe' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionProcess 'EKOS_Antivirus_Setup_4.2.0.exe' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionProcess 'EKOS_Antivirus_Setup_4.1.0.exe' -ErrorAction SilentlyContinue; " ^
  "Add-MpPreference -ExclusionProcess 'EKOS Antivirüs Setup 4.2.0.exe' -ErrorAction SilentlyContinue; " ^
  "Write-Host '[3/3] Uzantı ve Karantina İstisnaları Tamamlanıyor...' -ForegroundColor Cyan; " ^
  "Add-MpPreference -ExclusionExtension '.ekosvault' -ErrorAction SilentlyContinue; " ^
  "Write-Host ''; " ^
  "Write-Host '✅ [BAŞARILI] EKOS Antivirüs ve bileşenleri Windows Defender korumasına güvenli istisna olarak tanımlandı!' -ForegroundColor Green;"

echo.
echo ====================================================================
echo İşlem tamamlandı. EKOS uygulamaları artık Defender tarafından engellenmeyecektir.
echo ====================================================================
pause
