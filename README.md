# 🛡️ EKOS Antivirüs Motoru v2.4.0

> **Gelişmiş Sezgisel Analiz, Gerçek Zamanlı İndirme Koruması ve Yerel Yürütülebilir Sanallaştırma Motoru**  
> **Lisans Sahibi & Geliştirici:** Eren Can Uçar  
> **Telif Hakkı:** © 2026 Eren Can Uçar. Tüm Hakları Saklıdır.

---

## 📌 Proje Hakkında

**EKOS Antivirüs**, yüksek performanslı **C/C++ Güvenlik Çekirdeği** ve modern **Electron GUI** mimarisi ile geliştirilmiş yeni nesil bir Windows güvenlik yazılımıdır. 

Geleneksel imza tabanlı antivirüs sistemlerinin ötesine geçerek; **Entropi analizi**, **PE IAT WinAPI sezgisel inceleme**, **Steganografi (EOF Overlay) tespiti**, **Script & Makro analizi** ve **In-Memory Sanallaştırma (Sandbox)** teknolojileri ile Zero-Day ve karmaşık tehditlere (RAT, Ransomware, Crypter/Packer) karşı tam koruma sağlar.

---

## ⚡ Temel Güvenlik Modülleri

EKOS Antivirüs, 6 aktif koruma motoru ile bilgisayarınızı anlık olarak korur:

1. 📥 **Anlık İndirme Koruması (Real-Time Downloads Watcher)**  
   - `Downloads` (İndirilenler) klasörüne inen dosyaları anında algılar, geçici `.crdownload` ve `.tmp` dosyalarını süzerek tamamlanan dosyayı sezgisel taramadan geçirir ve zararlı tespit edilirse anında karantinaya alır.

2. 🧬 **PE & Entropi Sezgisel Motoru (PE & Entropy Engine)**  
   - UPX, crypter ve bilinmeyen packer ile sıkıştırılmış yürütülebilir dosyaların rastgelelik (entropi) oranını hesaplar. Şüpheli IAT WinAPI çağrılarını (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`) analiz eder.

3. 🖼️ **Steganografi & EOF Analizörü (Overlay Inspector)**  
   - Medya ve görsel dosyalarının (PNG, JPG, PDF) sonuna (End-Of-File) gömülmüş gizli kodları, overlay payload verilerini ve steganografik tehditleri ortaya çıkarır.

4. 🔏 **WinTrust Cert Verifier (Authenticode Dijital İmza)**  
   - Güvenilir üreticilere ait (Microsoft, Google, Valve vb.) geçerli Authenticode dijital imzasına sahip dosyaları doğrulayarak yanlış alarmları (False-Positive) önler.

5. 📜 **Script & Makro İnceleyici (PowerShell / Macro Guard)**  
   - Gizlenmiş (obfuscated) PowerShell, VBScript, Batch betiklerini ve Office/PDF dokümanlarına gömülü zararlı makro kodlarını inceler.

6. 📦 **Sandbox Decrypt Engine (In-Memory Sanallaştırma)**  
   - Şüpheli zararlı yazılımları bellek içi sanal sandbox ortamında simüle ederek davranışsal Zero-Day tehdit analizini gerçekleştirir.

---

## 🎨 Arayüz Özellikleri (UI & UX)

- **Cyberpunk Dark Mode & Glassmorphism**: Modern, şık ve dinamik kullanıcı deneyimi.
- **F11 Tam Ekran Desteği**: `F11` tuşu ile tam ekran moduna geçiş yapabilme.
- **Özel İmleç (Custom Dot Cursor)**: Etkileşimli beyaz nokta ve dinamik buton odaklama imleci.
- **Sıfır Scrollbar Tasarımı**: Uygulama içerisinde hiçbir kaydırma çubuğu (scrollbar) gözükmez.
- **Genel Koruma & Modül Bazlı Anahtarlar (Toggle Switches)**:
  - **Açık (Aktif)**: Yeşil renk ve yeşil dış ışıma efekti.
  - **Kapalı (Devre Dışı)**: Kırmızı renk ve karta gelindiğinde kırmızı parlama efekti.
- **Spam Tıklama Koruması (Debounce Cooldown)**: Butonlara ve anahtarlara art arda tıklanarak uygulamanın kilitlenmesi engellenmiştir.
- **FIFO Bildirim Kuyruğu (Max 3 Bildirim)**: Ekranda aynı anda en fazla 3 bildirim gösterilir. 3'ü geçtiğinde en eski bildirim otomatik kaybolarak yenisi gösterilir.

---

## 📦 Kurulum & Yayınlama

Projenin tek tıkla çalışan yönetici yetkili (UAC Admin) standalone Windows kurulum dosyası derlenmiştir:

- **Setup Dosyası**: `gui/dist/EKOS Antivirüs Setup 2.4.0.exe`
- **Kurulum Türü**: NSIS Administrator Installer (Tüm kullanıcılar için per-machine kurulum)

---

## 📜 Lisans & Yasal Uyarı

Bu yazılım **Proprietary (Özel Mülkiyet)** EULA lisansı ile korunmaktadır.

```text
EKOS Antivirüs Motoru Son Kullanıcı Lisans Sözleşmesi (EULA)
Telif Hakkı (©) 2026 Eren Can Uçar. Tüm Hakları Saklıdır.

Bu yazılımın orijinal sahibi ve lisans sahibi Eren Can Uçar'dır.
Yazılımın tersine mühendislik yapılması, değiştirilmesi, değiştirilerek 
yayılması, ticari amaçla kullanılması veya orijinal sahibi dışında 
üçüncü şahıslara dağıtılması KESİNLİKLE KISITLANMIŞTIR VE YASAKTIR.
```
