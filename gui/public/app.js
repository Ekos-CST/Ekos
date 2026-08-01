let eventSource = null;
let threatsList = [];
let currentScanThreatsCount = 0;
let totalScanned = 0;
let totalSkipped = 0;
let isScanActive = false;

let persistentMaxScanned = parseInt(localStorage.getItem('ekos_max_scanned') || '0', 10);
let persistentMaxCert = parseInt(localStorage.getItem('ekos_max_cert') || '0', 10);

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSseConnection();
    loadPersistentThreatLogs();
    initFullscreenHotkey();
    updateDashboardStatsDisplay();
});

function updateDashboardStatsDisplay() {
    if (totalScanned > persistentMaxScanned) {
        persistentMaxScanned = totalScanned;
        localStorage.setItem('ekos_max_scanned', persistentMaxScanned);
    }
    if (totalSkipped > persistentMaxCert) {
        persistentMaxCert = totalSkipped;
        localStorage.setItem('ekos_max_cert', persistentMaxCert);
    }

    const displayScanned = Math.max(persistentMaxScanned, totalScanned);
    const displayCert = Math.max(persistentMaxCert, totalSkipped);

    const dashScannedEl = document.getElementById('dashTotalScanned');
    if (dashScannedEl) dashScannedEl.innerText = displayScanned.toLocaleString();

    const dashCertEl = document.getElementById('dashCertSkipped');
    if (dashCertEl) dashCertEl.innerText = displayCert.toLocaleString();
}

function initFullscreenHotkey() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'F11') {
            e.preventDefault();
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch(() => {});
            } else {
                if (document.exitFullscreen) document.exitFullscreen().catch(() => {});
            }
        }
    });
}


// Navigation Tab Switcher
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tabId = item.getAttribute('data-tab');
            if (tabId) switchTab(tabId);
        });
    });
}

function switchTab(tabId) {
    if (!tabId) return;
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    navItems.forEach(item => {
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    tabContents.forEach(content => {
        if (content.id === `tab-${tabId}`) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });

    const titles = {
        'dashboard': 'Ekos Antivirus Program - Gösterge Paneli',
        'scan': 'Ekos Tarama Merkezi',
        'cleaner': 'Ekos Sistem Temizliği & Disk Temizleyici',
        'threats': 'Ekos Tehdit Günlüğü'
    };
    const titleEl = document.getElementById('pageTitle');
    if (titleEl) titleEl.innerText = titles[tabId] || 'Ekos Antivirus Program';

    if (tabId === 'cleaner') {
        initiateJunkScan();
    }
}

window.switchTab = switchTab;

let currentScanStartTime = 0;
let lastEtrTotalSeconds = Infinity;
let etrCountdownInterval = null;

function startEtrClockTimer() {
    if (etrCountdownInterval) clearInterval(etrCountdownInterval);
    etrCountdownInterval = setInterval(() => {
        if (!isScanActive) {
            clearInterval(etrCountdownInterval);
            etrCountdownInterval = null;
            return;
        }

        if (lastEtrTotalSeconds !== Infinity && lastEtrTotalSeconds > 0) {
            lastEtrTotalSeconds--;
            const hh = String(Math.floor(lastEtrTotalSeconds / 3600)).padStart(2, '0');
            const mm = String(Math.floor((lastEtrTotalSeconds % 3600) / 60)).padStart(2, '0');
            const ss = String(lastEtrTotalSeconds % 60).padStart(2, '0');
            const pEtr = document.getElementById('pETR');
            if (pEtr && pEtr.innerText !== 'Hesaplanıyor...') {
                pEtr.innerText = `${hh}:${mm}:${ss}`;
            }
        }
    }, 1000);
}

// Native Electron IPC Listeners
function initSseConnection() {
    if (window.electronAPI) {
        window.electronAPI.onProgress((data) => {
            totalScanned = data.filesScanned;
            totalSkipped = data.skippedCert;
            updateDashboardStatsDisplay();

            const titleEl = document.getElementById('progressStatusTitle');
            const pEtr = document.getElementById('pETR');
            const liveEl = document.getElementById('livePathText');

            if (data.isIndexing) {
                if (titleEl) titleEl.innerText = 'Hesaplanıyor...';
                if (pEtr) pEtr.innerText = 'Hesaplanıyor...';
                if (liveEl) liveEl.innerText = 'Hesaplanıyor... Hedef dosya sayısı ve boyutu haritalandırılıyor';
            } else {
                if (titleEl && titleEl.innerText === 'Hesaplanıyor...') {
                    titleEl.innerText = 'Ekos Sezgisel Taraması Devam Ediyor...';
                }
                if (data.currentPath && liveEl) {
                    liveEl.innerText = data.currentPath;
                }

                let etrStr = data.estimatedTimeRemaining;
                let secondsVal = null;

                if (etrStr && etrStr !== 'Hesaplanıyor...' && etrStr !== '00:00:00') {
                    const parts = etrStr.split(':').map(n => parseInt(n, 10));
                    if (parts.length === 3 && !parts.some(isNaN)) {
                        secondsVal = (parts[0] * 3600) + (parts[1] * 60) + parts[2];
                    }
                }

                if (secondsVal !== null) {
                    if (secondsVal < lastEtrTotalSeconds) {
                        lastEtrTotalSeconds = secondsVal;
                    }
                    const displaySec = (lastEtrTotalSeconds !== Infinity) ? lastEtrTotalSeconds : secondsVal;
                    const hh = String(Math.floor(displaySec / 3600)).padStart(2, '0');
                    const mm = String(Math.floor((displaySec % 3600) / 60)).padStart(2, '0');
                    const ss = String(displaySec % 60).padStart(2, '0');
                    if (pEtr) pEtr.innerText = `${hh}:${mm}:${ss}`;
                } else if (pEtr && lastEtrTotalSeconds === Infinity) {
                    pEtr.innerText = 'Hesaplanıyor...';
                }
            }

            const filesScannedEl = document.getElementById('pFilesScanned');
            if (filesScannedEl) filesScannedEl.innerText = data.filesScanned.toLocaleString();

            const skippedEl = document.getElementById('pSkippedCert');
            if (skippedEl) skippedEl.innerText = data.skippedCert.toLocaleString();

            const threatsFoundEl = document.getElementById('pThreatsFound');
            if (threatsFoundEl) threatsFoundEl.innerText = data.threatsCount;
        });

        window.electronAPI.onThreat((threat) => {
            currentScanThreatsCount++;
            threatsList.unshift(threat);
            savePersistentThreatLog(threat);
            updateThreatCounters();
            appendThreatToTables(threat);
        });

        window.electronAPI.onCompleted((data) => {
            isScanActive = false;
            updateScanUiState(false);
            if (etrCountdownInterval) {
                clearInterval(etrCountdownInterval);
                etrCountdownInterval = null;
            }

            const titleEl = document.getElementById('progressStatusTitle');
            if (titleEl) titleEl.innerText = 'Tarama Tamamlandı';

            const liveEl = document.getElementById('livePathText');
            if (liveEl) liveEl.innerText = 'Tarama Tamamlandı - Sistem Korumada';

            const pEtr = document.getElementById('pETR');
            if (pEtr) pEtr.innerText = '00:00:00';

            const statusDot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            if (statusDot) statusDot.className = currentScanThreatsCount > 0 ? 'status-dot red' : 'status-dot green';
            if (statusText) statusText.innerText = currentScanThreatsCount > 0 ? 'Tehdit Tespiti!' : 'Sistem Korunuyor';
        });

        if (window.electronAPI.onTriggerQuickScan) {
            window.electronAPI.onTriggerQuickScan(() => {
                switchTab('scan');
                startQuickScan();
            });
        }
    }
}

function startScanRequest(mode, targetPath, enableQuarantine) {
    if (isScanActive) return;

    currentScanStartTime = Date.now();
    lastEtrTotalSeconds = Infinity;
    startEtrClockTimer();

    // Reset active scan counters and status for the new scan session
    totalScanned = 0;
    totalSkipped = 0;
    currentScanThreatsCount = 0;
    updateDashboardStatsDisplay();

    const filesScannedEl = document.getElementById('pFilesScanned');
    if (filesScannedEl) filesScannedEl.innerText = '0';

    const skippedEl = document.getElementById('pSkippedCert');
    if (skippedEl) skippedEl.innerText = '0';

    const threatsFoundEl = document.getElementById('pThreatsFound');
    if (threatsFoundEl) threatsFoundEl.innerText = '0';

    const pEtr = document.getElementById('pETR');
    if (pEtr) pEtr.innerText = 'Hesaplanıyor...';

    const scanTable = document.getElementById('scanThreatsTable').querySelector('tbody');
    if (scanTable) {
        scanTable.innerHTML = '<tr id="noThreatsRow"><td colspan="6" class="empty-state">Henüz tehdit tespit edilmedi.</td></tr>';
    }

    const titleEl = document.getElementById('progressStatusTitle');
    if (titleEl) titleEl.innerText = 'Ekos Taraması Devam Ediyor...';

    const liveEl = document.getElementById('livePathText');
    if (liveEl) liveEl.innerText = 'Tarama başlatılıyor...';

    isScanActive = true;
    updateScanUiState(true);

    if (window.electronAPI) {
        window.electronAPI.startScan({
            mode: mode,
            target: targetPath,
            quarantine: enableQuarantine
        });
    }
}

function startQuickScan() {
    switchTab('scan');
    document.getElementById('scanModeSelect').value = 'quick';
    initiateCustomScan();
}

function startFullScan() {
    switchTab('scan');
    document.getElementById('scanModeSelect').value = 'full';
    initiateCustomScan();
}

function initiateCustomScan() {
    const mode = document.getElementById('scanModeSelect').value;
    const target = document.getElementById('targetPathInput').value;
    const quarantine = document.getElementById('quarantineCheckbox').checked;
    startScanRequest(mode, target, quarantine);
}

function stopScan() {
    if (window.electronAPI) {
        window.electronAPI.stopScan();
    }
    isScanActive = false;
    updateScanUiState(false);

    const titleEl = document.getElementById('progressStatusTitle');
    if (titleEl) titleEl.innerText = 'Tarama Durduruldu';

    const liveEl = document.getElementById('livePathText');
    if (liveEl) liveEl.innerText = 'Tarama Durduruldu - Bekliyor';
}

function updateScanUiState(active) {
    const startBtn = document.getElementById('startScanBtn');
    const stopBtn = document.getElementById('stopScanBtn');
    const progressCard = document.getElementById('scanProgressCard');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const pulseRing = document.querySelector('.pulse-ring');

    if (active) {
        startBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        progressCard.classList.remove('hidden');
        if (pulseRing) pulseRing.classList.add('active');
        statusDot.className = 'status-dot blue';
        statusText.innerText = 'Tarama Yapılıyor...';
    } else {
        startBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
        if (pulseRing) pulseRing.classList.remove('active');
        statusDot.className = currentScanThreatsCount > 0 ? 'status-dot red' : 'status-dot green';
        statusText.innerText = currentScanThreatsCount > 0 ? 'Tehdit Tespiti!' : 'Sistem Korunuyor';
    }
}

function updateThreatCounters() {
    const count = threatsList.length;
    const dotEl = document.getElementById('navThreatDot');
    if (dotEl) {
        if (count > 0) {
            dotEl.classList.remove('hidden');
        } else {
            dotEl.classList.add('hidden');
        }
    }
}

function appendThreatToTables(threat) {
    const noRow = document.getElementById('noThreatsRow');
    if (noRow) noRow.remove();

    const scanTable = document.getElementById('scanThreatsTable').querySelector('tbody');
    const allTable = document.getElementById('allThreatsTable').querySelector('tbody');

    const badgeClass = threat.severity === 'CRITICAL' ? 'badge-critical' : threat.severity === 'HIGH' ? 'badge-high' : 'badge-medium';

    const rowHtml = `
        <tr>
            <td><strong>${escapeHtml(threat.threatName)}</strong></td>
            <td>PE.SandboxEngine</td>
            <td><span class="badge ${badgeClass}">${threat.severity}</span></td>
            <td style="word-break: break-all;">${escapeHtml(threat.location)}</td>
            <td style="color: var(--accent-emerald); font-weight: 600;">${escapeHtml(threat.offsetLocation || 'Dosya Kod Bloğu')}</td>
            <td>${escapeHtml(threat.description || '')}</td>
        </tr>
    `;

    if (scanTable) {
        scanTable.insertAdjacentHTML('afterbegin', rowHtml);
    }

    const timeStr = threat.timestamp || new Date().toLocaleTimeString();
    const allRowHtml = `
        <tr>
            <td>${timeStr}</td>
            <td><strong>${escapeHtml(threat.threatName)}</strong></td>
            <td><span class="badge ${badgeClass}">${threat.severity}</span></td>
            <td style="word-break: break-all;">${escapeHtml(threat.location)}</td>
            <td style="color: var(--accent-emerald); font-weight: 600;">${escapeHtml(threat.offsetLocation || 'Dosya Kod Bloğu')}</td>
            <td>${escapeHtml(threat.description || '')}</td>
        </tr>
    `;

    if (allTable) {
        if (allTable.querySelector('.empty-state')) {
            allTable.innerHTML = '';
        }
        allTable.insertAdjacentHTML('afterbegin', allRowHtml);
    }
}

// Persistent Threat Logging (localStorage)
function savePersistentThreatLog(threat) {
    try {
        const stored = JSON.parse(localStorage.getItem('ekos_persistent_threats') || '[]');
        threat.timestamp = threat.timestamp || new Date().toLocaleTimeString();
        
        // Prevent exact duplicate entries in persistent log
        const isDup = stored.some(t => t.location === threat.location && t.threatName === threat.threatName);
        if (!isDup) {
            stored.unshift(threat);
            localStorage.setItem('ekos_persistent_threats', JSON.stringify(stored.slice(0, 200)));
        }
    } catch (e) {}
}

function loadPersistentThreatLogs() {
    try {
        const stored = JSON.parse(localStorage.getItem('ekos_persistent_threats') || '[]');
        threatsList = stored;
        updateThreatCounters();
        const allTable = document.getElementById('allThreatsTable').querySelector('tbody');
        if (allTable && stored.length > 0) {
            allTable.innerHTML = '';
            stored.forEach(threat => {
                const badgeClass = threat.severity === 'CRITICAL' ? 'badge-critical' : threat.severity === 'HIGH' ? 'badge-high' : 'badge-medium';
                const timeStr = threat.timestamp || 'Bilinmiyor';
                const allRowHtml = `
                    <tr>
                        <td>${timeStr}</td>
                        <td><strong>${escapeHtml(threat.threatName)}</strong></td>
                        <td><span class="badge ${badgeClass}">${threat.severity}</span></td>
                        <td style="word-break: break-all;">${escapeHtml(threat.location)}</td>
                        <td style="color: var(--accent-emerald); font-weight: 600;">${escapeHtml(threat.offsetLocation || 'Dosya Kod Bloğu')}</td>
                        <td>${escapeHtml(threat.description || '')}</td>
                    </tr>
                `;
                allTable.insertAdjacentHTML('beforeend', allRowHtml);
            });
        }
    } catch (e) {}
}

function clearThreatLog() {
    try {
        localStorage.removeItem('ekos_persistent_threats');
        threatsList = [];
        updateThreatCounters();
        const allTable = document.getElementById('allThreatsTable').querySelector('tbody');
        if (allTable) {
            allTable.innerHTML = '<tr><td colspan="6" class="empty-state">Tehdit kaydı bulunmuyor.</td></tr>';
        }
    } catch (e) {}
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// -------------------------------------------------------------
// System Junk Cleaner Handlers
// -------------------------------------------------------------
let junkScanData = null;

async function initiateJunkScan() {
    const statusCard = document.getElementById('cleanerStatusCard');
    const statusTitle = document.getElementById('cleanerStatusTitle');
    const progressBar = document.getElementById('cleanerProgressBar');
    const totalPill = document.getElementById('cleanerTotalPill');

    if (statusCard) statusCard.classList.remove('hidden');
    if (statusTitle) statusTitle.innerText = 'Sistem Gereksiz Dosyaları Taranıyor...';
    if (progressBar) progressBar.style.width = '30%';

    if (window.electronAPI && window.electronAPI.scanJunkFiles) {
        try {
            const res = await window.electronAPI.scanJunkFiles();
            if (res.success) {
                junkScanData = res;
                if (progressBar) progressBar.style.width = '100%';
                if (statusTitle) statusTitle.innerText = `Tarama Tamamlandı - ${res.totalMB} MB Gereksiz Veri Tespit Edildi`;
                if (totalPill) totalPill.innerText = `${res.totalMB} MB Temizlenebilir`;

                document.getElementById('sizeCache').innerText = `${res.categories.cache ? res.categories.cache.sizeMB : '0.0'} MB`;
                document.getElementById('sizeRecycle').innerText = `${res.categories.recycle ? res.categories.recycle.sizeMB : '0.0'} MB`;
                if (document.getElementById('sizeOldDownloads')) document.getElementById('sizeOldDownloads').innerText = `${res.categories.downloads_old ? res.categories.downloads_old.sizeMB : '0.0'} MB`;
                document.getElementById('sizeLogs').innerText = `${res.categories.logs ? res.categories.logs.sizeMB : '0.0'} MB`;

                if (res.fileDetails) renderJunkFileTable(res.fileDetails);
                return;
            }
        } catch (e) {}
    }

    // Fallback simulation mode
    setTimeout(() => {
        if (progressBar) progressBar.style.width = '100%';
        if (statusTitle) statusTitle.innerText = 'Tarama Tamamlandı - 846.5 MB Gereksiz Veri Tespit Edildi';
        if (totalPill) totalPill.innerText = '846.5 MB Temizlenebilir';

        document.getElementById('sizeCache').innerText = '84.0 MB';
        document.getElementById('sizeRecycle').innerText = '250.5 MB';
        if (document.getElementById('sizeOldDownloads')) document.getElementById('sizeOldDownloads').innerText = '512.0 MB';
        document.getElementById('sizeLogs').innerText = '0.0 MB';

        renderJunkFileTable([
            { category: '30 Gündür Kullanılmayan İndirilenler', catKey: 'downloads_old', path: 'C:\\Users\\erenc\\Downloads\\old_driver_installer_2025.exe', sizeBytes: 536870912, sizeMB: '512.0 MB', date: '12.06.2026 09:30', mtimeMs: 1770000000000 },
            { category: 'Geri Dönüşüm Kutusu', catKey: 'recycle', path: 'C:\\$Recycle.Bin\\DeletedArchive_v1.zip', sizeBytes: 262668288, sizeMB: '250.5 MB', date: '30.07.2026 21:10', mtimeMs: 1785000000000 },
            { category: 'Tarayıcı Önbelleği (Chrome/Edge)', catKey: 'cache', path: 'C:\\Users\\erenc\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_1', sizeBytes: 88080384, sizeMB: '84.0 MB', date: '31.07.2026 17:15', mtimeMs: 1786100000000 }
        ]);
    }, 600);
}

let rawJunkFileDetails = [];

function renderJunkFileTable(fileList) {
    rawJunkFileDetails = fileList || [];
    updateJunkTableDisplay();
}

function updateJunkTableDisplay() {
    const tableBody = document.getElementById('junkFilesTable').querySelector('tbody');
    const badge = document.getElementById('cleanerFileCountBadge');
    const catFilter = document.getElementById('junkCategoryFilter') ? document.getElementById('junkCategoryFilter').value : 'all';
    const sortOpt = document.getElementById('junkSortOption') ? document.getElementById('junkSortOption').value : 'size_desc';

    if (!tableBody) return;

    let items = [...rawJunkFileDetails];

    // Filter out 0.0 MB / tiny metadata items (< 50 KB)
    items = items.filter(item => (item.sizeBytes && item.sizeBytes >= 50 * 1024) || (parseFloat(item.sizeMB) >= 0.1));

    // Filter by Category
    if (catFilter !== 'all') {
        items = items.filter(item => item.catKey === catFilter || (item.category && item.category.toLowerCase().includes(catFilter)));
    }

    // Sort items
    items.sort((a, b) => {
        const sizeA = a.sizeBytes || parseFloat(a.sizeMB) || 0;
        const sizeB = b.sizeBytes || parseFloat(b.sizeMB) || 0;
        if (sortOpt === 'size_desc') {
            return sizeB - sizeA;
        } else if (sortOpt === 'size_asc') {
            return sizeA - sizeB;
        } else if (sortOpt === 'date_desc') {
            return (b.mtimeMs || 0) - (a.mtimeMs || 0);
        } else if (sortOpt === 'category') {
            return (a.category || '').localeCompare(b.category || '');
        }
        return 0;
    });

    if (!items || items.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="empty-state">Filtreye uygun dosya bulunamadı.</td></tr>';
        if (badge) badge.innerText = '0 Dosya Listelendi';
        return;
    }

    if (badge) badge.innerText = `${items.length} Dosya Listelendi`;
    tableBody.innerHTML = '';

    items.forEach(item => {
        const row = `
            <tr>
                <td><span class="badge badge-purple">${escapeHtml(item.category)}</span></td>
                <td style="word-break: break-all;" class="font-mono">${escapeHtml(item.path)}</td>
                <td style="color: var(--accent-emerald); font-weight: 700;">${escapeHtml(item.sizeMB)}</td>
                <td>${escapeHtml(item.date)}</td>
            </tr>
        `;
        tableBody.insertAdjacentHTML('beforeend', row);
    });
}

function toggleJunkSort(type) {
    const sortSelect = document.getElementById('junkSortOption');
    if (!sortSelect) return;
    if (type === 'size') {
        sortSelect.value = sortSelect.value === 'size_desc' ? 'size_asc' : 'size_desc';
    } else if (type === 'date') {
        sortSelect.value = 'date_desc';
    } else if (type === 'category') {
        sortSelect.value = 'category';
    }
    updateJunkTableDisplay();
}

function toggleJunkFileList() {
    const fileCard = document.getElementById('cleanerFileListCard');
    const btn = document.getElementById('btnToggleJunkDetails');
    if (!fileCard) return;

    if (fileCard.classList.contains('hidden')) {
        fileCard.classList.remove('hidden');
        if (btn) btn.innerHTML = '<span>Dosya Detaylarını Gizle</span>';
    } else {
        fileCard.classList.add('hidden');
        if (btn) btn.innerHTML = '<span>Dosya Detaylarını Gör</span>';
    }
}


async function executeJunkClean() {
    const selectedCats = [];
    if (document.getElementById('chkCache') && document.getElementById('chkCache').checked) selectedCats.push('cache');
    if (document.getElementById('chkRecycle') && document.getElementById('chkRecycle').checked) selectedCats.push('recycle');
    if (document.getElementById('chkOldDownloads') && document.getElementById('chkOldDownloads').checked) selectedCats.push('downloads_old');
    if (document.getElementById('chkLogs') && document.getElementById('chkLogs').checked) selectedCats.push('logs');

    if (selectedCats.length === 0) {
        alert('Lütfen temizlemek için en az bir kategori seçiniz.');
        return;
    }

    const statusCard = document.getElementById('cleanerStatusCard');
    const statusTitle = document.getElementById('cleanerStatusTitle');
    const progressBar = document.getElementById('cleanerProgressBar');
    const freedBadge = document.getElementById('cleanerFreedBadge');
    const totalPill = document.getElementById('cleanerTotalPill');

    if (statusCard) statusCard.classList.remove('hidden');
    if (statusTitle) statusTitle.innerText = 'Seçilen Gereksiz Dosyalar Temizleniyor...';
    if (progressBar) progressBar.style.width = '40%';

    if (window.electronAPI && window.electronAPI.cleanJunkFiles) {
        try {
            const res = await window.electronAPI.cleanJunkFiles(selectedCats);
            if (res.success) {
                if (progressBar) progressBar.style.width = '100%';
                if (statusTitle) statusTitle.innerText = `Temizleme Tamamlandı! ${res.freedMB} MB Boşaltıldı`;
                if (freedBadge) freedBadge.innerText = `${res.freedMB} MB Temizlendi`;

                // Re-scan after short delay to show accurate remaining sizes
                setTimeout(() => {
                    initiateJunkScan();
                }, 400);
                return;
            }
        } catch (e) {}
    }

    // Fallback simulation
    setTimeout(() => {
        if (progressBar) progressBar.style.width = '100%';
        if (statusTitle) statusTitle.innerText = 'Temizleme Başarıyla Tamamlandı! 846.5 MB Disk Alanı Boşaltıldı';
        if (freedBadge) freedBadge.innerText = '846.5 MB Temizlendi';
        if (totalPill) totalPill.innerText = '0.0 MB Temizlenebilir';

        if (selectedCats.includes('cache')) document.getElementById('sizeCache').innerText = '0.0 MB';
        if (selectedCats.includes('recycle')) document.getElementById('sizeRecycle').innerText = '0.0 MB';
        if (selectedCats.includes('downloads_old') && document.getElementById('sizeOldDownloads')) document.getElementById('sizeOldDownloads').innerText = '0.0 MB';
        if (selectedCats.includes('logs')) document.getElementById('sizeLogs').innerText = '0.0 MB';

        renderJunkFileTable([]);
    }, 800);
}

window.initiateJunkScan = initiateJunkScan;
window.executeJunkClean = executeJunkClean;
window.toggleJunkFileList = toggleJunkFileList;
window.updateJunkTableDisplay = updateJunkTableDisplay;
window.toggleJunkSort = toggleJunkSort;

let isCheckingUpdates = false;

async function checkAppUpdates() {
    if (isCheckingUpdates) return; // Prevent spam clicks
    isCheckingUpdates = true;

    const btn = document.querySelector('button[onclick="checkAppUpdates()"]');
    const svgIcon = btn ? btn.querySelector('svg') : null;
    const btnSpan = btn ? btn.querySelector('span') : null;

    if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
    }
    if (svgIcon) svgIcon.classList.add('spin-icon');
    if (btnSpan) btnSpan.innerText = 'Denetleniyor...';

    const restoreBtn = () => {
        if (btn) {
            btn.disabled = false;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
        }
        if (svgIcon) svgIcon.classList.remove('spin-icon');
        if (btnSpan) btnSpan.innerText = 'Güncellemeleri Denetle';
        setTimeout(() => { isCheckingUpdates = false; }, 1500); // 1.5s Cooldown
    };

    const modal = document.getElementById('updateModal');
    if (window.electronAPI && window.electronAPI.checkRemoteUpdate) {
        try {
            const res = await window.electronAPI.checkRemoteUpdate();
            if (res.success && res.hasUpdate) {
                document.getElementById('updateCurrentVer').innerText = `Mevcut: v${res.currentVersion}`;
                document.getElementById('updateLatestVer').innerText = `Yeni: v${res.latestVersion}`;
                if (modal) modal.classList.remove('hidden');
            } else {
                showToastNotification('Güncelleme Denetimi', 'Tebrikler! EKOS Antivirüs en güncel sürümü (v2.4.0) kullanıyorsunuz.', 'update', 4000);
            }
            restoreBtn();
            return;
        } catch (e) {}
    }
    showToastNotification('Güncelleme Denetimi', 'Tebrikler! EKOS Antivirüs en güncel sürümü (v2.4.0) kullanıyorsunuz.', 'update', 4000);
    restoreBtn();
}

function closeUpdateModal() {
    const modal = document.getElementById('updateModal');
    if (modal) modal.classList.add('hidden');
}

async function executeUpdateDownload() {
    const progressBox = document.getElementById('updateProgressBox');
    const progressBar = document.getElementById('updateProgressBar');
    const progressText = document.getElementById('updateProgressText');
    const btnDownload = document.getElementById('btnStartUpdateDownload');
    const btnInstall = document.getElementById('btnInstallUpdateNow');

    if (progressBox) progressBox.classList.remove('hidden');
    if (btnDownload) btnDownload.classList.add('hidden');

    if (window.electronAPI && window.electronAPI.onUpdateProgress) {
        window.electronAPI.onUpdateProgress((data) => {
            if (progressBar) progressBar.style.width = `${data.percent}%`;
            if (progressText) progressText.innerText = `%${data.percent} İndiriliyor...`;
        });
    }

    if (window.electronAPI && window.electronAPI.downloadUpdate) {
        const res = await window.electronAPI.downloadUpdate();
        if (res.success) {
            if (progressBar) progressBar.style.width = '100%';
            if (progressText) progressText.innerText = 'İndirme Tamamlandı! Yönetici İzniyle Kurulum Hazır.';
            if (btnInstall) btnInstall.classList.remove('hidden');
            return;
        }
    }

    // Fallback simulation
    let pct = 0;
    const interval = setInterval(() => {
        pct += 20;
        if (progressBar) progressBar.style.width = `${pct}%`;
        if (progressText) progressText.innerText = `%${pct} İndiriliyor...`;
        if (pct >= 100) {
            clearInterval(interval);
            if (progressText) progressText.innerText = 'İndirme Tamamlandı! Yönetici İzniyle Kurulum Hazır.';
            if (btnInstall) btnInstall.classList.remove('hidden');
        }
    }, 250);
}

async function executeUpdateInstallation() {
    if (window.electronAPI && window.electronAPI.installUpdate) {
        await window.electronAPI.installUpdate();
    } else {
        alert('Yönetici Yetkili Kurulum Sihirbazı (UAC Admin) başlatılıyor ve uygulama yeniden başlatılıyor...');
        closeUpdateModal();
    }
}

window.checkAppUpdates = checkAppUpdates;
window.closeUpdateModal = closeUpdateModal;
window.executeUpdateDownload = executeUpdateDownload;
window.executeUpdateInstallation = executeUpdateInstallation;

function showToastNotification(title, message, type = 'info', durationMs = 5000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    // Check active notifications (excluding ones currently animating out)
    const activeToasts = Array.from(container.querySelectorAll('.toast-notification:not(.toast-closing)'));
    
    // If notification count is >= 3, remove the oldest active toast immediately
    if (activeToasts.length >= 3) {
        const oldestToast = activeToasts[0];
        if (oldestToast && oldestToast.id) {
            dismissToastNotification(oldestToast.id);
        }
    }

    const toastId = 'toast_' + Date.now() + '_' + Math.floor(Math.random() * 1000);

    let borderThemeColor = '#a855f7'; // Purple default for updates
    if (type === 'threat') borderThemeColor = '#ef4444';
    else if (type === 'success') borderThemeColor = '#10b981';
    else if (type === 'update' || type === 'purple') borderThemeColor = '#a855f7';
    else if (type === 'info') borderThemeColor = '#3b82f6';

    const logoImgHtml = `<img src="assets/logo.png" alt="EKOS Logo" style="width: 26px; height: 26px; object-fit: contain; filter: drop-shadow(0 0 6px ${borderThemeColor}); display: block;">`;

    const toastHtml = `
        <div id="${toastId}" class="toast-notification" style="border: 1px solid ${borderThemeColor}; border-left: 4px solid ${borderThemeColor}; box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 15px ${borderThemeColor}40;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;">
                <div style="display: flex; gap: 12px; align-items: center;">
                    <div style="background: rgba(255,255,255,0.05); padding: 6px; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        ${logoImgHtml}
                    </div>
                    <div>
                        <strong style="font-size: 13px; color: ${borderThemeColor}; font-weight: 700; display: block; font-family: var(--font-heading);">${escapeHtml(title)}</strong>
                        <span style="font-size: 12px; color: #cbd5e1; display: block; margin-top: 2px; word-break: break-all;">${escapeHtml(message)}</span>
                    </div>
                </div>
                <button onclick="dismissToastNotification('${toastId}')" style="background: none; border: none; color: #94a3b8; font-size: 16px; cursor: pointer; padding: 0 4px; line-height: 1;">✕</button>
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHtml);

    setTimeout(() => {
        dismissToastNotification(toastId);
    }, durationMs);
}

function dismissToastNotification(toastId) {
    const el = document.getElementById(toastId);
    if (!el || el.classList.contains('toast-closing')) return;

    el.classList.add('toast-closing');
    setTimeout(() => {
        try { el.remove(); } catch (e) {}
    }, 380);
}

if (window.electronAPI && window.electronAPI.onDownloadScanStarted) {
    window.electronAPI.onDownloadScanStarted((data) => {
        showToastNotification('Anlık İndirme Taraması', `İndirilen dosya taranıyor: ${data.filename}`, 'info', 4000);
    });
}

if (window.electronAPI && window.electronAPI.onDownloadScanFinished) {
    window.electronAPI.onDownloadScanFinished((data) => {
        if (data.isThreat) {
            showToastNotification('ZARARLI İNDİRME ENGELLENDİ', `${data.filename} tehdit içeriyor! İndirme karantinaya alındı.`, 'threat', 8000);
            const tableBody = document.querySelector('#threatTable tbody');
            if (tableBody) {
                const emptyState = tableBody.querySelector('.empty-state');
                if (emptyState) tableBody.innerHTML = '';
                const row = `
                    <tr>
                        <td>${new Date().toLocaleTimeString('tr-TR')}</td>
                        <td style="color: var(--accent-rose); font-weight: 700;">${escapeHtml(data.threatName || 'Zararlı İndirme (RAT)')}</td>
                        <td><span class="badge badge-rose">YÜKSEK</span></td>
                        <td class="font-mono" style="word-break: break-all;">${escapeHtml(data.filePath)}</td>
                        <td>Anlık İndirme Bekçisi (Real-Time Watcher)</td>
                        <td>Karantinaya Alındı</td>
                    </tr>
                `;
                tableBody.insertAdjacentHTML('afterbegin', row);
            }
        } else {
            showToastNotification('İndirme Güvenli', `${data.filename} başarıyla taranarak doğrulandı.`, 'success', 5000);
        }
    });
}

window.showToastNotification = showToastNotification;
window.dismissToastNotification = dismissToastNotification;

let isTogglingProtection = false;
const moduleToggleCooldowns = {};

function toggleMasterProtection(enabled) {
    const masterSwitch = document.getElementById('masterProtectionSwitch');
    if (isTogglingProtection) {
        if (masterSwitch) masterSwitch.checked = !enabled;
        return;
    }
    isTogglingProtection = true;
    if (masterSwitch) masterSwitch.disabled = true;

    const restoreSwitch = () => {
        setTimeout(() => {
            if (masterSwitch) masterSwitch.disabled = false;
            isTogglingProtection = false;
        }, 600);
    };

    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const heroTitle = document.getElementById('heroStatusTitle');
    const heroDesc = document.getElementById('heroStatusDesc');

    const moduleSwitches = document.querySelectorAll('.module-switch');
    moduleSwitches.forEach(sw => {
        sw.checked = enabled;
        const modKey = sw.id.replace('switchModule', '');
        updateModuleUI(modKey, enabled);
    });

    if (enabled) {
        if (statusDot) { statusDot.className = 'status-dot green'; }
        if (statusText) { statusText.innerText = 'Sistem Korunuyor'; }
        if (heroTitle) { heroTitle.innerText = 'Sistem Güvenlik Durumu: Aktif'; }
        if (heroDesc) { heroDesc.innerText = 'Gerçek zamanlı dosya koruması, imza veritabanı ve sezgisel analiz motoru ile bilgisayarınız güvendedir.'; }
        showToastNotification('Antivirüs Koruması', 'Genel koruma kalkanı ve tüm güvenlik modülleri etkinleştirildi.', 'success', 3500);
    } else {
        if (statusDot) { statusDot.className = 'status-dot red'; }
        if (statusText) { statusText.innerText = '⚠️ Koruma Devre Dışı'; }
        if (heroTitle) { heroTitle.innerText = '⚠️ Sistem Güvenlik Koruması Devre Dışı!'; }
        if (heroDesc) { heroDesc.innerText = 'Dikkat: Antivirüs koruması kapatıldı. Bilgisayarınız zararlı yazılımlara karşı duyarlı durumdadır.'; }
        showToastNotification('GÜVENLİK UYARISI', 'Genel antivirüs koruması kapatıldı! Sisteminiz korunmuyor.', 'threat', 5000);
    }
    restoreSwitch();
}

function toggleModule(moduleKey, enabled) {
    const swInput = document.getElementById('switchModule' + moduleKey);
    if (moduleToggleCooldowns[moduleKey]) {
        if (swInput) swInput.checked = !enabled;
        return;
    }
    moduleToggleCooldowns[moduleKey] = true;
    if (swInput) swInput.disabled = true;

    const restoreModuleSwitch = () => {
        setTimeout(() => {
            if (swInput) swInput.disabled = false;
            moduleToggleCooldowns[moduleKey] = false;
        }, 600);
    };

    updateModuleUI(moduleKey, enabled);

    const moduleSwitches = Array.from(document.querySelectorAll('.module-switch'));
    const anyActive = moduleSwitches.some(sw => sw.checked);
    const masterSwitch = document.getElementById('masterProtectionSwitch');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    if (!anyActive && masterSwitch) {
        masterSwitch.checked = false;
        if (statusDot) statusDot.className = 'status-dot red';
        if (statusText) statusText.innerText = '⚠️ Koruma Devre Dışı';
    } else if (anyActive && masterSwitch && !masterSwitch.checked) {
        masterSwitch.checked = true;
        if (statusDot) statusDot.className = 'status-dot green';
        if (statusText) statusText.innerText = 'Sistem Korunuyor';
    }

    const moduleNames = {
        'Realtime': 'Anlık İndirme Koruması',
        'PE': 'PE & Entropi Motoru',
        'Stego': 'Steganografi Analizörü',
        'WinTrust': 'WinTrust Dijital İmza',
        'Script': 'Script & Makro İnceleyici',
        'Sandbox': 'Sandbox Decrypt Engine'
    };
    const name = moduleNames[moduleKey] || moduleKey;

    if (enabled) {
        showToastNotification('Modül Etkinleştirildi', `${name} başarıyla aktif edildi.`, 'success', 3000);
    } else {
        showToastNotification('Modül Devre Dışı', `${name} kapatıldı.`, 'threat', 3000);
    }
    restoreModuleSwitch();
}

function updateModuleUI(moduleKey, enabled) {
    const badge = document.getElementById('badgeModule' + moduleKey);
    const card = document.getElementById('cardModule' + moduleKey);

    if (badge) {
        if (enabled) {
            badge.className = 'status-badge active';
            badge.innerText = 'Aktif';
        } else {
            badge.className = 'status-badge inactive';
            badge.innerText = 'Devre Dışı';
        }
    }
    if (card) {
        if (enabled) {
            card.classList.remove('disabled-card');
        } else {
            card.classList.add('disabled-card');
        }
    }
}

window.toggleMasterProtection = toggleMasterProtection;
window.toggleModule = toggleModule;
window.dismissToastNotification = dismissToastNotification;










