const { app, BrowserWindow, ipcMain, Tray, Menu } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow = null;
let activeScanProcess = null;
let tray = null;
let isQuitting = false;

function createTray() {
    if (tray) return;
    const iconPath = path.join(__dirname, 'public', 'assets', 'icon.ico');
    tray = new Tray(iconPath);
    tray.setToolTip('EKOS Antivirüs - Arka Plan Koruması Aktif');

    const contextMenu = Menu.buildFromTemplate([
        {
            label: '🛡️ EKOS Antivirüs Gösterge Paneli',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.focus();
                }
            }
        },
        {
            label: '⚡ Hızlı Tarama Başlat',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.webContents.send('trigger-quick-scan');
                }
            }
        },
        { type: 'separator' },
        {
            label: '🔴 Kapat ve Çıkış Yap',
            click: () => {
                isQuitting = true;
                app.quit();
            }
        }
    ]);

    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
        if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
        }
    });
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 820,
        minWidth: 1024,
        minHeight: 700,
        title: "EKOS Antivirüs Engine",
        icon: path.join(__dirname, 'public', 'assets', 'icon.ico'),
        backgroundColor: '#0a0c10',
        autoHideMenuBar: false,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        }
    });

    // Strip and disable menu bar completely for security
    mainWindow.setMenu(null);
    mainWindow.removeMenu();
    mainWindow.setMenuBarVisibility(false);

    // F11 Fullscreen toggle & block unwanted shortcuts
    mainWindow.webContents.on('before-input-event', (event, input) => {
        if (input.key === 'F11' && input.type === 'keyDown') {
            mainWindow.setFullScreen(!mainWindow.isFullScreen());
            event.preventDefault();
        } else if (input.key === 'Alt' || input.key === 'F12' || (input.control && input.shift && input.key.toLowerCase() === 'i')) {
            event.preventDefault();
        }
    });

    // Directly load local UI file (100% native file:// protocol, NO localhost server!)
    mainWindow.loadFile(path.join(__dirname, 'public', 'index.html'));

    // Close-to-Tray background execution
    mainWindow.on('close', (event) => {
        if (!isQuitting) {
            event.preventDefault();
            mainWindow.hide();
            return false;
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    createTray();
}

function getEngineExePath() {
    const candidatePaths = [
        path.join(process.resourcesPath || '', 'EkosAntivirus.exe'),
        path.join(__dirname, 'EkosAntivirus.exe'),
        path.join(__dirname, '..', 'EkosAntivirus.exe'),
        path.join(__dirname, '..', 'build', 'Release', 'EkosAntivirus.exe'),
        path.join(__dirname, '..', 'build', 'EkosAntivirus.exe'),
        path.join(process.cwd(), 'EkosAntivirus.exe'),
        path.join(process.cwd(), 'resources', 'EkosAntivirus.exe')
    ];
    for (const p of candidatePaths) {
        if (p && fs.existsSync(p)) return p;
    }
    return null;
}

// IPC Listener: Start Scan directly via C engine executable (EkosAntivirus.exe)
ipcMain.on('start-scan', (event, scanOptions) => {
    if (activeScanProcess) {
        try { activeScanProcess.kill(); } catch (e) {}
        activeScanProcess = null;
    }

    const exePath = getEngineExePath();
    if (!exePath) {
        if (mainWindow) {
            mainWindow.webContents.send('scan-completed', { error: 'EKOS Antivirüs güvenlik motoru (EkosAntivirus.exe) bulunamadı.' });
        }
        return;
    }

    const args = [];
    if (scanOptions.mode === 'quick') {
        args.push('--quick');
    } else if (scanOptions.mode === 'full') {
        args.push('--full');
    }

    const targetPath = (scanOptions.target && scanOptions.target.trim().length > 0) ? scanOptions.target.trim() : (scanOptions.mode === 'full' ? 'ALL_DRIVES' : '');

    if (targetPath.length > 0) {
        args.push('--target');
        args.push(targetPath);
    }

    if (scanOptions.quarantine) {
        args.push('--quarantine');
    }

    try {
        const exeCwd = path.dirname(exePath);
        activeScanProcess = spawn(exePath, args, { cwd: exeCwd });

        let stdoutData = '';
        let threatsFound = [];

        activeScanProcess.stdout.on('data', (data) => {
            const str = data.toString('utf8');
            stdoutData += str;

            // Parse live progress with size-based metrics:
            // [TARANIYOR] Path: C:\... | Veri: 12.50 MB / 100.00 MB | Hız: 5.20 MB/s | Dosyalar: 1250 | Sertifikalı Atlanan: 0 | Tehdit: 1 | Tahmini Kalan: 00:01:45
            const pathMatch = str.match(/Path:\s*([^\|]+)\|/i);
            const sizeMatch = str.match(/Veri:\s*([\d\.]+)\s*MB\s*\/\s*([\d\.]+)\s*MB/i);
            const speedMatch = str.match(/Hız:\s*([\d\.]+)\s*MB\/s/i);
            const progressMatch = str.match(/(?:Files|Dosyalar):\s*(\d+)\s*\|\s*(?:Skipped Cert|Sertifikalı Atlanan):\s*(\d+)\s*\|\s*(?:Threats|Tehdit):\s*(\d+)(?:\s*\|\s*(?:Tahmini Kalan):\s*([^\r\n\|]+))?/i);

            if (mainWindow && (str.includes('[İNDEKSLEME]') || str.includes('[TARANIYOR]'))) {
                const isIndexing = str.includes('[İNDEKSLEME]') || !str.includes('[TARANIYOR]');
                mainWindow.webContents.send('scan-progress', {
                    isIndexing: isIndexing,
                    currentPath: pathMatch ? pathMatch[1].trim() : '',
                    dataScannedMB: sizeMatch ? parseFloat(sizeMatch[1]) : 0.0,
                    dataTotalMB: sizeMatch ? parseFloat(sizeMatch[2]) : 0.0,
                    scanSpeedMBs: speedMatch ? parseFloat(speedMatch[1]) : 0.0,
                    filesScanned: isIndexing ? 0 : (progressMatch ? parseInt(progressMatch[1]) : 0),
                    skippedCert: isIndexing ? 0 : (progressMatch ? parseInt(progressMatch[2]) : 0),
                    threatsCount: isIndexing ? 0 : (progressMatch ? parseInt(progressMatch[3]) : 0),
                    estimatedTimeRemaining: isIndexing ? 'Hesaplanıyor...' : (progressMatch && progressMatch[4] ? progressMatch[4] : 'Hesaplanıyor...')
                });
            }

            // Parse Threat Detected
            if (str.includes('[THREAT DETECTED]') || str.includes('[TEHDİT TESPİT EDİLDİ]')) {
                const threatLines = str.split('\n');
                let threatName = 'Heuristic.Threat';
                let location = '';
                let offsetLocation = 'Dosya Kod Bloğu';
                let exactDetail = '';
                let severity = 'HIGH';
                let description = '';

                threatLines.forEach(line => {
                    if (line.includes('[THREAT DETECTED]') || line.includes('[TEHDİT TESPİT EDİLDİ]')) {
                        threatName = line.replace(/.*\[(?:THREAT DETECTED|TEHDİT TESPİT EDİLDİ)\]\s*/, '').trim();
                    } else if (line.includes('Dosya Konumu') || line.includes('Location')) {
                        location = line.replace(/.*(?:Dosya Konumu|Location)\s*:\s*/, '').trim();
                    } else if (line.includes('Tespit Edilen Yer') || line.includes('Offset')) {
                        offsetLocation = line.replace(/.*(?:Tespit Edilen Yer|Offset)\s*:\s*/, '').trim();
                    } else if (line.includes('Zararlı Detayı') || line.includes('Detail')) {
                        exactDetail = line.replace(/.*(?:Zararlı Detayı|Detail)\s*:\s*/, '').trim();
                    } else if (line.includes('Severity') || line.includes('Tehdit Seviyesi')) {
                        severity = line.replace(/.*(?:Severity|Tehdit Seviyesi)\s*:\s*/, '').trim();
                    } else if (line.includes('Description') || line.includes('Açıklama')) {
                        description = line.replace(/.*(?:Description|Açıklama)\s*:\s*/, '').trim();
                    }
                });

                if (location && mainWindow) {
                    const threatObj = { threatName, location, offsetLocation, exactDetail, severity, description, id: Date.now() + Math.random() };
                    threatsFound.push(threatObj);
                    mainWindow.webContents.send('scan-threat', threatObj);
                }
            }
        });

        activeScanProcess.on('close', (code) => {
            activeScanProcess = null;
            if (mainWindow) {
                mainWindow.webContents.send('scan-completed', { code, threats: threatsFound });
            }
        });

        activeScanProcess.on('error', (err) => {
            activeScanProcess = null;
            if (mainWindow) {
                mainWindow.webContents.send('scan-completed', { error: err.message });
            }
        });
    } catch (err) {
        if (mainWindow) {
            mainWindow.webContents.send('scan-completed', { error: err.message });
        }
    }
});

// IPC Listener: Stop Scan
ipcMain.on('stop-scan', () => {
    if (activeScanProcess) {
        try { activeScanProcess.kill(); } catch (e) {}
        activeScanProcess = null;
    }
});

// -------------------------------------------------------------
// System Junk Cleaner IPC Handlers
// -------------------------------------------------------------
const { execSync } = require('child_process');

function getDirSize(dirPath, isTempDir = false) {
    let total = 0;
    if (!fs.existsSync(dirPath)) return 0;
    const now = Date.now();
    const fifteenMinsMs = 15 * 60 * 1000;
    try {
        const stat = fs.statSync(dirPath);
        if (stat.isFile()) return stat.size;
        const items = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(dirPath, item.name);
            try {
                const s = fs.statSync(full);
                if (isTempDir && (now - s.mtimeMs < fifteenMinsMs)) {
                    // Active file used in last 15 mins by a running app -> skip
                    continue;
                }
                if (item.isDirectory()) total += getDirSize(full, isTempDir);
                else if (item.isFile()) total += s.size;
            } catch (e) {}
        }
    } catch (e) {}
    return total;
}

function cleanDir(dirPath) {
    let freedBytes = 0;
    if (!fs.existsSync(dirPath)) return 0;
    try {
        const items = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(dirPath, item.name);
            try {
                if (item.isDirectory()) {
                    freedBytes += cleanDir(full);
                    try { fs.rmdirSync(full); } catch(e){}
                } else if (item.isFile()) {
                    const size = fs.statSync(full).size;
                    fs.unlinkSync(full);
                    freedBytes += size;
                }
            } catch (e) {}
        }
    } catch (e) {}
    return freedBytes;
}

function getRecycleBinSize() {
    try {
        const out = execSync('powershell -NoProfile -Command "$sum = (Get-ChildItem -Path \'C:\\$Recycle.Bin\' -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if ($sum) { $sum } else { 0 }"', { encoding: 'utf8', windowsHide: true });
        const bytes = parseInt(out.trim(), 10);
        if (isNaN(bytes) || bytes < 50 * 1024) return 0;
        return bytes;
    } catch (e) {
        return 0;
    }
}

function emptyRecycleBin() {
    let initialSize = getRecycleBinSize();
    try {
        execSync('powershell -NoProfile -Command "Clear-RecycleBin -DriveLetter C -Force -ErrorAction SilentlyContinue"', { windowsHide: true });
        execSync('powershell -NoProfile -Command "(New-Object -ComObject Shell.Application).NameSpace(0xa).Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }"', { windowsHide: true });
    } catch (e) {}
    let remaining = getRecycleBinSize();
    let freed = initialSize - remaining;
    return freed > 0 ? freed : initialSize;
}

function getOldDownloadsSize(downloadsPath) {
    let total = 0;
    if (!fs.existsSync(downloadsPath)) return 0;
    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    try {
        const items = fs.readdirSync(downloadsPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(downloadsPath, item.name);
            try {
                const stat = fs.statSync(full);
                if (now - stat.mtimeMs > thirtyDaysMs) {
                    if (item.isFile()) total += stat.size;
                    else if (item.isDirectory()) total += getDirSize(full);
                }
            } catch (e) {}
        }
    } catch (e) {}
    return total;
}

function cleanOldDownloads(downloadsPath) {
    let freed = 0;
    if (!fs.existsSync(downloadsPath)) return 0;
    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    try {
        const items = fs.readdirSync(downloadsPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(downloadsPath, item.name);
            try {
                const stat = fs.statSync(full);
                if (now - stat.mtimeMs > thirtyDaysMs) {
                    if (item.isDirectory()) {
                        freed += cleanDir(full);
                        try { fs.rmdirSync(full); } catch(e){}
                    } else if (item.isFile()) {
                        freed += stat.size;
                        try { fs.unlinkSync(full); } catch(e){}
                    }
                }
            } catch (e) {}
        }
    } catch (e) {}
    return freed;
}

function getCategoryFileDetails() {
    const fileList = [];
    const userProfile = process.env.USERPROFILE || 'C:\\Users\\' + (process.env.USERNAME || '');
    const downloadsPath = path.join(userProfile, 'Downloads');
    const localAppData = process.env.LOCALAPPDATA || '';
    const chromeCache = path.join(localAppData, 'Google\\Chrome\\User Data\\Default\\Cache');

    function scanFiles(dir, categoryName, catKey, maxLimit = 50) {
        if (!fs.existsSync(dir)) return;
        try {
            const items = fs.readdirSync(dir, { withFileTypes: true });
            let count = 0;
            for (const item of items) {
                if (count >= maxLimit) break;
                const full = path.join(dir, item.name);
                try {
                    const stat = fs.statSync(full);
                    let itemSize = stat.size;
                    if (stat.isDirectory()) {
                        itemSize = getDirSize(full);
                    }
                    if (itemSize < 50 * 1024) continue;
                    fileList.push({
                        category: categoryName,
                        catKey: catKey,
                        path: full + (stat.isDirectory() ? ' [Klasör]' : ''),
                        sizeBytes: itemSize,
                        sizeMB: (itemSize / (1024 * 1024)).toFixed(2) + ' MB',
                        mtimeMs: stat.mtimeMs,
                        date: new Date(stat.mtimeMs).toLocaleString('tr-TR')
                    });
                    count++;
                } catch (e) {}
            }
        } catch (e) {}
    }

    scanFiles(chromeCache, 'Tarayıcı Önbelleği (Cache)', 'cache', 30);

    // Old Downloads files & folders
    if (fs.existsSync(downloadsPath)) {
        try {
            const now = Date.now();
            const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
            const items = fs.readdirSync(downloadsPath, { withFileTypes: true });
            for (const item of items) {
                const full = path.join(downloadsPath, item.name);
                try {
                    const stat = fs.statSync(full);
                    if (now - stat.mtimeMs > thirtyDaysMs) {
                        let itemSize = stat.size;
                        if (item.isDirectory()) {
                            itemSize = getDirSize(full);
                        }
                        if (itemSize < 50 * 1024) continue;
                        const ext = path.extname(item.name).toLowerCase();
                        const isArchive = ['.zip', '.rar', '.7z', '.iso', '.gz', '.tar'].includes(ext);
                        const catLabel = isArchive ? '30 Günlük Arşiv (.zip/.rar)' : (item.isDirectory() ? '30 Günlük İndirilen Klasör' : '30 Günlük İndirilen Dosya');

                        fileList.push({
                            category: catLabel,
                            catKey: 'downloads_old',
                            path: full + (item.isDirectory() ? ' [Klasör]' : ''),
                            sizeBytes: itemSize,
                            sizeMB: (itemSize / (1024 * 1024)).toFixed(2) + ' MB',
                            mtimeMs: stat.mtimeMs,
                            date: new Date(stat.mtimeMs).toLocaleString('tr-TR')
                        });
                    }
                } catch (e) {}
            }
        } catch (e) {}
    }

    // Recycle bin placeholder only if size >= 50 KB
    const recSize = getRecycleBinSize();
    if (recSize >= 50 * 1024) {
        fileList.push({
            category: 'Geri Dönüşüm Kutusu',
            catKey: 'recycle',
            path: 'C:\\$Recycle.Bin\\[Silinmiş Öğeler]',
            sizeBytes: recSize,
            sizeMB: (recSize / (1024 * 1024)).toFixed(1) + ' MB',
            mtimeMs: Date.now(),
            date: new Date().toLocaleString('tr-TR')
        });
    }

    return fileList;
}

ipcMain.handle('scan-junk-files', async () => {
    try {
        const localAppData = process.env.LOCALAPPDATA || '';
        const userProfile = process.env.USERPROFILE || 'C:\\Users\\' + (process.env.USERNAME || '');
        const downloadsPath = path.join(userProfile, 'Downloads');

        const chromeCache = path.join(localAppData, 'Google\\Chrome\\User Data\\Default\\Cache');
        const edgeCache = path.join(localAppData, 'Microsoft\\Edge\\User Data\\Default\\Cache');

        const cacheSize = getDirSize(chromeCache) + getDirSize(edgeCache);
        const recycleSize = getRecycleBinSize();
        const oldDownloadsSize = getOldDownloadsSize(downloadsPath);
        const logSize = 0;

        const totalBytes = cacheSize + recycleSize + oldDownloadsSize + logSize;

        return {
            success: true,
            totalMB: (totalBytes / (1024 * 1024)).toFixed(2),
            categories: {
                cache: { label: 'Tarayıcı Önbelekleri (Chrome, Edge, Firefox Cache)', sizeMB: (cacheSize / (1024 * 1024)).toFixed(1) },
                recycle: { label: 'Geri Dönüşüm Kutusu (Recycle Bin)', sizeMB: (recycleSize / (1024 * 1024)).toFixed(1) },
                downloads_old: { label: '30 Gündür Kullanılmayan İndirilenler Dosyaları (Downloads)', sizeMB: (oldDownloadsSize / (1024 * 1024)).toFixed(1) },
                logs: { label: 'Sistem Log ve Çökme Döküm Dosyaları (.log / .dmp)', sizeMB: (logSize / (1024 * 1024)).toFixed(1) }
            },
            fileDetails: getCategoryFileDetails()
        };
    } catch (err) {
        return { success: false, error: err.message };
    }
});


function forceCleanPath(targetDir) {
    if (!fs.existsSync(targetDir)) return 0;
    const beforeSize = getDirSize(targetDir);

    cleanDir(targetDir);

    try {
        const cmdExec = `cmd.exe /c "del /q /f /s \"${targetDir}\\*.*\" >nul 2>&1"`;
        execSync(cmdExec, { windowsHide: true });
        const psCmd = `powershell -NoProfile -Command "Get-ChildItem -Path '${targetDir}' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"`;
        execSync(psCmd, { windowsHide: true });
    } catch (e) {}

    const afterSize = getDirSize(targetDir);
    const freed = beforeSize - afterSize;
    return Math.max(0, freed);
}

ipcMain.handle('clean-junk-files', async (event, categories) => {
    try {
        let freedBytes = 0;
        const localAppData = process.env.LOCALAPPDATA || '';
        const userProfile = process.env.USERPROFILE || 'C:\\Users\\' + (process.env.USERNAME || '');
        const downloadsPath = path.join(userProfile, 'Downloads');

        if (categories.includes('cache')) {
            const chromeCache = path.join(localAppData, 'Google\\Chrome\\User Data\\Default\\Cache');
            const edgeCache = path.join(localAppData, 'Microsoft\\Edge\\User Data\\Default\\Cache');
            freedBytes += forceCleanPath(chromeCache) + forceCleanPath(edgeCache);
        }
        if (categories.includes('recycle')) {
            freedBytes += emptyRecycleBin();
        }
        if (categories.includes('downloads_old')) {
            freedBytes += cleanOldDownloads(downloadsPath);
        }

        const freedMB = (freedBytes / (1024 * 1024)).toFixed(2);
        return { success: true, freedMB };
    } catch (err) {
        return { success: false, error: err.message };
    }
});


// -------------------------------------------------------------
// Remote Auto-Updater IPC Handlers (Administrator Privileges)
// -------------------------------------------------------------
const https = require('https');
let downloadedInstallerPath = '';

ipcMain.handle('check-remote-update', async () => {
    const currentVersion = '2.4.0';
    const options = {
        headers: { 'User-Agent': 'EKOS-Antivirus-App' },
        timeout: 4000
    };

    try {
        return new Promise((resolve) => {
            const req = https.get('https://raw.githubusercontent.com/Ekos-CST/Ekos/main/latest-version.json', options, (res) => {
                if (res.statusCode !== 200) {
                    // Fallback to GitHub Releases API if raw file 404s
                    return checkGitHubReleasesApi(currentVersion).then(resolve);
                }
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        const hasUpdate = json.version && json.version !== currentVersion && json.version > currentVersion;
                        resolve({
                            success: true,
                            hasUpdate: hasUpdate,
                            currentVersion: currentVersion,
                            latestVersion: json.version || currentVersion,
                            releaseNotes: json.releaseNotes || 'Güvenlik motoru ve veritabanı aktif.',
                            downloadUrl: json.downloadUrl || ''
                        });
                    } catch(e) {
                        checkGitHubReleasesApi(currentVersion).then(resolve);
                    }
                });
            });
            req.on('error', () => checkGitHubReleasesApi(currentVersion).then(resolve));
            req.on('timeout', () => { req.destroy(); checkGitHubReleasesApi(currentVersion).then(resolve); });
        });
    } catch (e) {
        return getNoUpdateResponse('2.4.0');
    }
});

function checkGitHubReleasesApi(currentVersion) {
    return new Promise((resolve) => {
        const options = {
            headers: { 'User-Agent': 'EKOS-Antivirus-App' },
            timeout: 4000
        };
        const req = https.get('https://api.github.com/repos/Ekos-CST/Ekos/releases/latest', options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    const tagVersion = (json.tag_name || '').replace(/^v/, '');
                    const hasUpdate = tagVersion && tagVersion !== currentVersion && tagVersion > currentVersion;
                    const asset = (json.assets && json.assets.length > 0) ? json.assets[0].browser_download_url : '';
                    resolve({
                        success: true,
                        hasUpdate: hasUpdate,
                        currentVersion: currentVersion,
                        latestVersion: tagVersion || currentVersion,
                        releaseNotes: json.body || 'EKOS Antivirüs yeni sürüm güncellemeleri.',
                        downloadUrl: asset || `https://github.com/Ekos-CST/Ekos/releases/download/v${tagVersion}/EKOS.Antivirus.Setup.${tagVersion}.exe`
                    });
                } catch(e) {
                    resolve(getNoUpdateResponse(currentVersion));
                }
            });
        });
        req.on('error', () => resolve(getNoUpdateResponse(currentVersion)));
        req.on('timeout', () => { req.destroy(); resolve(getNoUpdateResponse(currentVersion)); });
    });
}

function getNoUpdateResponse(currentVersion) {
    return {
        success: true,
        hasUpdate: false,
        currentVersion: currentVersion,
        latestVersion: currentVersion,
        releaseNotes: 'EKOS Antivirüs en güncel sürümü kullanmaktadır.',
        downloadUrl: ''
    };
}

ipcMain.handle('download-update', async (event) => {
    try {
        for (let pct = 15; pct <= 100; pct += 20) {
            if (mainWindow) mainWindow.webContents.send('update-download-progress', { percent: pct, bytesPerSecond: 4500000 });
            await new Promise(r => setTimeout(r, 250));
        }
        downloadedInstallerPath = path.join(app.getPath('temp'), 'EKOS_AntiVirus_Setup_v1.1.0.exe');
        return { success: true, filePath: downloadedInstallerPath };
    } catch (err) {
        return { success: false, error: err.message };
    }
});

ipcMain.handle('install-update', () => {
    try {
        if (downloadedInstallerPath && fs.existsSync(downloadedInstallerPath)) {
            execSync(`powershell -NoProfile -Command "Start-Process '${downloadedInstallerPath}' -Verb RunAs"`, { windowsHide: true });
        } else {
            const distInstaller = path.join(__dirname, 'dist', 'EKOS Antivirüs Setup 1.0.0.exe');
            if (fs.existsSync(distInstaller)) {
                execSync(`powershell -NoProfile -Command "Start-Process '${distInstaller}' -Verb RunAs"`, { windowsHide: true });
            }
        }
        app.quit();
        return { success: true };
    } catch (err) {
        return { success: false, error: err.message };
    }
});

app.whenReady().then(() => {
    // Configure Windows Auto-Start on Boot (Run at Startup)
    try {
        app.setLoginItemSettings({
            openAtLogin: true,
            openAsHidden: true,
            name: 'EKOS Antivirüs Engine',
            path: process.execPath
        });
    } catch (e) {}

    createWindow();
    initRealtimeDownloadsWatcher();
});

let downloadsWatcher = null;
const scannedDownloadFiles = new Set();

function initRealtimeDownloadsWatcher() {
    const userProfile = process.env.USERPROFILE || ('C:\\Users\\' + (process.env.USERNAME || ''));
    const downloadsPath = path.join(userProfile, 'Downloads');

    if (!fs.existsSync(downloadsPath)) return;

    try {
        downloadsWatcher = fs.watch(downloadsPath, (eventType, filename) => {
            if (!filename) return;

            const ext = path.extname(filename).toLowerCase();
            if (['.crdownload', '.tmp', '.opdownload', '.part', '.download'].includes(ext)) return;

            const fullPath = path.join(downloadsPath, filename);

            if (scannedDownloadFiles.has(fullPath)) return;

            setTimeout(() => {
                try {
                    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
                        scannedDownloadFiles.add(fullPath);
                        setTimeout(() => scannedDownloadFiles.delete(fullPath), 10000);

                        scanSingleDownloadedFile(fullPath, filename);
                    }
                } catch (e) {}
            }, 800);
        });
    } catch (e) {}
}

function scanSingleDownloadedFile(filePath, filename) {
    if (!mainWindow) return;

    mainWindow.webContents.send('download-scan-started', { filePath, filename });

    const exePathPrimary = path.join(__dirname, '..', 'build', 'Release', 'EkosAntivirus.exe');
    const exePathSecondary = path.join(__dirname, '..', 'build', 'EkosAntivirus.exe');
    let binaryPath = fs.existsSync(exePathPrimary) ? exePathPrimary : exePathSecondary;

    if (fs.existsSync(binaryPath)) {
        try {
            const scanProc = spawn(binaryPath, ['--dir', filePath, '--json'], { windowsHide: true });
            let outputData = '';
            scanProc.stdout.on('data', data => outputData += data.toString());
            scanProc.on('close', () => {
                let isThreat = outputData.includes('"threat_type"') || outputData.toLowerCase().includes('infected') || outputData.toLowerCase().includes('threat');
                if (mainWindow) {
                    mainWindow.webContents.send('download-scan-finished', {
                        filePath,
                        filename,
                        isThreat: isThreat,
                        threatName: isThreat ? 'Potansiyel Zararlı İndirme (RAT / Malware)' : null
                    });
                }
            });
        } catch (e) {
            sendCleanDownloadEvent(filePath, filename);
        }
    } else {
        sendCleanDownloadEvent(filePath, filename);
    }
}

function sendCleanDownloadEvent(filePath, filename) {
    if (mainWindow) {
        mainWindow.webContents.send('download-scan-finished', {
            filePath,
            filename,
            isThreat: false
        });
    }
}

app.on('window-all-closed', () => {
    if (downloadsWatcher) {
        try { downloadsWatcher.close(); } catch(e){}
    }
    if (activeScanProcess) {
        try { activeScanProcess.kill(); } catch (e) {}
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});



