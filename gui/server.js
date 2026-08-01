const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let activeScanProcess = null;
let sseClients = [];
let scanHistory = [];
let isScanning = false;

// Broadcast event to connected GUI clients
function sendSseEvent(event, data) {
    sseClients.forEach(client => {
        client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    });
}

// SSE Connection Endpoint
app.get('/api/scan-stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const clientId = Date.now();
    const newClient = { id: clientId, res };
    sseClients.push(newClient);

    req.on('close', () => {
        sseClients = sseClients.filter(c => c.id !== clientId);
    });
});

// Start Scan Endpoint
app.post('/api/scan', (req, res) => {
    if (isScanning) {
        return res.status(400).json({ error: 'Tarama zaten devam ediyor.' });
    }

    const { mode, target, quarantine } = req.body;
    const exePathPrimary = path.join(__dirname, '..', 'build', 'Release', 'EkosAntivirus.exe');
    const exePathFallback = path.join(__dirname, '..', 'build', 'EkosAntivirus.exe');
    const exePath = fs.existsSync(exePathPrimary) ? exePathPrimary : exePathFallback;

    if (!fs.existsSync(exePath)) {
        return res.status(404).json({ error: 'Ekos Antivirus motoru (EkosAntivirus.exe) bulunamadı. Lütfen önce derleyin.' });
    }

    const args = [];
    if (mode === 'quick') {
        args.push('--quick');
    } else {
        args.push('--full');
    }

    if (target && target.trim() !== '') {
        args.push('--target', target.trim());
    }

    if (quarantine) {
        args.push('--quarantine');
    }

    const reportPath = path.join(__dirname, '..', 'scan_report.json');
    args.push('--report', reportPath);

    isScanning = true;
    const threatsFound = [];

    sendSseEvent('scan_started', { mode, target: target || 'Default', time: new Date().toLocaleTimeString() });

    try {
        activeScanProcess = spawn(exePath, args, { cwd: path.join(__dirname, '..') });

        let stdoutData = '';

        activeScanProcess.stdout.on('data', (data) => {
            const str = data.toString('utf8');
            stdoutData += str;

            // Parse live progress with size-based metrics:
            // [TARANIYOR] Path: C:\... | Veri: 12.50 MB / 100.00 MB | Hız: 5.20 MB/s | Dosyalar: 1250 | Sertifikalı Atlanan: 0 | Tehdit: 1 | Tahmini Kalan: 00:01:45
            const pathMatch = str.match(/Path:\s*([^\|]+)\|/i);
            const sizeMatch = str.match(/Veri:\s*([\d\.]+)\s*MB\s*\/\s*([\d\.]+)\s*MB/i);
            const speedMatch = str.match(/Hız:\s*([\d\.]+)\s*MB\/s/i);
            const progressMatch = str.match(/(?:Files|Dosyalar):\s*(\d+)\s*\|\s*(?:Skipped Cert|Sertifikalı Atlanan):\s*(\d+)\s*\|\s*(?:Threats|Tehdit):\s*(\d+)(?:\s*\|\s*(?:Tahmini Kalan):\s*([^\r\n\|]+))?/i);

            if (progressMatch) {
                sendSseEvent('progress', {
                    currentPath: pathMatch ? pathMatch[1].trim() : '',
                    dataScannedMB: sizeMatch ? parseFloat(sizeMatch[1]) : 0.0,
                    dataTotalMB: sizeMatch ? parseFloat(sizeMatch[2]) : 0.0,
                    scanSpeedMBs: speedMatch ? parseFloat(speedMatch[1]) : 0.0,
                    filesScanned: parseInt(progressMatch[1]),
                    skippedCert: parseInt(progressMatch[2]),
                    threatsCount: parseInt(progressMatch[3]),
                    estimatedTimeRemaining: progressMatch[4] || 'Hesaplanıyor...'
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

                if (location) {
                    const threatObj = { threatName, location, offsetLocation, exactDetail, severity, description, id: Date.now() + Math.random() };
                    threatsFound.push(threatObj);
                    sendSseEvent('threat_detected', threatObj);
                }
            }
        });

        activeScanProcess.on('close', (code) => {
            isScanning = false;
            activeScanProcess = null;

            // Try to load scan_report.json
            let reportData = null;
            if (fs.existsSync(reportPath)) {
                try {
                    const raw = fs.readFileSync(reportPath, 'utf8');
                    reportData = JSON.parse(raw);
                } catch (e) {}
            }

            sendSseEvent('scan_completed', {
                exitCode: code,
                threats: threatsFound,
                report: reportData
            });
        });

        res.json({ success: true, message: 'Tarama başlatıldı.' });

    } catch (err) {
        isScanning = false;
        res.status(500).json({ error: err.message });
    }
});

// Stop Scan Endpoint
app.post('/api/stop-scan', (req, res) => {
    if (activeScanProcess && isScanning) {
        activeScanProcess.kill();
        isScanning = false;
        activeScanProcess = null;
        sendSseEvent('scan_stopped', { message: 'Tarama kullanıcı tarafından durduruldu.' });
        return res.json({ success: true, message: 'Tarama durduruldu.' });
    }
    res.json({ success: false, message: 'Aktif bir tarama yok.' });
});

// Get Scan Report Endpoint
app.get('/api/report', (req, res) => {
    const reportPath = path.join(__dirname, '..', 'scan_report.json');
    if (fs.existsSync(reportPath)) {
        res.sendFile(reportPath);
    } else {
        res.status(404).json({ error: 'Henüz rapor oluşturulmadı.' });
    }
});

app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` EKOS ANTİVİRÜS GUI DASHBOARD YAYINDA`);
    console.log(` Arayüze erişmek için: http://localhost:${PORT}`);
    console.log(`=======================================================`);
});
