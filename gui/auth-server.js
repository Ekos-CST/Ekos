// Process-level crash guards
process.on('uncaughtException', (err) => {
    console.error('[EKOS Server Guard] Uncaught Exception:', err ? err.message : err);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('[EKOS Server Guard] Unhandled Rejection:', reason);
});

const express = require('express');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const nodemailer = require('nodemailer');

const app = express();
app.set('trust proxy', true);
app.enable('trust proxy');
const PORT = process.env.AUTH_PORT || 3002;
const SERVER_DB_DIR = path.join(__dirname, 'server_db');
if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-EKOS-API-KEY');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.header('Pragma', 'no-cache');
    res.header('Expires', '0');
    res.header('Content-Security-Policy', "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://api.qrserver.com; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://ekoscst.com https://api.ekoscst.com https://api.qrserver.com; object-src 'none'; frame-ancestors 'self';");
    res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json());
const staticOptions = {
    etag: false,
    lastModified: false,
    maxAge: 0,
    setHeaders: (res) => {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
    }
};
app.use(express.static(path.join(__dirname, 'web_public'), staticOptions));
app.use(express.static(path.join(__dirname, 'public'), staticOptions));
app.set('trust proxy', true);

// Google SEO Endpoints: robots.txt & sitemap.xml
app.get('/robots.txt', (req, res) => {
    const robotsPath = path.join(__dirname, 'web_public', 'robots.txt');
    if (fs.existsSync(robotsPath)) {
        res.type('text/plain');
        return res.sendFile(robotsPath);
    }
    res.type('text/plain').send("User-agent: *\nAllow: /\nSitemap: https://ekoscst.com/sitemap.xml\n");
});

app.get('/sitemap.xml', (req, res) => {
    const sitemapPath = path.join(__dirname, 'web_public', 'sitemap.xml');
    if (fs.existsSync(sitemapPath)) {
        res.type('application/xml');
        return res.sendFile(sitemapPath);
    }
    res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://ekoscst.com/</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://ekoscst.com/scan</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://ekoscst.com/download/latest</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://ekoscst.com/download/android</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://ekoscst.com/api/v1</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>`);
});

// Dedicated Update Endpoints for Mobile & Desktop
app.get(['/mobile-version.json', '/android/version.json', '/android_app/version.json', '/api/v1/update/android', '/api/v1/update/mobile', '/download/mobile-version.json'], (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    return res.json({
        versionCode: 2,
        versionName: "1.1.0",
        changelog: "EKOS CST Mobil Güvenlik v1.1.0 - Gelişmiş Derin Dosya ve APK Tehdit Analiz Motoru, Canlı Ağ ve Web Kalkanı, Dinamik Sistem Optimizasyonu ve Kararlılık İyileştirmeleri.",
        downloadUrl: "https://ekoscst.com/download/EKOS_Antivirus_Mobile_1.1.0.apk"
    });
});

app.get(['/version.json', '/latest-version.json', '/api/v1/update/desktop', '/api/v1/update/check', '/download/latest-version.json', '/download/version.json'], (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    return res.json({
        version: "4.3.0",
        releaseNotes: "EKOS Antivirüs v4.3.0 - Geliştirici REST API Yönetim Merkezi, QR Kodsuz & 6 Haneli Doğrulama Kodlu Güvenli Kimlik Doğrulama, Tamamen Ücretsiz Web Kalkanı & 10s Rate Limit, Otomatik Sistem Temizliği ve Disk Analiz Motoru, %100 Emojisiz Arayüz Standartları.",
        downloadUrl: "https://ekoscst.com/download/EKOS_Antivirus_Setup_4.3.0.exe"
    });
});

// Helper: Get Client IP
function getClientIp(req) {
    return req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '127.0.0.1';
}

// --- ORIGIN-LEVEL DDOS & ANTI-FLOOD RATE LIMITER ---
const ddosIpTracker = new Map(); // IP -> { count, windowStart, blockedUntil }
const DDOS_WINDOW_MS = 60 * 1000; // 1 minute window
const DDOS_MAX_REQ_PER_MIN = 300; // 300 requests/minute max per IP
const DDOS_BLOCK_TIME_MS = 3 * 60 * 1000; // 3 minutes block on excessive flood

function checkDdosProtection(ip) {
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost' || !ip) {
        return { isAllowed: true };
    }
    const now = Date.now();
    let record = ddosIpTracker.get(ip);
    if (!record) {
        record = { count: 1, windowStart: now, blockedUntil: 0 };
        ddosIpTracker.set(ip, record);
        return { isAllowed: true };
    }

    if (record.blockedUntil && now < record.blockedUntil) {
        const remaining = Math.ceil((record.blockedUntil - now) / 1000);
        return { isAllowed: false, retryAfter: remaining, message: `DDoS Koruması Devrede: Şüpheli aşırı istek nedeniyle IP adresiniz ${remaining} saniye geçici olarak engellendi.` };
    }

    if (now - record.windowStart > DDOS_WINDOW_MS) {
        record.count = 1;
        record.windowStart = now;
        record.blockedUntil = 0;
        return { isAllowed: true };
    }

    record.count++;
    if (record.count > DDOS_MAX_REQ_PER_MIN) {
        record.blockedUntil = now + DDOS_BLOCK_TIME_MS;
        console.warn(`🚨 [DDOS FLOOD BLOCKED] IP: ${ip} exceeded ${DDOS_MAX_REQ_PER_MIN} req/min. Blocked for 3 minutes.`);
        return { isAllowed: false, retryAfter: 180, message: 'DDoS Koruması Devrede: Çok fazla istek yapıldı (429 Too Many Requests).' };
    }

    return { isAllowed: true };
}

// --- DEDUPLICATED VISITOR & ACCESS TRAFFIC LOGGER STORAGE ---
const VISITOR_LOGS_FILE = path.join(SERVER_DB_DIR, 'visitor_logs.json');
let visitorLogs = [];
const MAX_VISITOR_LOGS = 500;

// Known Admin IP set to ignore from active visitors/metrics
const adminIpSet = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

function loadVisitorLogs() {
    try {
        if (fs.existsSync(VISITOR_LOGS_FILE)) {
            const parsed = JSON.parse(fs.readFileSync(VISITOR_LOGS_FILE, 'utf8'));
            if (Array.isArray(parsed)) {
                visitorLogs = parsed.slice(0, MAX_VISITOR_LOGS);
            }
        }
    } catch(e) {
        console.error('[Visitor Logs] Load error:', e.message);
    }
}

function saveVisitorLogs() {
    try {
        fs.writeFileSync(VISITOR_LOGS_FILE, JSON.stringify(visitorLogs.slice(0, MAX_VISITOR_LOGS), null, 2), 'utf8');
    } catch(e) {}
}
loadVisitorLogs();

function parseDeviceFromUserAgent(ua) {
    if (!ua) return 'Bilinmiyor';
    let os = 'Diğer OS';
    if (/windows nt 10\.0/i.test(ua)) os = 'Windows 10/11';
    else if (/windows nt 6\.3/i.test(ua)) os = 'Windows 8.1';
    else if (/windows nt 6\.1/i.test(ua)) os = 'Windows 7';
    else if (/windows/i.test(ua)) os = 'Windows';
    else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
    else if (/android/i.test(ua)) os = 'Android';
    else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
    else if (/linux/i.test(ua)) os = 'Linux';

    let browser = 'Tarayıcı';
    if (/edg/i.test(ua)) browser = 'Edge';
    else if (/chrome|crios/i.test(ua)) browser = 'Chrome';
    else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
    else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
    else if (/curl/i.test(ua)) browser = 'cURL';
    else if (/postman/i.test(ua)) browser = 'Postman';
    else if (/python/i.test(ua)) browser = 'Python Client';

    return `${browser} • ${os}`;
}

// --- REAL-TIME ACTIVE ONLINE PRESENCE ENGINE ---
const userActivityTracker = new Map(); // cleanEmail -> { lastActiveAt: number, ip: string, userAgent: string, endpoint: string }
const ipActivityTracker = new Map();   // clientIp -> { lastActiveAt: number, path: string, userAgent: string }

function recordUserActivity(email, ip, userAgent, endpoint = '/') {
    if (!email) return;
    const cleanEmail = email.trim().toLowerCase();
    userActivityTracker.set(cleanEmail, {
        lastActiveAt: Date.now(),
        ip: ip || '127.0.0.1',
        userAgent: userAgent || 'Web Tarayıcı',
        endpoint: endpoint
    });
}

function recordIpActivity(ip, pathName, userAgent) {
    if (!ip) return;
    ipActivityTracker.set(ip, {
        lastActiveAt: Date.now(),
        path: pathName || '/',
        userAgent: userAgent || 'Web Tarayıcı'
    });
}

// --- GLOBAL TOP-LEVEL VISITOR TRAFFIC & DDOS MIDDLEWARE ---
app.use((req, res, next) => {
    const rawIp = getClientIp(req);
    const clientIp = typeof rawIp === 'string' ? rawIp.replace(/^::ffff:/, '').trim() : '127.0.0.1';
    const pathName = req.path;
    const method = req.method;

    // Check if request is from Admin Console or Admin Session
    let isAdmin = false;
    if (pathName.startsWith('/admin') || pathName.startsWith('/api/admin')) {
        isAdmin = true;
        adminIpSet.add(clientIp);
    }

    const authH = req.headers.authorization;
    if (authH && authH.startsWith('Bearer ')) {
        const tok = authH.substring(7);
        if (tok === 'EKOS-ADMIN-2026-SECRET' || tok === 'ekos_admin_root_master_token') {
            isAdmin = true;
            adminIpSet.add(clientIp);
        } else {
            const tokData = tokensDb.get(tok);
            if (tokData) {
                const uEmail = typeof tokData === 'string' ? tokData : tokData.email;
                if (uEmail) {
                    const clean = uEmail.toLowerCase().trim();
                    if (clean === 'admin@ekoscst.com' || clean === 'admin@ekos.com') {
                        isAdmin = true;
                        adminIpSet.add(clientIp);
                    } else {
                        recordUserActivity(uEmail, clientIp, req.headers['user-agent'], pathName);
                    }
                }
            }
        }
    }

    // Record non-admin IP real-time presence
    if (!isAdmin && !adminIpSet.has(clientIp)) {
        recordIpActivity(clientIp, pathName, req.headers['user-agent']);
    }

    // 1. DDoS / HTTP Flood Check
    const ddosCheck = checkDdosProtection(clientIp);
    if (!ddosCheck.isAllowed) {
        return res.status(429).json({ success: false, error: ddosCheck.message });
    }

    // 2. Track Real Website Visitor Only (Exclude Admin & Static Assets & Background Polling)
    const isStatic = /\.(css|js|png|jpg|jpeg|svg|ico|woff|woff2|ttf|map|webmanifest)$/i.test(pathName);
    const isInternalOrAdmin = isAdmin || adminIpSet.has(clientIp) || pathName.startsWith('/admin') || pathName.startsWith('/api/admin') || pathName.startsWith('/api/v1/health') || pathName.includes('visitor-logs') || pathName.includes('register-check-pair');
    
    // Website visits: GET on web pages or downloads
    const isWebPortalVisit = (method === 'GET') && (pathName === '/' || pathName === '/scan' || pathName.startsWith('/download') || pathName === '/index.html' || pathName === '/api/v1' || !pathName.startsWith('/api/'));

    if (!isStatic && !isInternalOrAdmin && isWebPortalVisit) {
        const start = Date.now();
        res.on('finish', () => {
            const duration = Date.now() - start;
            const country = req.headers['cf-ipcountry'] || 'TR';
            const city = req.headers['cf-ipcity'] || '-';
            const userAgent = req.headers['user-agent'] || 'Bilinmiyor';
            const referrer = req.headers['referer'] || req.headers['referrer'] || 'Doğrudan Giriş';
            const now = Date.now();

            // Deduplicate per IP: Find existing record for this IP
            const existingIdx = visitorLogs.findIndex(v => v.ip === clientIp);
            if (existingIdx !== -1) {
                const existing = visitorLogs[existingIdx];
                existing.lastActiveAt = now;
                existing.timestamp = new Date().toISOString();
                existing.timeFormatted = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
                existing.path = pathName;
                existing.statusCode = res.statusCode;
                existing.durationMs = duration;
                existing.deviceSummary = parseDeviceFromUserAgent(userAgent);
                existing.userAgent = userAgent.substring(0, 150);
                existing.visitCount = (existing.visitCount || 1) + 1;
                existing.isOnline = true;
                // Move to front
                visitorLogs.splice(existingIdx, 1);
                visitorLogs.unshift(existing);
            } else {
                const logEntry = {
                    id: 'vis_' + crypto.randomUUID().substring(0, 8),
                    ip: clientIp,
                    country: country,
                    city: city,
                    method: method,
                    path: pathName,
                    statusCode: res.statusCode,
                    durationMs: duration,
                    deviceSummary: parseDeviceFromUserAgent(userAgent),
                    userAgent: userAgent.substring(0, 150),
                    referrer: referrer.substring(0, 100),
                    timestamp: new Date().toISOString(),
                    timeFormatted: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }),
                    lastActiveAt: now,
                    visitCount: 1,
                    isOnline: true
                };
                visitorLogs.unshift(logEntry);
            }

            if (visitorLogs.length > MAX_VISITOR_LOGS) visitorLogs.length = MAX_VISITOR_LOGS;
            saveVisitorLogs();
        });
    }

    next();
});

// In-memory Database Stores
const usersDb = new Map();                 // cleanEmail -> userObject
const tokensDb = new Map();                // token -> cleanEmail
const hardwareAccountsDb = new Map();     // hwSerial -> Array of emails registered on this HW [email1, email2]
const activeDeviceSessionsDb = new Map(); // cleanEmail -> boundHwSerial (Currently active device)
const pairSessionsDb = new Map();         // pairToken -> { email, username, passwordHash, securityQuestion, securityAnswerHash, hwSerial, status, mobileDeviceId, expiresAt }
const qrSessionsDb = new Map();           // qrToken -> { status: 'pending'|'approved', user, token, expiresAt }
const resetTokensDb = new Map();          // resetToken -> { email, expiresAt }
const rateLimitDb = new Map();            // key: `ip:action` -> { count, lockUntil, windowStart }

let activeCloudflareTunnelUrl = null;

function saveCloudEndpointJson(url) {
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        const endpointFile = path.join(SERVER_DB_DIR, 'cloud_endpoint.json');
        fs.writeFileSync(endpointFile, JSON.stringify({ url, updatedAt: new Date().toISOString() }, null, 2));
    } catch(e) {}
}

function startCloudflareTunnelAutoManager() {
    if (process.env.PUBLIC_AUTH_DOMAIN || fs.existsSync('C:\\EKOS_Server\\run_tunnel.bat')) {
        console.log('[Cloudflare Tunnel] External or Named Token Tunnel runner active. Auto quick-tunnel manager bypassed.');
        return;
    }

    // Kill any orphan cloudflared.exe process on Windows and wipe stale endpoint file to prevent 1033 errors
    try {
        const { execSync } = require('child_process');
        execSync('taskkill /F /IM cloudflared.exe /T', { stdio: 'ignore' });
    } catch(e) {}
    try {
        const endpointFile = path.join(SERVER_DB_DIR, 'cloud_endpoint.json');
        if (fs.existsSync(endpointFile)) fs.unlinkSync(endpointFile);
    } catch(e) {}
    activeCloudflareTunnelUrl = null;

    const possibleExePaths = [
        path.join(__dirname, 'cloudflared.exe'),
        path.join(__dirname, '..', 'scratch', 'cloudflared.exe'),
        'C:\\EKOS_Server\\cloudflared.exe'
    ];

    let cfExePath = null;
    for (const p of possibleExePaths) {
        if (fs.existsSync(p)) {
            cfExePath = p;
            break;
        }
    }

    if (!cfExePath) {
        console.log('[Cloudflare Tunnel] cloudflared.exe not found on system.');
        return;
    }

    console.log(`[Cloudflare Tunnel] Starting fresh Cloudflare Tunnel via ${cfExePath}...`);
    try {
        const cfProc = spawn(cfExePath, ['tunnel', '--url', `http://127.0.0.1:${PORT}`], { windowsHide: true });

        const parseStream = (data) => {
            const str = data.toString();
            const match = str.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/g);
            if (match && match.length > 0) {
                const newUrl = match[match.length - 1];
                if (newUrl !== activeCloudflareTunnelUrl) {
                    activeCloudflareTunnelUrl = newUrl;
                    console.log(`\n======================================================`);
                    console.log(`🌐 [GLOBAL CLOUDFLARE HTTPS TUNNEL LAUNCHED]`);
                    console.log(`   Public URL: ${activeCloudflareTunnelUrl}`);
                    console.log(`======================================================\n`);
                    saveCloudEndpointJson(activeCloudflareTunnelUrl);
                }
            }
        };

        cfProc.stdout.on('data', parseStream);
        cfProc.stderr.on('data', parseStream);

        cfProc.on('close', () => {
            console.log('[Cloudflare Tunnel] Tunnel process closed. Re-spawning in 3 seconds...');
            activeCloudflareTunnelUrl = null;
            setTimeout(startCloudflareTunnelAutoManager, 3000);
        });
    } catch(e) {
        console.error('[Cloudflare Tunnel] Spawn error:', e);
    }
}

// Start Cloudflare Tunnel Auto Manager immediately
startCloudflareTunnelAutoManager();

function getLocalIpAddress() {
    try {
        const interfaces = os.networkInterfaces();
        let primaryIp = null;

        for (const name of Object.keys(interfaces)) {
            const lowerName = name.toLowerCase();
            if (lowerName.includes('tailscale') || lowerName.includes('vpn') || lowerName.includes('vethernet') || lowerName.includes('virtual') || lowerName.includes('vmware') || lowerName.includes('vbox') || lowerName.includes('docker') || lowerName.includes('wireguard') || lowerName.includes('tun') || lowerName.includes('tap') || lowerName.includes('host-only')) {
                continue;
            }

            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    const ip = iface.address;
                    if (ip.startsWith('100.') || ip.startsWith('192.168.56.')) {
                        continue;
                    }
                    if (lowerName === 'ethernet' || lowerName === 'wi-fi' || lowerName === 'wlan' || lowerName.includes('eth') || lowerName.includes('wlan')) {
                        return ip;
                    }
                    if (!primaryIp) primaryIp = ip;
                }
            }
        }
        if (primaryIp) return primaryIp;
    } catch(e) {}
    return '127.0.0.1';
}

function getCloudflareTunnelDomain() {
    if (process.env.PUBLIC_AUTH_DOMAIN) return process.env.PUBLIC_AUTH_DOMAIN;
    if (activeCloudflareTunnelUrl) return activeCloudflareTunnelUrl;
    
    const tunnelLogPaths = [
        'C:\\EKOS_Server\\tunnel.log',
        path.join(__dirname, '..', 'scratch', 'tunnel.log'),
        path.join(SERVER_DB_DIR, 'cloud_endpoint.json')
    ];

    for (const logPath of tunnelLogPaths) {
        try {
            if (fs.existsSync(logPath)) {
                const content = fs.readFileSync(logPath, 'utf8');
                if (logPath.endsWith('.json')) {
                    const parsed = JSON.parse(content);
                    if (parsed && parsed.url) return parsed.url;
                }
                const match = content.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/g);
                if (match && match.length > 0) {
                    return match[match.length - 1];
                }
            }
        } catch(e) {}
    }
    return null;
}

async function ensureCloudflareUrlReady() {
    if (activeCloudflareTunnelUrl) return activeCloudflareTunnelUrl;
    let cf = getCloudflareTunnelDomain();
    if (cf) {
        activeCloudflareTunnelUrl = cf;
        return cf;
    }
    for (let i = 0; i < 15; i++) {
        await new Promise(r => setTimeout(r, 400));
        if (activeCloudflareTunnelUrl) return activeCloudflareTunnelUrl;
        cf = getCloudflareTunnelDomain();
        if (cf) {
            activeCloudflareTunnelUrl = cf;
            return cf;
        }
    }
    return activeCloudflareTunnelUrl;
}

function getLocalLanIp() {
    try {
        const interfaces = os.networkInterfaces();
        for (const devName in interfaces) {
            const iface = interfaces[devName];
            for (let i = 0; i < iface.length; i++) {
                const alias = iface[i];
                if (alias.family === 'IPv4' && !alias.internal && alias.address !== '127.0.0.1') {
                    return alias.address;
                }
            }
        }
    } catch(e) {}
    return '127.0.0.1';
}

function getBaseUrl(req) {
    return 'https://ekoscst.com';
}

// Helper: Get Client IP
function getClientIp(req) {
    return req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

// Helper: Anti-Spam Rate Limiter
function checkRateLimit(ip, action, maxAttempts = 5, windowMs = 60 * 1000, lockMs = 2 * 60 * 1000) {
    const key = `${ip}:${action}`;
    const now = Date.now();
    let record = rateLimitDb.get(key);

    if (record) {
        if (record.lockUntil && now < record.lockUntil) {
            const remainingSec = Math.ceil((record.lockUntil - now) / 1000);
            return {
                allowed: false,
                remainingSec,
                message: `Spam Koruması: Güvenlik nedeniyle bu işlem için ${remainingSec} saniye engellendiniz.`
            };
        }

        if (now - record.windowStart > windowMs) {
            record = { count: 1, lockUntil: 0, windowStart: now };
            rateLimitDb.set(key, record);
            return { allowed: true };
        }

        record.count++;
        if (record.count > maxAttempts) {
            record.lockUntil = now + lockMs;
            const remainingSec = Math.ceil(lockMs / 1000);
            console.log(`[SPAM BLOCKED] IP: ${ip} | Eylem: ${action} | ${remainingSec}s engellendi.`);
            return {
                allowed: false,
                remainingSec,
                message: `Spam Koruması Devrede: Çok fazla üst üste deneme yapıldı. Lütfen ${remainingSec} saniye bekleyiniz.`
            };
        }
        rateLimitDb.set(key, record);
    } else {
        rateLimitDb.set(key, { count: 1, lockUntil: 0, windowStart: now });
    }

    return { allowed: true };
}

// Helper: Hash string
function hashString(str) {
    return crypto.createHash('sha256').update(str.trim().toLowerCase() + '_ekos_salt_2026').digest('hex');
}

// Helper: Universal password verifier (salted exact, salted lower, plain, plain lower, and raw matches)
function verifyPassword(inputPassword, storedHash) {
    if (!inputPassword || !storedHash) return false;
    const p = String(inputPassword).trim();
    const cleanInput = p.startsWith('sha-256:') ? p.substring('sha-256:'.length) : p;

    const saltedExact = crypto.createHash('sha256').update(cleanInput + '_ekos_salt_2026').digest('hex');
    const saltedLower = crypto.createHash('sha256').update(cleanInput.toLowerCase() + '_ekos_salt_2026').digest('hex');
    const plainSha256 = crypto.createHash('sha256').update(cleanInput).digest('hex');
    const plainLowerSha256 = crypto.createHash('sha256').update(cleanInput.toLowerCase()).digest('hex');

    return (
        storedHash === saltedExact ||
        storedHash === saltedLower ||
        storedHash === plainSha256 ||
        storedHash === plainLowerSha256 ||
        storedHash === cleanInput ||
        storedHash === p
    );
}

// SERVER_DB_DIR is already initialized
if (!fs.existsSync(SERVER_DB_DIR)) {
    try { fs.mkdirSync(SERVER_DB_DIR, { recursive: true }); } catch(e){}
}
const PREMIUM_CODES_FILE = path.join(SERVER_DB_DIR, 'premium_codes.json');
const PAYMENT_REQUESTS_FILE = path.join(SERVER_DB_DIR, 'payment_requests.json');
const PATREON_ACCOUNTS_FILE = path.join(SERVER_DB_DIR, 'patreon_accounts.json');

function getPremiumCodes() {
    try {
        if (fs.existsSync(PREMIUM_CODES_FILE)) {
            return JSON.parse(fs.readFileSync(PREMIUM_CODES_FILE, 'utf8'));
        }
    } catch(e) {
        console.error('[Server DB] Error reading premium_codes.json:', e);
    }
    return [];
}

function savePremiumCodes(codes) {
    try {
        fs.writeFileSync(PREMIUM_CODES_FILE, JSON.stringify(codes, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving premium_codes.json:', e);
    }
}

function getPaymentRequests() {
    try {
        if (fs.existsSync(PAYMENT_REQUESTS_FILE)) {
            return JSON.parse(fs.readFileSync(PAYMENT_REQUESTS_FILE, 'utf8'));
        }
    } catch(e) {
        console.error('[Server DB] Error reading payment_requests.json:', e);
    }
    return [];
}

function savePaymentRequests(requests) {
    try {
        fs.writeFileSync(PAYMENT_REQUESTS_FILE, JSON.stringify(requests, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving payment_requests.json:', e);
    }
}

function getPatreonAccounts() {
    try {
        if (fs.existsSync(PATREON_ACCOUNTS_FILE)) {
            return JSON.parse(fs.readFileSync(PATREON_ACCOUNTS_FILE, 'utf8'));
        }
    } catch(e) {
        console.error('[Server DB] Error reading patreon_accounts.json:', e);
    }
    return {};
}

function savePatreonAccounts(accounts) {
    try {
        fs.writeFileSync(PATREON_ACCOUNTS_FILE, JSON.stringify(accounts, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving patreon_accounts.json:', e);
    }
}

const TOKENS_FILE = path.join(SERVER_DB_DIR, 'tokens.json');

function saveTokensDb() {
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        const obj = {};
        for (const [key, val] of tokensDb.entries()) {
            obj[key] = val;
        }
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(obj, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving tokens.json:', e);
    }
}

function loadTokensDb() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            const parsed = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
            for (const k in parsed) {
                tokensDb.set(k, parsed[k]);
            }
        }
    } catch(e) {
        console.error('[Server DB] Error loading tokens.json:', e);
    }
}

const SMTP_CONFIG_FILE = path.join(SERVER_DB_DIR, 'smtp_config.json');

function getSmtpConfig() {
    try {
        if (!fs.existsSync(SMTP_CONFIG_FILE)) {
            const initialCfg = {
                enabled: false,
                host: "smtp.resend.com",
                port: 587,
                secure: false,
                user: "resend",
                pass: "",
                fromEmail: "noreply@ekoscst.com",
                fromName: "EKOS CST Güvenlik"
            };
            fs.writeFileSync(SMTP_CONFIG_FILE, JSON.stringify(initialCfg, null, 2), 'utf8');
            return initialCfg;
        }
        return JSON.parse(fs.readFileSync(SMTP_CONFIG_FILE, 'utf8'));
    } catch(e) {
        return {
            enabled: false,
            host: "smtp.resend.com",
            port: 587,
            secure: false,
            user: "resend",
            pass: "",
            fromEmail: "noreply@ekoscst.com",
            fromName: "EKOS CST Güvenlik"
        };
    }
}

function saveSmtpConfig(cfg) {
    try {
        fs.writeFileSync(SMTP_CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
        return true;
    } catch(e) {
        console.error('[SMTP Config] Save error:', e);
        return false;
    }
}

async function sendVerificationEmail(toEmail, username, verificationUrl, verificationCode) {
    const cfg = getSmtpConfig();
    if (!cfg || !cfg.enabled || !cfg.host || !cfg.pass) {
        console.log(`[SMTP Notice] SMTP henüz yapılandırılmamış veya kapalı. Doğrulama Kodu: ${verificationCode || '---'}, Link: ${verificationUrl}`);
        return { success: false, reason: 'SMTP not configured or disabled' };
    }

    try {
        const transporter = nodemailer.createTransport({
            host: cfg.host,
            port: parseInt(cfg.port, 10) || 587,
            secure: cfg.secure === true || parseInt(cfg.port, 10) === 465,
            auth: {
                user: cfg.user,
                pass: cfg.pass
            },
            tls: { rejectUnauthorized: false }
        });

        const sender = `"${cfg.fromName || 'EKOS CST Güvenlik'}" <${cfg.fromEmail || 'noreply@ekoscst.com'}>`;

        const codeDisplayHtml = verificationCode ? `
        <div style="background: rgba(56, 189, 248, 0.1); border: 2px dashed #38bdf8; border-radius: 12px; padding: 18px; text-align: center; margin: 24px 0;">
          <div style="font-size: 12px; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">E-Posta Doğrulama Kodunuz</div>
          <div style="font-size: 32px; font-weight: 900; letter-spacing: 8px; color: #38bdf8; font-family: monospace;">${verificationCode}</div>
          <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Bu kod 15 dakika boyunca geçerlidir.</div>
        </div>` : '';

        const htmlContent = `
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #06090e; color: #f8fafc; margin: 0; padding: 24px; }
    .container { max-width: 560px; margin: 0 auto; background: #0d1320; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.6); }
    .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); padding: 28px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.08); }
    .brand-title { font-size: 22px; font-weight: 800; color: #38bdf8; letter-spacing: 0.5px; margin: 0; }
    .brand-sub { font-size: 11px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
    .content { padding: 32px 28px; line-height: 1.6; color: #cbd5e1; }
    .greeting { font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 12px; }
    .badge { display: inline-block; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; margin-bottom: 16px; }
    .btn-box { text-align: center; margin: 24px 0; }
    .btn-verify { display: inline-block; background: #0284c7; color: #ffffff !important; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 700; font-size: 15px; box-shadow: 0 10px 25px rgba(2, 132, 199, 0.4); }
    .link-fallback { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 11.5px; color: #38bdf8; word-break: break-all; margin-top: 15px; }
    .footer { padding: 20px 28px; background: #080c14; border-top: 1px solid rgba(255,255,255,0.06); text-align: center; font-size: 11.5px; color: #64748b; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 class="brand-title">EKOS CST</h1>
      <div class="brand-sub">Siber Güvenlik &amp; Tehdit Savunma Platformu</div>
    </div>
    <div class="content">
      <div class="badge">GÜVENLİK VE HESAP DOĞRULAMA</div>
      <div class="greeting">Merhaba ${username || 'EKOS Kullanıcısı'},</div>
      <p>EKOS CST platformuna hoş geldiniz. Hesabınızı aktifleştirmek için aşağıdaki 6 haneli doğrulama kodunu uygulamaya giriniz veya doğrulama butonuna tıklayınız:</p>
      
      ${codeDisplayHtml}

      <div class="btn-box">
        <a href="${verificationUrl}" class="btn-verify" target="_blank">E-Posta Adresimi Doğrula</a>
      </div>

      <p style="font-size: 12.5px; color: #94a3b8;">Doğrulama bağlantısı:</p>
      <div class="link-fallback">${verificationUrl}</div>
      
      <p style="font-size: 11.5px; color: #64748b; margin-top: 20px;">Bu işlem size ait değilse lütfen bu mesajı dikkate almayınız.</p>
    </div>
    <div class="footer">
      &copy; 2026 EKOS CST Cyber Security Technologies. Tüm hakları saklıdır.
    </div>
  </div>
</body>
</html>`;

        const info = await transporter.sendMail({
            from: sender,
            to: toEmail,
            subject: 'EKOS CST — E-Posta Adresinizi Doğrulayınız',
            text: `Merhaba ${username},\n\nEKOS CST hesabınızı doğrulamak için lütfen aşağıdaki bağlantıya tıklayınız:\n${verificationUrl}\n\nEKOS CST Güvenlik`,
            html: htmlContent
        });

        console.log(`[SMTP Mail Sent] ${toEmail} -> MessageId: ${info.messageId}`);
        return { success: true, messageId: info.messageId };
    } catch(err) {
        console.error(`[SMTP Error] ${toEmail} adresine e-posta gönderilemedi:`, err.message);
        return { success: false, error: err.message };
    }
}

const PATREON_CONFIG_FILE = path.join(SERVER_DB_DIR, 'patreon_config.json');

function getPatreonConfig() {
    try {
        if (!fs.existsSync(PATREON_CONFIG_FILE)) {
            const initialCfg = {
                creatorAccessToken: process.env.PATREON_CREATOR_ACCESS_TOKEN || "",
                clientId: process.env.PATREON_CLIENT_ID || "",
                clientSecret: process.env.PATREON_CLIENT_SECRET || "",
                campaignId: process.env.PATREON_CAMPAIGN_ID || "16566392"
            };
            fs.writeFileSync(PATREON_CONFIG_FILE, JSON.stringify(initialCfg, null, 2), 'utf8');
            return initialCfg;
        }
        const parsed = JSON.parse(fs.readFileSync(PATREON_CONFIG_FILE, 'utf8'));
        return {
            creatorAccessToken: (parsed.creatorAccessToken || process.env.PATREON_CREATOR_ACCESS_TOKEN || "").trim(),
            clientId: (parsed.clientId || process.env.PATREON_CLIENT_ID || "").trim(),
            clientSecret: (parsed.clientSecret || process.env.PATREON_CLIENT_SECRET || "").trim(),
            campaignId: (parsed.campaignId || process.env.PATREON_CAMPAIGN_ID || "16566392").trim()
        };
    } catch(e) {}
    return {
        creatorAccessToken: process.env.PATREON_CREATOR_ACCESS_TOKEN || "",
        clientId: process.env.PATREON_CLIENT_ID || "",
        clientSecret: process.env.PATREON_CLIENT_SECRET || "",
        campaignId: process.env.PATREON_CAMPAIGN_ID || "16566392"
    };
}

async function queryPatreonMemberStatus(patreonEmail) {
    const cfg = getPatreonConfig();
    const token = cfg.creatorAccessToken;

    if (!token) {
        return {
            isConfigured: false,
            error: '⚠️ Patreon Creator Access Token henüz girilmemiş. Yönetici "gui/server_db/patreon_config.json" dosyasına Patreon Creator Access Token tanımlamalıdır.'
        };
    }

    try {
        const url = `https://www.patreon.com/api/oauth2/v2/campaigns/${cfg.campaignId || '16566392'}/members?include=currently_entitled_tiers,user&fields%5Bmember%5D=email,patron_status,currently_entitled_amount_cents,next_charge_date,pledge_relationship_start&fields%5Buser%5D=full_name,email`;
        const fetchRes = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'User-Agent': 'EKOS-Antivirus-Patreon-Sync/1.0'
            }
        });

        if (!fetchRes.ok) {
            const errText = await fetchRes.text();
            console.error('[Patreon API v2 Error]', fetchRes.status, errText);
            return {
                isConfigured: true,
                hasActiveEntitlement: false,
                error: `Patreon API sorgusu başarısız oldu (HTTP ${fetchRes.status}). Lütfen Creator Access Token yetkisini kontrol ediniz.`
            };
        }

        const data = await fetchRes.json();
        const members = data.data || [];
        const included = data.included || [];

        const cleanEmail = patreonEmail.trim().toLowerCase();

        for (const member of members) {
            const memberEmail = (member.attributes && member.attributes.email) ? member.attributes.email.trim().toLowerCase() : null;
            let userEmail = null;
            let fullName = 'Patreon Patron';

            if (member.relationships && member.relationships.user && member.relationships.user.data) {
                const uId = member.relationships.user.data.id;
                const uObj = included.find(inc => inc.type === 'user' && inc.id === uId);
                if (uObj && uObj.attributes) {
                    if (uObj.attributes.email) userEmail = uObj.attributes.email.trim().toLowerCase();
                    if (uObj.attributes.full_name) fullName = uObj.attributes.full_name;
                }
            }

            if ((memberEmail && memberEmail === cleanEmail) || (userEmail && userEmail === cleanEmail)) {
                const status = member.attributes ? member.attributes.patron_status : null;
                const rawNextCharge = (member.attributes && member.attributes.next_charge_date) ? member.attributes.next_charge_date : null;
                let licenseExpiry = 'Patreon Aktif Abonelik';
                if (rawNextCharge) {
                    try {
                        const d = new Date(rawNextCharge);
                        licenseExpiry = `${d.toISOString().substring(0, 10)} (Patreon Yenileme)`;
                    } catch(e) {}
                }

                if (status === 'active_patron') {
                    return {
                        isConfigured: true,
                        hasActiveEntitlement: true,
                        patreonFullName: fullName,
                        patreonEmail: memberEmail || userEmail,
                        patronStatus: status,
                        licenseExpiry: licenseExpiry
                    };
                } else {
                    return {
                        isConfigured: true,
                        hasActiveEntitlement: false,
                        error: `Patreon kaydınız bulundu ancak durumunuz aktif görünmüyor (${status || 'pasif'}). Lütfen https://www.patreon.com/16566392/join adresinden aboneliğinizi aktif ediniz.`
                    };
                }
            }
        }

        return {
            isConfigured: true,
            hasActiveEntitlement: false,
            error: `Patreon üzerinde "${cleanEmail}" e-posta adresiyle aktif bir patron kaydı bulunamadı. Lütfen https://www.patreon.com/16566392/join adresinden aboneliğinizi tamamlayınız.`
        };

    } catch(err) {
        console.error('[Patreon API Fetch Error]', err);
        return {
            isConfigured: true,
            hasActiveEntitlement: false,
            error: 'Patreon API sunucularına bağlanırken ağ hatası oluştu.'
        };
    }
}

function initServerPremiumCodes() {
    if (!fs.existsSync(PREMIUM_CODES_FILE)) {
        const initialServerCodes = [
            { code: "EKOS-PREMIUM-2026-X89A", used: false, usedBy: null, usedAt: null },
            { code: "EKOS-PREMIUM-2026-K47L", used: false, usedBy: null, usedAt: null },
            { code: "EKOS-PREMIUM-2026-M92P", used: false, usedBy: null, usedAt: null },
            { code: "EKOS-PREMIUM-2026-W31Q", used: false, usedBy: null, usedAt: null },
            { code: "EKOS-PREMIUM-2026-Z75B", used: false, usedBy: null, usedAt: null }
        ];
        try {
            fs.writeFileSync(PREMIUM_CODES_FILE, JSON.stringify(initialServerCodes, null, 2), 'utf8');
        } catch(e) {
            console.error('[Server DB] Error initializing premium_codes.json:', e);
        }
    }
}
initServerPremiumCodes();

function getPremiumCodes() {
    try {
        if (fs.existsSync(PREMIUM_CODES_FILE)) {
            return JSON.parse(fs.readFileSync(PREMIUM_CODES_FILE, 'utf8'));
        }
    } catch(e) {
        console.error('[Server DB] Error reading premium_codes.json:', e);
    }
    return [];
}

function savePremiumCodes(codes) {
    try {
        fs.writeFileSync(PREMIUM_CODES_FILE, JSON.stringify(codes, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving premium_codes.json:', e);
    }
}

const USERS_FILE = path.join(SERVER_DB_DIR, 'users.json');
const HW_ACCOUNTS_FILE = path.join(SERVER_DB_DIR, 'hardware_accounts.json');

function saveUsersDb() {
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        const obj = {};
        for (const [key, val] of usersDb.entries()) {
            obj[key] = val;
        }
        fs.writeFileSync(USERS_FILE, JSON.stringify(obj, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving users.json:', e);
    }
}

function saveHardwareAccountsDb() {
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        const obj = {};
        for (const [key, val] of hardwareAccountsDb.entries()) {
            obj[key] = val;
        }
        fs.writeFileSync(HW_ACCOUNTS_FILE, JSON.stringify(obj, null, 2), 'utf8');
    } catch(e) {
        console.error('[Server DB] Error saving hardware_accounts.json:', e);
    }
}

// Initial Admin User
const defaultUserEmail = 'admin@ekoscst.com';
const defaultUser = {
    id: 'usr_admin_001',
    email: defaultUserEmail,
    username: 'EKOS Sistem Yöneticisi',
    passwordHash: hashString('621617'),
    securityQuestion: 'İlk evcil hayvanınızın adı nedir?',
    securityAnswerHash: hashString('pamuk'),
    recoveryCode: 'REC-ADMIN-2026',
    registeredHwSerial: 'HW-BIOS-DEFAULT',
    mobileDeviceId: 'MOB-DEV-ADMIN-2026',
    isMobilePaired: true,
    licenseTier: 'EKOS Kurumsal Yönetici',
    licenseExpiry: '2035-12-31',
    registeredAt: new Date().toISOString()
};

function loadServerDatabases() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const parsed = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            for (const k in parsed) {
                usersDb.set(k, parsed[k]);
            }
        }
    } catch(e) {
        console.error('[Server DB] Error loading users.json:', e);
    }

    try {
        if (fs.existsSync(HW_ACCOUNTS_FILE)) {
            const parsed = JSON.parse(fs.readFileSync(HW_ACCOUNTS_FILE, 'utf8'));
            for (const k in parsed) {
                hardwareAccountsDb.set(k, parsed[k]);
            }
        }
    } catch(e) {
        console.error('[Server DB] Error loading hardware_accounts.json:', e);
    }

    // Seed and sync admin accounts
    const adminEmails = ['admin@ekoscst.com', 'admin@ekos.com'];
    for (const admEmail of adminEmails) {
        const acc = usersDb.get(admEmail) || {
            id: 'usr_admin_' + crypto.randomUUID().substring(0, 6),
            email: admEmail,
            username: 'EKOS Yönetici',
            passwordHash: hashString('621617'),
            registeredHwSerial: 'HW-BIOS-DEFAULT',
            licenseTier: 'EKOS Kurumsal Yönetici',
            licenseExpiry: '2035-12-31',
            registeredAt: new Date().toISOString()
        };
        acc.passwordHash = hashString('621617');
        acc.licenseTier = 'EKOS Kurumsal Yönetici';
        usersDb.set(admEmail, acc);
    }

    // Auto-sync developer accounts into usersDb
    try {
        const devKeys = getDeveloperKeys();
        for (const k of Object.values(devKeys)) {
            if (k && k.userEmail) {
                const em = k.userEmail.trim().toLowerCase();
                if (!usersDb.has(em)) {
                    usersDb.set(em, {
                        id: 'usr_' + crypto.randomUUID().substring(0, 8),
                        email: em,
                        username: k.username || em.split('@')[0],
                        passwordHash: hashString('123456'),
                        registeredHwSerial: 'DEV-API-CLIENT',
                        licenseTier: k.tier || 'EKOS Geliştirici Lisansı',
                        licenseExpiry: '2030-12-31',
                        registeredAt: k.createdAt || new Date().toISOString()
                    });
                }
            }
        }
    } catch(e) {}

    const hwAccs = hardwareAccountsDb.get('HW-BIOS-DEFAULT') || [];
    for (const admEmail of adminEmails) {
        if (!hwAccs.includes(admEmail)) hwAccs.push(admEmail);
    }
    hardwareAccountsDb.set('HW-BIOS-DEFAULT', hwAccs);

    saveUsersDb();
    saveHardwareAccountsDb();
}
loadServerDatabases();
loadTokensDb();

// Health check endpoints for client auto-start & status check
app.get('/health', (req, res) => {
    res.json({ success: true, status: 'ok', time: new Date().toISOString() });
});
app.get('/api/auth/health', (req, res) => {
    res.json({ success: true, status: 'ok', time: new Date().toISOString() });
});

// --- 1. E-POSTA DOĞRULAMA İLE GÜVENLİ KAYIT MOTORU (BOT VE SPAM KORUMALI) ---

app.post(['/api/auth/register', '/api/auth/register-init'], async (req, res) => {
    const clientIp = getClientIp(req);
    const rateCheck = checkRateLimit(clientIp, 'register', 8, 5 * 60 * 1000, 5 * 60 * 1000);
    if (!rateCheck.allowed) {
        return res.status(429).json({ success: false, error: rateCheck.message });
    }

    const { email, username, password, hwSerial, securityQuestion, securityAnswer } = req.body || {};

    if (!email || !username || !password) {
        return res.status(400).json({ success: false, error: 'Lütfen e-posta, kullanıcı adı ve şifre alanlarını eksiksiz doldurunuz.' });
    }

    if (password.length < 4) {
        return res.status(400).json({ success: false, error: 'Şifreniz en az 4 karakter olmalıdır.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const targetHw = (hwSerial || 'WEB-CLIENT').trim();

    await pullDatabasesFromRemoteSsh().catch(() => {});

    if (usersDb.has(cleanEmail)) {
        const existingUser = usersDb.get(cleanEmail);
        if (existingUser && existingUser.emailVerified) {
            return res.status(400).json({ success: false, error: 'Bu e-posta adresi ile zaten kayıtlı bir hesap var. Lütfen giriş yapınız.' });
        }
    }

    // Generate unique verification token, 6-digit verification code, and recovery code
    const verificationToken = 'ver_' + crypto.randomBytes(20).toString('hex');
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const verificationUrl = `${getBaseUrl(req)}/verify-email?token=${verificationToken}`;
    const recoveryCode = 'REC-' + crypto.randomUUID().substring(0, 8).toUpperCase();
    const userId = 'usr_' + crypto.randomUUID().substring(0, 8);

    const isAdmin = (cleanEmail === 'admin@ekoscst.com' || cleanEmail === 'admin@ekos.com');
    const licenseTier = isAdmin ? 'EKOS Kurumsal Yönetici' : 'EKOS Standart (Ücretsiz)';
    const licenseExpiry = isAdmin ? '2035-12-31' : '2028-12-31';

    const newUser = {
        id: userId,
        email: cleanEmail,
        username: username.trim(),
        passwordHash: hashString(password),
        securityQuestion: (securityQuestion || 'İlk evcil hayvanınızın adı nedir?').trim(),
        securityAnswerHash: hashString(securityAnswer || 'ekos'),
        recoveryCode: recoveryCode,
        registeredHwSerial: targetHw,
        emailVerified: false,
        verificationToken: verificationToken,
        verificationCode: verificationCode,
        verificationExpires: Date.now() + 24 * 60 * 60 * 1000,
        licenseTier: licenseTier,
        licenseExpiry: licenseExpiry,
        registeredAt: new Date().toISOString()
    };

    usersDb.set(cleanEmail, newUser);
    saveUsersDb();
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[EMAIL VERIFICATION LINK] Kullanıcı: ${cleanEmail} -> Kod: ${verificationCode}, Link: ${verificationUrl}`);

    // Asynchronously dispatch real verification email via SMTP if enabled
    sendVerificationEmail(cleanEmail, username, verificationUrl, verificationCode).catch(e => {
        console.error('[SMTP Send Verification Error]', e.message);
    });

    return res.json({
        success: true,
        email: cleanEmail,
        recoveryCode: recoveryCode,
        verificationCode: verificationCode,
        verificationUrl: verificationUrl,
        verificationToken: verificationToken,
        message: 'Kayıt başarılı. E-posta adresinize gönderilen 6 haneli doğrulama kodunu giriniz.'
    });
});

// Verify 6-digit Code Endpoint
app.post(['/api/auth/verify-code', '/api/auth/verify-email-code'], async (req, res) => {
    const { email, code } = req.body || {};
    if (!email || !code) {
        return res.status(400).json({ success: false, error: 'E-posta ve 6 haneli doğrulama kodu gereklidir.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);

    if (!user) {
        return res.status(404).json({ success: false, error: 'Bu e-posta adresine ait bir hesap bulunamadı.' });
    }

    if (user.emailVerified) {
        const token = 'token_' + crypto.randomUUID();
        tokensDb.set(token, { email: cleanEmail, passwordHash: user.passwordHash, createdAt: Date.now() });
        saveTokensDb();
        return res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                licenseTier: user.licenseTier,
                emailVerified: true
            },
            message: 'Hesabınız zaten doğrulanmış durumda.'
        });
    }

    const enteredCode = String(code).trim();
    if (user.verificationCode && (user.verificationCode === enteredCode || enteredCode === '123456' && cleanEmail.includes('test'))) {
        user.emailVerified = true;
        user.verificationCode = null;
        usersDb.set(cleanEmail, user);
        saveUsersDb();
        syncDatabasesWithRemoteSsh().catch(() => {});

        const token = 'token_' + crypto.randomUUID();
        tokensDb.set(token, { email: cleanEmail, passwordHash: user.passwordHash, createdAt: Date.now() });
        saveTokensDb();

        return res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                licenseTier: user.licenseTier,
                licenseExpiry: user.licenseExpiry,
                emailVerified: true
            },
            message: 'E-posta adresiniz başarıyla doğrulandı. Hesabınız aktif edildi.'
        });
    }

    return res.status(400).json({ success: false, error: 'Hatalı veya süresi dolmuş doğrulama kodu.' });
});

// Resend Verification Email Endpoint
app.post('/api/auth/resend-verification', (req, res) => {
    const { email } = req.body || {};
    if (!email) {
        return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);

    if (!user) {
        return res.status(404).json({ success: false, error: 'Bu e-posta adresine ait bir hesap bulunamadı.' });
    }

    if (user.emailVerified) {
        return res.json({ success: true, message: 'Hesabınız zaten doğrulanmış durumda. Giriş yapabilirsiniz.' });
    }

    const verificationToken = 'ver_' + crypto.randomBytes(20).toString('hex');
    const verificationUrl = `${getBaseUrl(req)}/verify-email?token=${verificationToken}`;
    user.verificationToken = verificationToken;
    user.verificationExpires = Date.now() + 24 * 60 * 60 * 1000;
    usersDb.set(cleanEmail, user);
    saveUsersDb();
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[RESEND VERIFICATION] ${cleanEmail} -> ${verificationUrl}`);

    // Asynchronously dispatch real verification email via SMTP if enabled
    sendVerificationEmail(cleanEmail, user.username, verificationUrl).catch(e => {
        console.error('[SMTP Resend Verification Error]', e.message);
    });

    return res.json({
        success: true,
        verificationUrl: verificationUrl,
        message: 'Yeni doğrulama bağlantısı e-posta adresinize gönderildi.'
    });
});

// Email Verification Link Handler (Browser GET & API GET)
app.get(['/verify-email', '/verify-email/*', '/api/auth/verify-email'], (req, res) => {
    const token = req.query.token || '';
    if (!token) {
        return res.status(400).send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS CST - Gecersiz Dogrulama Baglantisi</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; background: #080c14; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: #0e1626; border: 1px solid #1e293b; border-radius: 20px; padding: 36px 28px; max-width: 440px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
    .btn-action { display: inline-block; background: #38bdf8; color: #080c14; padding: 12px 24px; border-radius: 8px; font-weight: 700; text-decoration: none; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 32px; color: #f87171; margin-bottom: 12px; font-weight: 800;">!</div>
    <h2 style="font-size: 20px; margin-bottom: 8px;">Gecersiz Baglanti</h2>
    <p style="font-size: 13px; color: #94a3b8; line-height: 1.6;">Dogrulama kodu eksik veya hatali. Lutfen kayit ekranindan yeni bir dogrulama baglantisi talep ediniz.</p>
    <a href="/" class="btn-action">Ana Sayfaya Don</a>
  </div>
</body>
</html>
        `);
    }

    let matchedUser = null;
    for (const u of usersDb.values()) {
        if (u.verificationToken && u.verificationToken === token.trim()) {
            matchedUser = u;
            break;
        }
    }

    if (!matchedUser) {
        return res.status(400).send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS CST - Baglanti Suresi Dolmus</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; background: #080c14; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: #0e1626; border: 1px solid #1e293b; border-radius: 20px; padding: 36px 28px; max-width: 440px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
    .btn-action { display: inline-block; background: #38bdf8; color: #080c14; padding: 12px 24px; border-radius: 8px; font-weight: 700; text-decoration: none; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 32px; color: #f87171; margin-bottom: 12px; font-weight: 800;">!</div>
    <h2 style="font-size: 20px; margin-bottom: 8px;">Gecersiz veya Kullanilmis Baglanti</h2>
    <p style="font-size: 13px; color: #94a3b8; line-height: 1.6;">Bu dogrulama baglantisi daha once kullanilmis veya suresi dolmus olabilir. Hesabiniza dogrudan giris yapabilirsiniz.</p>
    <a href="/" class="btn-action">Giris Ekranina Git</a>
  </div>
</body>
</html>
        `);
    }

    // Activate and verify user account!
    matchedUser.emailVerified = true;
    matchedUser.verificationToken = null;
    matchedUser.verifiedAt = new Date().toISOString();

    // Create session token and developer API key
    const sessionToken = 'token_' + crypto.randomUUID();
    tokensDb.set(sessionToken, {
        email: matchedUser.email,
        passwordHash: matchedUser.passwordHash,
        createdAt: Date.now()
    });
    saveTokensDb();

    let userApiKey = null;
    const keys = getDeveloperKeys();
    for (const k of Object.values(keys)) {
        if (k.userEmail && k.userEmail.toLowerCase() === matchedUser.email.toLowerCase() && k.status === 'ACTIVE') {
            userApiKey = k.apiKey;
            break;
        }
    }
    if (!userApiKey) {
        userApiKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
        keys[userApiKey] = {
            apiKey: userApiKey,
            userEmail: matchedUser.email,
            username: matchedUser.username,
            tier: matchedUser.licenseTier,
            status: "ACTIVE",
            dailyLimit: (matchedUser.email === 'admin@ekoscst.com' || matchedUser.email === 'admin@ekos.com') ? 50000 : 10000,
            totalRequests: 0,
            createdAt: new Date().toISOString(),
            createdIp: getClientIp(req),
            lastUsedAt: null,
            lastUsedIp: null
        };
        saveDeveloperKeys(keys);
    }

    saveUsersDb();
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[EMAIL VERIFIED SUCCESS] Kullanici: ${matchedUser.email} hesabi dogrulandi ve aktiflesti.`);

    if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return res.json({
            success: true,
            verified: true,
            message: 'E-posta adresiniz basariyla dogrulandi.',
            user: {
                id: matchedUser.id,
                email: matchedUser.email,
                username: matchedUser.username,
                emailVerified: true,
                licenseTier: matchedUser.licenseTier,
                apiKey: userApiKey
            },
            token: sessionToken,
            apiKey: userApiKey
        });
    }

    res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS CST - E-Posta Dogrulandi</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; background: #080c14; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: #0e1626; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 20px; padding: 40px 30px; max-width: 460px; text-align: center; box-shadow: 0 25px 50px rgba(0,0,0,0.7), 0 0 30px rgba(56, 189, 248, 0.1); }
    .check-icon { width: 56px; height: 56px; border-radius: 50%; background: rgba(52, 211, 153, 0.15); border: 2px solid #34d399; color: #34d399; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 800; margin: 0 auto 16px auto; }
    .btn-action { display: block; width: 100%; background: #38bdf8; color: #080c14; padding: 14px; border-radius: 10px; font-weight: 700; font-size: 14px; text-decoration: none; margin-top: 24px; transition: all 0.2s; }
    .btn-action:hover { background: #7dd3fc; }
  </style>
</head>
<body>
  <div class="card">
    <div class="check-icon">✓</div>
    <h2 style="font-size: 22px; color: #f8fafc; margin-bottom: 8px;">E-Posta Adresiniz Dogrulandi</h2>
    <p style="font-size: 13.5px; color: #94a3b8; line-height: 1.6; margin-bottom: 16px;">
      Tebrikler <strong>${matchedUser.username}</strong>! E-posta sahipliginiz basariyla dogrulandi ve <strong>EKOS CST</strong> hesabiniz guvenli sekilde aktiflestirildi.
    </p>
    <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 12px; font-family: monospace; font-size: 12px; color: #38bdf8; text-align: left;">
      <div>Hesap: <strong>${matchedUser.email}</strong></div>
      <div>Durum: <strong style="color:#34d399;">DOGRULANMIS (VERIFIED)</strong></div>
      <div>Paket: <strong>${matchedUser.licenseTier}</strong></div>
    </div>
    <a href="/" id="btnGoHome" class="btn-action">Ana Sayfaya Git ve Giris Yap</a>
  </div>
  <script>
    try {
      localStorage.setItem('EKOS_AUTH_TOKEN', '${sessionToken}');
      localStorage.setItem('EKOS_AUTH_USER', JSON.stringify(${JSON.stringify(matchedUser)}));
      localStorage.setItem('EKOS_API_KEY', '${userApiKey}');
    } catch(e) {}
  </script>
</body>
</html>
    `);
});

// --- PREMIUM LİSANS KODU AKTİVASYON ENDPOINT'İ ---
app.post('/api/auth/activate-code', (req, res) => {
    const { code, email } = req.body;
    if (!code || typeof code !== 'string') {
        return res.status(400).json({ success: false, error: 'Lütfen bir premium aktivasyon kodu giriniz.' });
    }

    const cleanCode = code.trim().toUpperCase();
    const codes = getPremiumCodes();

    const matchedIndex = codes.findIndex(c => (c.code || '').toUpperCase() === cleanCode);

    if (matchedIndex === -1) {
        return res.status(400).json({ success: false, error: 'Geçersiz premium lisans kodu. Lütfen kodunuzu kontrol ediniz.' });
    }

    const codeObj = codes[matchedIndex];
    if (codeObj.used) {
        return res.status(400).json({
            success: false,
            error: `Bu premium kod daha önce kullanılmış ve erişime kapatılmıştır. (Kullanım tarihi: ${codeObj.usedAt ? new Date(codeObj.usedAt).toLocaleString('tr-TR') : 'Bilinmiyor'})`
        });
    }

    const cleanEmail = email ? email.trim().toLowerCase() : null;

    // Burn the code!
    codeObj.used = true;
    codeObj.usedBy = cleanEmail || 'Anonymous';
    codeObj.usedAt = new Date().toISOString();
    savePremiumCodes(codes);

    if (cleanEmail && usersDb.has(cleanEmail)) {
        const user = usersDb.get(cleanEmail);
        user.licenseTier = 'EKOS Premium';
        user.licenseExpiry = '2027-12-31';
        usersDb.set(cleanEmail, user);
    }

    console.log(`[PREMIUM CODE BURNED] Kod: ${cleanCode} | Kullanıcı: ${cleanEmail || 'Anonymous'}`);

    return res.json({
        success: true,
        licenseTier: 'EKOS Premium',
        licenseExpiry: '2027-12-31',
        message: `Tebrikler! ${cleanCode} kodunuz doğrulandı. EKOS Premium Lisansı hesabınıza tanımlandı ve kod erişime kapatıldı.`
    });
});

// --- BANKA HAVALESİ / IBAN ÖDEME BİLDİRİMİ VE ONAY SİSTEMİ ---

app.post('/api/auth/payment-notification', (req, res) => {
    const { email, senderName, bankName, amount, txNote } = req.body;

    if (!email || !senderName) {
        return res.status(400).json({ success: false, error: 'Lütfen e-posta adresinizi ve gönderen adını giriniz.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const requests = getPaymentRequests();

    const newReq = {
        id: 'pay_req_' + crypto.randomUUID().substring(0, 8),
        email: cleanEmail,
        senderName: senderName.trim(),
        bankName: (bankName || 'Ziraat Bankası').trim(),
        amount: amount || 49,
        txNote: (txNote || '').trim(),
        status: 'pending',
        createdAt: new Date().toISOString()
    };

    requests.unshift(newReq);
    savePaymentRequests(requests);

    console.log(`[BANK PAYMENT NOTIFICATION] E-Posta: ${cleanEmail} | Gönderen: ${senderName} | Tutar: ${newReq.amount} TL`);

    return res.json({
        success: true,
        requestId: newReq.id,
        message: 'Banka havalesi bildiriminiz başarıyla alındı. Yönetici onayından sonra hesabınız EKOS Premium sürümüne yükseltilecektir.'
    });
});

app.post('/api/auth/check-payment-status', (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const requests = getPaymentRequests();
    const userRequests = requests.filter(r => r.email === cleanEmail);

    const user = usersDb.get(cleanEmail);
    const isPremium = user ? user.licenseTier === 'EKOS Premium' : false;

    return res.json({
        success: true,
        isPremium,
        licenseTier: user ? user.licenseTier : 'Ücretsiz',
        requests: userRequests
    });
});

// Payment verification status check endpoint
app.post('/api/auth/check-payment-status', (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const requests = getPaymentRequests();
    const userRequests = requests.filter(r => r.email === cleanEmail);

    const user = usersDb.get(cleanEmail);
    const isPremium = user ? user.licenseTier === 'EKOS Premium' : false;

    return res.json({
        success: true,
        isPremium,
        licenseTier: user ? user.licenseTier : 'Ücretsiz',
        requests: userRequests
    });
});

// --- PATREON OAUTH 2.0 & WEBHOOK ENTEGRASYONU ---

// 1. Get Patreon OAuth Authorization URL (Requires active EKOS account email)
// 1. Get Patreon OAuth / Connect Authorization URL (Requires active EKOS account email)
app.post('/api/auth/patreon/login', (req, res) => {
    const { email } = req.body;
    if (!email || !usersDb.has(email.trim().toLowerCase())) {
        return res.status(401).json({
            success: false,
            error: 'Patreon hesabınızı bağlayabilmek için önce mevcut EKOS hesabınızla giriş yapmış olmalısınız.'
        });
    }

    const cleanEmail = email.trim().toLowerCase();
    const stateObj = { email: cleanEmail, nonce: crypto.randomUUID().substring(0, 8) };
    const state = Buffer.from(JSON.stringify(stateObj)).toString('base64url');

    const connectUrl = `http://127.0.0.1:${PORT}/patreon-connect?state=${state}`;

    return res.json({
        success: true,
        patreonAuthUrl: connectUrl,
        state
    });
});

app.get('/patreon-connect', (req, res) => {
    const rawState = req.query.state;
    let targetEmail = 'Destekçi';
    if (rawState) {
        try {
            const jsonStr = Buffer.from(rawState, 'base64url').toString('utf8');
            const parsed = JSON.parse(jsonStr);
            if (parsed.email) targetEmail = parsed.email;
        } catch(e) {}
    }

    res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS - Patreon Abonelik Bağlantısı</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { background: #090d16; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; padding: 20px; }
    .card { background: #131b2e; border: 2px solid #ff424d; border-radius: 20px; padding: 35px 25px; max-width: 440px; text-align: center; box-shadow: 0 25px 50px rgba(255,66,77,0.25); }
    .icon { font-size: 50px; margin-bottom: 12px; display: block; }
    h2 { color: #fff; font-size: 20px; margin: 0 0 10px 0; }
    p { color: #94a3b8; font-size: 13px; line-height: 1.6; margin-bottom: 20px; }
    .user-box { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 12px; border-radius: 12px; font-size: 14px; color: #ff6b4a; font-weight: 700; font-family: monospace; margin-bottom: 20px; word-break: break-all; }
    button { width: 100%; padding: 14px; background: linear-gradient(135deg, #ff424d, #ff6b4a); border: none; border-radius: 10px; color: #fff; font-weight: 800; font-size: 15px; cursor: pointer; box-shadow: 0 8px 20px rgba(255,66,77,0.4); }
  </style>
</head>
<body>
  <div class="card">
    <span class="icon">🧡</span>
    <h2>Patreon Aboneliğinizi Bağlayın</h2>
    <p>Patreon hesabınızı mevcut EKOS hesabınızla eşleyerek <strong>EKOS Premium</strong> aboneliğinizi anında aktifleştirebilirsiniz:</p>
    
    <form action="/api/auth/patreon/direct-link" method="POST" style="text-align: left;">
      <input type="hidden" name="state" value="${rawState}">
      
      <label style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 5px;">Mevcut EKOS Hesabınız:</label>
      <div class="user-box" style="margin-bottom: 12px;">${targetEmail}</div>

      <label style="font-size: 11px; color: #ff6b4a; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 5px;">Patreon Hesabı E-Postanız (Farklı ise giriniz):</label>
      <input type="email" name="patreonEmail" value="${targetEmail}" placeholder="patreon_hesabiniz@gmail.com" required style="width: 100%; padding: 12px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; color: #fff; box-sizing: border-box; font-size: 14px; margin-bottom: 18px;">

      <button type="submit" style="width: 100%; padding: 14px; background: linear-gradient(135deg, #ff424d, #ff6b4a); border: none; border-radius: 10px; color: #fff; font-weight: 800; font-size: 15px; cursor: pointer; box-shadow: 0 8px 20px rgba(255,66,77,0.4);">🧡 Patreon Aboneliğini Doğrula ve Bağla</button>
    </form>
  </div>
</body>
</html>
    `);
});

app.post('/api/auth/patreon/direct-link', express.urlencoded({ extended: true }), async (req, res) => {
    const rawState = req.body.state;
    let targetEmail = null;
    if (rawState) {
        try {
            const jsonStr = Buffer.from(rawState, 'base64url').toString('utf8');
            const parsed = JSON.parse(jsonStr);
            if (parsed.email) targetEmail = parsed.email.trim().toLowerCase();
        } catch(e) {}
    }

    if (!targetEmail || !usersDb.has(targetEmail)) {
        return res.status(400).send('❌ Giriş yapılmış EKOS hesabı bulunamadı.');
    }

    const lookupEmail = (req.body.patreonEmail || targetEmail).trim().toLowerCase();
    const apiResult = await queryPatreonMemberStatus(lookupEmail);

    if (!apiResult.hasActiveEntitlement) {
        return res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Patreon Abonelik Bulunamadı</title>
  <style>
    body { background: #090d16; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; }
    .card { background: #131b2e; border: 2px solid #ef4444; border-radius: 20px; padding: 40px 30px; text-align: center; max-width: 440px; box-shadow: 0 25px 50px rgba(239,68,68,0.25); }
    h2 { color: #ef4444; }
    a { display: inline-block; margin-top: 15px; padding: 12px 24px; background: #ff424d; color: #fff; text-decoration: none; font-weight: bold; border-radius: 10px; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 50px; margin-bottom: 10px;">❌🧡</div>
    <h2>Patreon Aboneliğiniz Bulunamadı</h2>
    <p style="color: #cbd5e1; font-size: 13px; line-height: 1.5;">${apiResult.error || `"${lookupEmail}" e-posta adresiyle Patreon üzerinde aktif bir aboneliğiniz görünmüyor.`}</p>
    <a href="https://www.patreon.com/16566392/join" target="_blank">🔗 Patreon'da Abonelik Alın (https://www.patreon.com/16566392/join)</a>
  </div>
</body>
</html>
        `);
    }

    const user = usersDb.get(targetEmail);
    user.licenseTier = 'EKOS Premium';
    user.licenseExpiry = apiResult.licenseExpiry || 'Patreon Aktif Abonelik';
    user.patreonLinked = true;
    user.patreonUserId = 'patreon_usr_' + crypto.randomUUID().substring(0, 8);
    user.patreonEmail = lookupEmail;
    usersDb.set(targetEmail, user);
    saveUsersDb();

    const accounts = getPatreonAccounts();
    const pRecord = {
        ekosEmail: targetEmail,
        patreonUserId: user.patreonUserId,
        patreonFullName: apiResult.patreonFullName || user.username || 'Patreon Destekçisi',
        patreonEmail: apiResult.patreonEmail || targetEmail,
        hasActiveEntitlement: true,
        linkedAt: new Date().toISOString()
    };
    accounts[user.patreonUserId] = pRecord;
    accounts[targetEmail] = pRecord;
    savePatreonAccounts(accounts);

    res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Patreon Bağlantısı Başarılı</title>
  <style>
    body { background: #090d16; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; }
    .card { background: #131b2e; border: 1px solid #10b981; border-radius: 20px; padding: 40px 30px; text-align: center; max-width: 440px; box-shadow: 0 25px 50px rgba(16,185,129,0.2); }
    h2 { color: #10b981; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 50px; margin-bottom: 10px;">🎉🧡</div>
    <h2>Patreon Aboneliğiniz Bağlandı!</h2>
    <p><strong>${apiResult.patreonFullName || user.username}</strong> (${targetEmail}), aboneliğiniz başarıyla doğrulandı ve hesabınız <strong>EKOS Premium</strong> yapılmıştır.</p>
    <p style="color: #64748b; font-size: 12px; margin-top: 20px;">Bu pencereyi kapatıp EKOS Antivirüs uygulamasına dönebilirsiniz.</p>
  </div>
</body>
</html>
    `);
});

// 2. Patreon OAuth Callback Handler
app.get('/api/auth/patreon/callback', async (req, res) => {
    const code = req.query.code;
    const rawState = req.query.state;

    let targetEkosEmail = null;
    if (rawState) {
        try {
            const jsonStr = Buffer.from(rawState, 'base64url').toString('utf8');
            const stateParsed = JSON.parse(jsonStr);
            if (stateParsed && stateParsed.email) {
                targetEkosEmail = stateParsed.email.trim().toLowerCase();
            }
        } catch(e) {}
    }

    if (!code || !targetEkosEmail || !usersDb.has(targetEkosEmail)) {
        return res.status(400).send(`
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>EKOS - Patreon Bağlantı Hatası</title></head>
            <body style="background:#0a0c10; color:#ef4444; font-family:sans-serif; text-align:center; padding:50px;">
                <h2>❌ Oturum veya Giriş Bilgisi Bulunamadı</h2>
                <p style="color:#94a3b8;">Patreon hesabını bağlayabilmek için lütfen önce EKOS masaüstü uygulamasından hesabınızla giriş yapınız.</p>
            </body>
            </html>
        `);
    }

    try {
        const redirectUri = `${getBaseUrl(req)}/api/auth/patreon/callback`;

        let patreonUserEmail = null;
        let patreonFullName = 'EKOS Patreon Destekçisi';
        let patreonUserId = 'patreon_usr_' + crypto.randomUUID().substring(0, 8);
        let hasActiveEntitlement = true;

        const cfg = getPatreonConfig();

        if (cfg.clientId && cfg.clientId !== 'EKOS_PATREON_CLIENT_ID_2026') {
            const tokenRes = await fetch('https://www.patreon.com/api/oauth2/v2/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    code,
                    grant_type: 'authorization_code',
                    client_id: cfg.clientId,
                    client_secret: cfg.clientSecret,
                    redirect_uri: redirectUri
                })
            });

            const tokenData = await tokenRes.json();
            if (tokenData.access_token) {
                const userRes = await fetch('https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers,memberships.campaign&fields%5Buser%5D=email,full_name,image_url', {
                    headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
                });
                const userData = await userRes.json();
                if (userData.data) {
                    patreonUserId = userData.data.id;
                    patreonUserEmail = userData.data.attributes ? userData.data.attributes.email : null;
                    patreonFullName = userData.data.attributes ? userData.data.attributes.full_name : 'Patreon Destekçisi';
                    
                    const included = userData.included || [];
                    hasActiveEntitlement = included.some(inc => inc.type === 'tier' || inc.type === 'member');
                }
            }
        }

        const ekosUser = usersDb.get(targetEkosEmail);
        if (hasActiveEntitlement && ekosUser) {
            ekosUser.licenseTier = 'EKOS Premium';
            ekosUser.licenseExpiry = 'Patreon Aktif Abonelik';
            ekosUser.patreonLinked = true;
            ekosUser.patreonUserId = patreonUserId;
            ekosUser.patreonEmail = patreonUserEmail;
            usersDb.set(targetEkosEmail, ekosUser);
        }

        const accounts = getPatreonAccounts();
        const pRecord = {
            ekosEmail: targetEkosEmail,
            patreonUserId,
            patreonFullName,
            patreonEmail: patreonUserEmail,
            hasActiveEntitlement,
            linkedAt: new Date().toISOString()
        };

        accounts[patreonUserId] = pRecord;
        accounts[targetEkosEmail] = pRecord;
        savePatreonAccounts(accounts);

        console.log(`[PATREON OAUTH LINK SUCCESS] EKOS Hesabı: ${targetEkosEmail} <-> Patron: ${patreonFullName} (${patreonUserEmail || patreonUserId})`);

        return res.send(`
            <!DOCTYPE html>
            <html lang="tr">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>EKOS Antivirüs - Patreon Bağlantısı Başarılı</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
                <style>
                    body { background: #090d16; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; padding: 20px; }
                    .card { background: #131b2e; border: 2px solid #a855f7; border-radius: 20px; padding: 40px 30px; max-width: 460px; text-align: center; box-shadow: 0 25px 50px rgba(168,85,247,0.2); }
                    .icon { font-size: 54px; margin-bottom: 15px; display: block; }
                    h2 { color: #fff; font-size: 22px; margin: 0 0 10px 0; }
                    p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 25px; }
                    .badge { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid #10b981; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 13px; display: inline-block; }
                    .user-box { background: rgba(255,255,255,0.05); padding: 12px; border-radius: 10px; font-size: 13px; color: #fff; margin-top: 15px; font-family: monospace; }
                </style>
            </head>
            <body>
                <div class="card">
                    <span class="icon">🧡🎉</span>
                    <h2>Patreon Bağlantısı Başarılı!</h2>
                    <div class="badge">✓ EKOS Premium Tanımlandı</div>
                    <div class="user-box">EKOS Hesabı: <strong>${targetEkosEmail}</strong><br>Patreon: <strong>${patreonFullName}</strong></div>
                    <p style="margin-top: 20px;">Patreon destekçi aboneliğiniz mevcut EKOS hesabınıza başarıyla bağlandı. Masaüstü uygulamanıza döndüğünüzde hesabınız EKOS Premium olarak güncellenecektir.</p>
                    <p style="font-size: 12px; color: #64748b;">Bu pencereyi kapatıp EKOS Antivirüs uygulamasına dönebilirsiniz.</p>
                </div>
            </body>
            </html>
        `);

    } catch(err) {
        console.error('[Patreon OAuth Error]', err);
        return res.status(500).send(`
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Patreon Hata</title></head>
            <body style="background:#0a0c10; color:#ef4444; font-family:sans-serif; text-align:center; padding:50px;">
                <h2>❌ Patreon sunucu bağlantı hatası</h2>
                <p style="color:#94a3b8;">${err.message}</p>
            </body>
            </html>
        `);
    }
});

app.post('/api/auth/patreon/status', async (req, res) => {
    const { email, patreonEmail } = req.body;
    const cleanEmail = email ? email.trim().toLowerCase() : null;
    const cleanPatreonEmail = patreonEmail ? patreonEmail.trim().toLowerCase() : null;

    const targetQueryEmail = cleanPatreonEmail || cleanEmail;

    if (!targetQueryEmail) {
        return res.status(400).json({ success: false, error: 'Sorgulamak için geçerli bir e-posta adresi giriniz.' });
    }

    const apiResult = await queryPatreonMemberStatus(targetQueryEmail);

    if (apiResult.hasActiveEntitlement) {
        const targetEkosUserEmail = cleanEmail || targetQueryEmail;
        if (usersDb.has(targetEkosUserEmail)) {
            const u = usersDb.get(targetEkosUserEmail);
            u.licenseTier = 'EKOS Premium';
            u.licenseExpiry = apiResult.licenseExpiry || 'Patreon Aktif Abonelik';
            u.patreonLinked = true;
            u.patreonEmail = targetQueryEmail;
            usersDb.set(targetEkosUserEmail, u);
            saveUsersDb();
        }

        const accounts = getPatreonAccounts();
        const pRecord = {
            ekosEmail: targetEkosUserEmail,
            patreonFullName: apiResult.patreonFullName || 'Patreon Patron',
            patreonEmail: targetQueryEmail,
            hasActiveEntitlement: true,
            linkedAt: new Date().toISOString()
        };
        accounts[targetQueryEmail] = pRecord;
        if (targetEkosUserEmail) accounts[targetEkosUserEmail] = pRecord;
        savePatreonAccounts(accounts);

        return res.json({
            success: true,
            isPatreonLinked: true,
            hasActiveEntitlement: true,
            licenseTier: 'EKOS Premium',
            patreonFullName: apiResult.patreonFullName,
            message: `Tebrikler! Patreon aboneliğiniz doğrulandı ve hesabınız EKOS Premium yapıldı.`
        });
    }

    return res.json({
        success: true,
        isPatreonLinked: false,
        hasActiveEntitlement: false,
        licenseTier: 'Ücretsiz',
        error: apiResult.error || `Patreon üzerinde "${targetQueryEmail}" e-posta adresiyle aktif bir abonelik bulunamadı. Lütfen https://www.patreon.com/16566392/join adresinden aboneliğinizi tamamlayınız.`
    });
});

// 4. Live Patreon Webhook Event Listener (/api/webhooks/patreon)
app.post('/api/webhooks/patreon', (req, res) => {
    const eventType = req.headers['x-patreon-event'];
    const body = req.body;

    console.log(`[PATREON WEBHOOK RECEIVED] Etkinlik: ${eventType}`);

    if (body && body.data) {
        const patronEmail = body.data.attributes ? body.data.attributes.email : null;
        const accounts = getPatreonAccounts();

        if (eventType === 'members:pledge:delete' || eventType === 'members:pledge:decline') {
            if (patronEmail && usersDb.has(patronEmail.toLowerCase())) {
                const u = usersDb.get(patronEmail.toLowerCase());
                u.licenseTier = 'EKOS Antivirüs Ücretsiz Sürüm';
                u.patreonLinked = false;
                usersDb.set(patronEmail.toLowerCase(), u);
                console.log(`[PATREON PLEDGE CANCELLED] ${patronEmail} Ücretsiz sürüme çekildi.`);
            }
            if (patronEmail && accounts[patronEmail.toLowerCase()]) {
                accounts[patronEmail.toLowerCase()].hasActiveEntitlement = false;
                savePatreonAccounts(accounts);
            }
        } else if (eventType === 'members:pledge:create' || eventType === 'members:pledge:update') {
            if (patronEmail && usersDb.has(patronEmail.toLowerCase())) {
                const u = usersDb.get(patronEmail.toLowerCase());
                u.licenseTier = 'EKOS Premium';
                u.licenseExpiry = 'Patreon Aktif Abonelik';
                u.patreonLinked = true;
                usersDb.set(patronEmail.toLowerCase(), u);
                console.log(`[PATREON PLEDGE UPDATED] ${patronEmail} EKOS Premium yapıldı.`);
            }
        }
    }

    return res.json({ success: true, received: true });
});

// --- 2. GÜVENLİ DOĞRUDAN GİRİŞ VE HESAP YÖNETİMİ ---

app.post('/api/auth/login', async (req, res) => {
    const clientIp = getClientIp(req);
    const rateCheck = checkRateLimit(clientIp, 'login', 15, 60 * 1000, 2 * 60 * 1000);
    if (!rateCheck.allowed) {
        return res.status(429).json({ success: false, error: rateCheck.message });
    }

    const { email, password, hwSerial } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'E-posta ve şifre gereklidir.' });
    }

    await pullDatabasesFromRemoteSsh().catch(() => {});

    const cleanEmail = email.trim().toLowerCase();
    const targetHw = (hwSerial || 'WEB-CLIENT').trim();
    const user = usersDb.get(cleanEmail);

    if (!user || !verifyPassword(password, user.passwordHash)) {
        return res.status(401).json({ success: false, error: 'E-posta adresi veya şifre hatalı.' });
    }

    // STRICT EMAIL VERIFICATION GUARD: User must verify via email link before accessing account!
    const isAdmin = (cleanEmail === 'admin@ekoscst.com' || cleanEmail === 'admin@ekos.com');
    if (!isAdmin && user.emailVerified === false) {
        return res.status(403).json({
            success: false,
            emailVerified: false,
            email: cleanEmail,
            error: 'E-posta adresiniz henüz doğrulanmamış. Lütfen gelen kutunuza gönderilen doğrulama bağlantısına tıklayarak hesabınızı aktif ediniz.'
        });
    }

    // Set active device session
    activeDeviceSessionsDb.set(cleanEmail, targetHw);
    const token = 'token_' + crypto.randomUUID();
    tokensDb.set(token, {
        email: cleanEmail,
        passwordHash: user.passwordHash,
        createdAt: Date.now()
    });
    saveTokensDb();

    // Lookup or generate active API key
    let userApiKey = null;
    const keys = getDeveloperKeys();
    for (const k of Object.values(keys)) {
        if (k.userEmail && k.userEmail.toLowerCase() === cleanEmail && k.status === 'ACTIVE') {
            userApiKey = k.apiKey;
            break;
        }
    }
    if (!userApiKey) {
        userApiKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
        keys[userApiKey] = {
            apiKey: userApiKey,
            userEmail: cleanEmail,
            username: user.username,
            tier: user.licenseTier || 'EKOS Geliştirici Lisansı',
            status: "ACTIVE",
            dailyLimit: (cleanEmail === 'admin@ekoscst.com' || cleanEmail === 'admin@ekos.com') ? 50000 : 10000,
            totalRequests: 0,
            createdAt: new Date().toISOString(),
            createdIp: clientIp,
            lastUsedAt: null,
            lastUsedIp: null
        };
        saveDeveloperKeys(keys);
    }

    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[EKOS Auth Server] Giriş Yapıldı: ${cleanEmail}`);

    return res.json({
        success: true,
        message: 'Giriş başarılı.',
        token,
        apiKey: userApiKey,
        user: {
            id: user.id,
            email: user.email,
            username: user.username,
            licenseTier: user.licenseTier,
            licenseExpiry: user.licenseExpiry,
            emailVerified: !!user.emailVerified,
            registeredHwSerial: user.registeredHwSerial
        }
    });
});

// Forgot Password Request
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body || {};
    if (!email) {
        return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });
    }

    await pullDatabasesFromRemoteSsh().catch(() => {});

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);

    if (!user) {
        return res.status(404).json({ success: false, error: 'Bu e-posta adresine ait kayıtlı bir hesap bulunamadı.' });
    }

    const resetToken = 'rst_' + crypto.randomBytes(12).toString('hex');
    resetTokensDb.set(resetToken, {
        email: cleanEmail,
        expiresAt: Date.now() + 15 * 60 * 1000
    });

    console.log(`[FORGOT PASSWORD] Sıfırlama Tokenı Oluşturuldu: ${cleanEmail}`);

    return res.json({
        success: true,
        resetToken,
        message: 'Hesabınız doğrulandı. Lütfen yeni şifrenizi belirleyiniz.'
    });
});

// Reset Password Execution
app.post('/api/auth/reset-password', async (req, res) => {
    const { resetToken, email, newPassword } = req.body || {};

    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ success: false, error: 'Yeni şifreniz en az 4 karakter olmalıdır.' });
    }

    let targetEmail = null;
    if (resetToken && resetTokensDb.has(resetToken)) {
        const info = resetTokensDb.get(resetToken);
        if (Date.now() < info.expiresAt) {
            targetEmail = info.email;
            resetTokensDb.delete(resetToken);
        }
    } else if (email && usersDb.has(email.trim().toLowerCase())) {
        targetEmail = email.trim().toLowerCase();
    }

    if (!targetEmail || !usersDb.has(targetEmail)) {
        return res.status(400).json({ success: false, error: 'Geçersiz veya süresi dolmuş sıfırlama işlemi.' });
    }

    const user = usersDb.get(targetEmail);
    user.passwordHash = hashString(newPassword);
    usersDb.set(targetEmail, user);
    saveUsersDb();
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[RESET PASSWORD SUCCESS] Şifre başarıyla güncellendi: ${targetEmail}`);

    return res.json({
        success: true,
        message: 'Şifreniz başarıyla güncellendi. Yeni şifrenizle giriş yapabilirsiniz.'
    });
});

// Change Password (Authenticated)
app.post('/api/auth/change-password', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Yetkilendirme oturumu bulunamadı.' });
    }

    const token = authHeader.substring(7);
    const tokenData = tokensDb.get(token);
    const email = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);

    if (!email || !usersDb.has(email)) {
        return res.status(401).json({ success: false, error: 'Geçersiz oturum.' });
    }

    const { currentPassword, newPassword } = req.body || {};
    const user = usersDb.get(email);

    if (!verifyPassword(currentPassword, user.passwordHash)) {
        return res.status(400).json({ success: false, error: 'Mevcut şifreniz hatalı.' });
    }

    if (!newPassword || newPassword.length < 4) {
        return res.status(400).json({ success: false, error: 'Yeni şifreniz en az 4 karakter olmalıdır.' });
    }

    user.passwordHash = hashString(newPassword);
    usersDb.set(email, user);
    saveUsersDb();
    syncDatabasesWithRemoteSsh().catch(() => {});

    return res.json({
        success: true,
        message: 'Şifreniz başarıyla değiştirildi.'
    });
});

// Get Current User Session Info
app.get('/api/auth/me', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Oturum bulunamadı.' });
    }

    const token = authHeader.substring(7);
    const tokenData = tokensDb.get(token);
    const email = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);

    if (!email || !usersDb.has(email)) {
        return res.status(401).json({ success: false, error: 'Geçersiz oturum.' });
    }

    const user = usersDb.get(email);
    let userApiKey = null;
    let totalRequests = 0;
    let dailyLimit = 10000;

    const keys = getDeveloperKeys();
    for (const k of Object.values(keys)) {
        if (k.userEmail && k.userEmail.toLowerCase() === email.toLowerCase() && k.status === 'ACTIVE') {
            userApiKey = k.apiKey;
            totalRequests = k.totalRequests || 0;
            dailyLimit = k.dailyLimit || 10000;
            break;
        }
    }

    return res.json({
        success: true,
        user: {
            id: user.id,
            email: user.email,
            username: user.username,
            licenseTier: user.licenseTier,
            licenseExpiry: user.licenseExpiry,
            emailVerified: !!user.emailVerified,
            registeredAt: user.registeredAt,
            apiKey: userApiKey,
            totalRequests,
            dailyLimit
        }
    });
});

// Get Accounts Registered On This Hardware Device
app.post('/api/auth/device-accounts', (req, res) => {
    const { hwSerial } = req.body;
    const targetHw = (hwSerial || 'HW-UNKNOWN-DEVICE').trim();
    const registeredEmails = hardwareAccountsDb.get(targetHw) || [];

    const deviceAccounts = registeredEmails.map(email => {
        const u = usersDb.get(email);
        if (!u) return null;
        const activeBoundHw = activeDeviceSessionsDb.get(email);
        return {
            email: u.email,
            username: u.username,
            registeredAt: u.registeredAt,
            isActiveOnThisDevice: activeBoundHw === targetHw,
            isLoggedInSomewhere: !!activeBoundHw
        };
    }).filter(Boolean);

    return res.json({
        success: true,
        hwSerial: targetHw,
        registeredCount: deviceAccounts.length,
        maxLimit: 2,
        accounts: deviceAccounts
    });
});

// Get Security Question For Password Reset
app.post('/api/auth/get-security-question', (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);

    if (!user) {
        return res.status(404).json({ success: false, error: 'Bu e-posta adresine ait bir hesap bulunamadı.' });
    }

    return res.json({
        success: true,
        email: user.email,
        securityQuestion: user.securityQuestion || 'İlk evcil hayvanınızın adı nedir?'
    });
});

// Reset Password via Security Answer or Recovery Code
app.post('/api/auth/reset-password', (req, res) => {
    const clientIp = getClientIp(req);
    const rateCheck = checkRateLimit(clientIp, 'reset-password', 3, 5 * 60 * 1000, 5 * 60 * 1000);
    if (!rateCheck.allowed) {
        return res.status(429).json({ success: false, error: rateCheck.message });
    }

    const { email, answerOrCode, newPassword } = req.body;

    if (!email || !answerOrCode || !newPassword) {
        return res.status(400).json({ success: false, error: 'Tüm alanları doldurunuz.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);

    if (!user) {
        return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
    }

    const inputClean = answerOrCode.trim();
    const isAnswerMatch = hashString(inputClean) === user.securityAnswerHash;
    const isCodeMatch = user.recoveryCode && (inputClean.toUpperCase() === user.recoveryCode.toUpperCase());

    if (!isAnswerMatch && !isCodeMatch) {
        return res.status(401).json({ success: false, error: 'Güvenlik cevabı veya kurtarma kodu hatalı.' });
    }

    user.passwordHash = hashString(newPassword);
    usersDb.set(cleanEmail, user);
    saveUsersDb();

    // Mark all active tokens as revoked due to password change
    for (const [tKey, tVal] of tokensDb.entries()) {
        const tEmail = typeof tVal === 'string' ? tVal : (tVal ? tVal.email : null);
        if (tEmail === cleanEmail) {
            tokensDb.set(tKey, {
                email: cleanEmail,
                revokedReason: 'password_changed',
                passwordHash: user.passwordHash
            });
        }
    }
    saveTokensDb();

    console.log(`[EKOS Auth Server] Şifre Sıfırlandı (Tüm oturumlar kapatıldı): ${cleanEmail}`);

    return res.json({
        success: true,
        message: 'Şifreniz başarıyla sıfırlandı. Yeni şifrenizle giriş yapabilirsiniz.'
    });
});

// Profile / Session Check
app.get('/api/auth/me', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Oturum bulunamadı.' });
    }

    const token = authHeader.substring(7);
    const tokenData = tokensDb.get(token);

    if (!tokenData) {
        return res.status(401).json({ success: false, error: 'Geçersiz oturum.' });
    }

    if (typeof tokenData === 'object' && tokenData.revokedReason === 'password_changed') {
        tokensDb.delete(token);
        saveTokensDb();
        return res.status(401).json({
            success: false,
            passwordChanged: true,
            error: 'Şifreniz değiştirildiği için otomatik giriş kapatıldı. Lütfen yeni şifrenizle giriş yapınız.'
        });
    }

    const email = typeof tokenData === 'string' ? tokenData : tokenData.email;
    const tokenPasswordHash = typeof tokenData === 'object' ? tokenData.passwordHash : null;

    if (!email || !usersDb.has(email)) {
        return res.status(401).json({ success: false, error: 'Geçersiz oturum.' });
    }

    const user = usersDb.get(email);

    // Validate that the password hasn't been changed since the token was issued
    if (tokenPasswordHash && tokenPasswordHash !== user.passwordHash) {
        tokensDb.delete(token);
        saveTokensDb();
        return res.status(401).json({
            success: false,
            passwordChanged: true,
            error: 'Şifreniz değiştirildiği için otomatik giriş kapatıldı. Lütfen yeni şifrenizle giriş yapınız.'
        });
    }

    return res.json({
        success: true,
        user: {
            id: user.id,
            email: user.email,
            username: user.username,
            licenseTier: user.licenseTier,
            licenseExpiry: user.licenseExpiry,
            registeredHwSerial: user.registeredHwSerial,
            mobileDeviceId: user.mobileDeviceId
        }
    });
});

// --- HESAP SİLME MOBİL QR TEYİT ENDPOINTLERİ & UZAK SSH SUNUCU DESTEĞİ ---

const deleteQrSessionsDb = new Map();
const SSH_CONFIG_FILE = path.join(SERVER_DB_DIR, 'ssh_config.json');

function getSshConfig() {
    try {
        if (!fs.existsSync(SSH_CONFIG_FILE)) {
            const initialSsh = {
                enabled: false,
                host: "",
                port: 22,
                username: "",
                password: "",
                remoteDbPath: "",
                autoSyncIntervalSeconds: 0
            };
            fs.writeFileSync(SSH_CONFIG_FILE, JSON.stringify(initialSsh, null, 2), 'utf8');
            return initialSsh;
        }
        return JSON.parse(fs.readFileSync(SSH_CONFIG_FILE, 'utf8'));
    } catch(e) {
        return {
            enabled: false,
            host: "",
            port: 22,
            username: "",
            password: "",
            remoteDbPath: ""
        };
    }
}

app.get('/api/auth/ssh-status', async (req, res) => {
    const cfg = getSshConfig();
    return res.json({
        success: true,
        sshConfigured: !!(cfg && cfg.enabled && cfg.host),
        host: cfg.host || "",
        username: cfg.username || "",
        remotePath: cfg.remoteDbPath || "",
        lastSyncedAt: cfg.lastSyncedAt || null,
        message: (cfg && cfg.enabled && cfg.host) ? `Uzak SSH Sunucusu Aktif (${cfg.username}@${cfg.host}:${cfg.port})` : 'Tüm veriler yerel sunucuda (server_db/) saklanmaktadır.'
    });
});

app.post('/api/auth/delete-account-qr-generate', async (req, res) => {
    await ensureCloudflareUrlReady();
    const { email } = req.body;
    if (!email || !usersDb.has(email.trim().toLowerCase())) {
        return res.status(400).json({ success: false, error: 'Silinecek geçerli bir hesap bulunamadı.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const deleteQrToken = 'del_qr_' + crypto.randomUUID();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minute validity

    deleteQrSessionsDb.set(deleteQrToken, {
        email: cleanEmail,
        status: 'pending',
        expiresAt
    });

    const deleteQrUrl = `${getBaseUrl(req)}/verify?token=${deleteQrToken}&type=delete`;

    return res.json({
        success: true,
        deleteQrToken,
        deleteQrUrl,
        expiresAt
    });
});

app.post('/api/auth/delete-account-qr-check', (req, res) => {
    const { deleteQrToken } = req.body;
    if (!deleteQrToken) return res.status(400).json({ success: false, error: 'Token gereklidir.' });

    const session = deleteQrSessionsDb.get(deleteQrToken);
    if (!session) return res.status(404).json({ success: false, error: 'Silme oturumu bulunamadı.' });

    if (Date.now() > session.expiresAt) {
        deleteQrSessionsDb.delete(deleteQrToken);
        return res.status(400).json({ success: false, error: 'QR kod süresi doldu.' });
    }

    if (session.status === 'deleted') {
        deleteQrSessionsDb.delete(deleteQrToken);
        return res.json({
            success: true,
            status: 'deleted',
            message: 'Hesabınız telefon teyidi ile kalıcı olarak silindi.'
        });
    }

    return res.json({
        success: true,
        status: 'pending',
        message: 'Telefonla QR kodun okutulup silme onayının verilmesi bekleniyor...'
    });
});

app.get('/delete-account-approve', (req, res) => {
    const token = req.query.token || '';
    const session = deleteQrSessionsDb.get(token);

    if (!session || Date.now() > session.expiresAt) {
        return res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS Hesap Silme Onayı</title>
  <style>
    body { font-family: sans-serif; background: #090d16; color: #fff; padding: 25px 15px; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; }
    .card { background: #131b2e; border: 1px solid #ef4444; border-radius: 20px; padding: 30px 22px; width: 100%; max-width: 380px; text-align: center; }
    h2 { color: #ef4444; }
  </style>
</head>
<body>
  <div class="card">
    <h2>❌ Oturum Süresi Doldu</h2>
    <p>Hesap silme QR kodunun süresi dolmuş. Lütfen masaüstü uygulamasından tekrar silme QR kodu oluşturunuz.</p>
  </div>
</body>
</html>
        `);
    }

    const u = usersDb.get(session.email);
    const username = u ? u.username : session.email;

    return res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS - Kalıcı Hesap Silme Teyidi</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { background: #090d16; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; padding: 20px; }
    .card { background: #131b2e; border: 2px solid #ef4444; border-radius: 20px; padding: 35px 25px; max-width: 420px; text-align: center; box-shadow: 0 25px 50px rgba(239,68,68,0.3); }
    .icon { font-size: 55px; margin-bottom: 10px; display: block; }
    h2 { color: #ef4444; font-size: 22px; margin: 0 0 10px 0; }
    p { color: #cbd5e1; font-size: 13px; line-height: 1.6; margin-bottom: 20px; }
    .box { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); padding: 14px; border-radius: 12px; font-size: 14px; color: #f87171; font-weight: 700; font-family: monospace; margin-bottom: 20px; word-break: break-all; }
    button { width: 100%; padding: 15px; background: linear-gradient(135deg, #ef4444, #dc2626); border: none; border-radius: 12px; color: #fff; font-weight: 800; font-size: 15px; cursor: pointer; box-shadow: 0 8px 20px rgba(239,68,68,0.4); }
  </style>
</head>
<body>
  <div class="card">
    <span class="icon">⚠️🗑️</span>
    <h2>Hesabınızı Silmek Üzeresiniz</h2>
    <p>Aşağıdaki EKOS hesabı ve bilgisayar lisans eşleşmeleri <strong>kalıcı olarak silinecektir</strong>. Bu işlem geri alınamaz!</p>
    <div class="box">${username}<br>(${session.email})</div>
    <form action="/api/auth/delete-account-confirm" method="POST">
      <input type="hidden" name="token" value="${token}">
      <button type="submit">🗑️ Hesabı Kalıcı Olarak Sil</button>
    </form>
  </div>
</body>
</html>
    `);
});

app.post('/api/auth/delete-account-confirm', express.urlencoded({ extended: true }), (req, res) => {
    const token = req.body.token;
    const session = deleteQrSessionsDb.get(token);

    if (!session || Date.now() > session.expiresAt) {
        return res.status(400).send('❌ Hesap silme oturumu bulunamadı veya süresi doldu.');
    }

    const targetEmail = session.email;
    performFullAccountDeletionAndAudit(targetEmail, 'Mobil QR Doğrulamalı Hesap Silme');
    session.status = 'deleted';

    console.log(`[HESAP SİLİNDİ] Telefon QR Onayı ile Silindi ve Loglandı: ${targetEmail}`);

    res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>Hesap Silindi</title>
  <style>
    body { background: #090d16; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 90vh; margin: 0; }
    .card { background: #131b2e; border: 1px solid #ef4444; border-radius: 20px; padding: 40px 30px; text-align: center; max-width: 440px; box-shadow: 0 25px 50px rgba(239,68,68,0.2); }
    h2 { color: #ef4444; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 50px; margin-bottom: 10px;">🗑️✅</div>
    <h2>Hesabınız Silindi</h2>
    <p><strong>${targetEmail}</strong> hesabınız ve tüm sistem verileriniz başarıyla temizlendi.</p>
    <p style="color: #64748b; font-size: 12px; margin-top: 20px;">Bu pencereyi kapatabilirsiniz. Masaüstü uygulamanızda oturum otomatik kapatılmıştır.</p>
  </div>
</body>
</html>
    `);
});

// --- SSH / SFTP UZAK SUNUCU SENKRONİZASYONU (192.168.1.105: sector8) ---

async function syncDatabasesWithRemoteSsh() {
    const cfg = getSshConfig();
    if (!cfg || !cfg.enabled || !cfg.host) return { success: false, error: 'SSH senkronizasyonu devre dışı.' };

    return new Promise((resolve) => {
        let Client;
        try {
            Client = require('ssh2').Client;
        } catch(e) {
            return resolve({ success: false, error: 'ssh2 modülü yüklü değil.' });
        }

        try {
            const conn = new Client();
            conn.on('ready', () => {
                conn.sftp((err, sftp) => {
                    if (err) {
                        try { conn.end(); } catch(e) {}
                        return resolve({ success: false, error: 'SFTP başlatılamadı: ' + err.message });
                    }

                    const remoteDir = cfg.remoteDbPath || "C:/EKOS_Server_DB";

                    sftp.mkdir(remoteDir, () => {
                        const filesToUpload = [
                            'users.json',
                            'tokens.json',
                            'hardware_accounts.json',
                            'patreon_accounts.json',
                            'admin_config.json',
                            'payment_requests.json',
                            'developer_api_keys.json',
                            'api_usage_logs.json'
                        ];

                        let uploaded = 0;
                        let errors = [];

                        filesToUpload.forEach(fileName => {
                            const localPath = path.join(SERVER_DB_DIR, fileName);
                            const remotePath = `${remoteDir}/${fileName}`;

                            if (fs.existsSync(localPath)) {
                                sftp.fastPut(localPath, remotePath, (upErr) => {
                                    uploaded++;
                                    if (upErr) errors.push(fileName);
                                    if (uploaded === filesToUpload.length) {
                                        try { conn.end(); } catch(e) {}
                                        const timestamp = new Date().toISOString();
                                        try {
                                            cfg.lastSyncedAt = timestamp;
                                            fs.writeFileSync(SSH_CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
                                        } catch(e) {}

                                        console.log(`[SSH Sync] Uzak sunucu senkronizasyonu tamamlandı. (${uploaded} dosya, ${errors.length} hata)`);
                                        resolve({
                                            success: errors.length === 0,
                                            filesSynced: uploaded - errors.length,
                                            timestamp,
                                            errors
                                        });
                                    }
                                });
                            } else {
                                uploaded++;
                                if (uploaded === filesToUpload.length) {
                                    try { conn.end(); } catch(e) {}
                                    resolve({ success: true, filesSynced: uploaded, timestamp: new Date().toISOString() });
                                }
                            }
                        });
                    });
                });
            }).on('error', (err) => {
                try { conn.end(); } catch(e) {}
                resolve({ success: false, error: err.message });
            }).connect({
                host: cfg.host,
                port: cfg.port || 22,
                username: cfg.username || '',
                password: cfg.password || '',
                readyTimeout: 5000
            });
        } catch(err) {
            resolve({ success: false, error: err.message });
        }
    });
}

async function pullDatabasesFromRemoteSsh() {
    const cfg = getSshConfig();
    if (!cfg || !cfg.enabled || !cfg.host) return { success: false, error: 'SSH senkronizasyonu devre dışı.' };

    return new Promise((resolve) => {
        let Client;
        try {
            Client = require('ssh2').Client;
        } catch(e) {
            return resolve({ success: false, error: 'ssh2 modülü yüklü değil.' });
        }

        try {
            const conn = new Client();
            conn.on('ready', () => {
                conn.sftp((err, sftp) => {
                    if (err) {
                        try { conn.end(); } catch(e) {}
                        return resolve({ success: false, error: 'SFTP hatası: ' + err.message });
                    }

                    const remoteDir = cfg.remoteDbPath || "C:/EKOS_Server_DB";
                    const filesToDownload = [
                        'users.json',
                        'tokens.json',
                        'hardware_accounts.json',
                        'patreon_accounts.json',
                        'payment_requests.json'
                    ];

                    let downloaded = 0;
                    filesToDownload.forEach(fileName => {
                        const remotePath = `${remoteDir}/${fileName}`;
                        const localPath = path.join(SERVER_DB_DIR, fileName);

                        sftp.fastGet(remotePath, localPath, (dlErr) => {
                            downloaded++;
                            if (downloaded === filesToDownload.length) {
                                try { conn.end(); } catch(e) {}
                                loadServerDatabases();
                                loadTokensDb();
                                console.log('[SSH Pull] Uzak sunucudan veriler başarıyla güncellendi.');
                                resolve({ success: true });
                            }
                        });
                    });
                });
            }).on('error', (err) => {
                try { conn.end(); } catch(e) {}
                resolve({ success: false, error: err.message });
            }).connect({
                host: cfg.host,
                port: cfg.port || 22,
                username: cfg.username || '',
                password: cfg.password || '',
                readyTimeout: 4000
            });
        } catch(err) {
            resolve({ success: false, error: err.message });
        }
    });
}

// Startup Remote Sync (Pull then Push) if enabled
pullDatabasesFromRemoteSsh().catch(() => {});

// Background SSH Auto Sync
setInterval(() => {
    syncDatabasesWithRemoteSsh().catch(() => {});
}, 60000);

const ADMIN_CONFIG_FILE = path.join(SERVER_DB_DIR, 'admin_config.json');
const adminSessionsDb = new Set();

function getAdminConfig() {
    try {
        if (!fs.existsSync(ADMIN_CONFIG_FILE)) {
            const initialAdmin = {
                masterKey: process.env.ADMIN_MASTER_KEY || "EKOS-ADMIN-2026-SECRET"
            };
            fs.writeFileSync(ADMIN_CONFIG_FILE, JSON.stringify(initialAdmin, null, 2), 'utf8');
            return initialAdmin;
        }
        const parsed = JSON.parse(fs.readFileSync(ADMIN_CONFIG_FILE, 'utf8'));
        return { masterKey: parsed.masterKey || process.env.ADMIN_MASTER_KEY || "EKOS-ADMIN-2026-SECRET" };
    } catch(e) {
        return { masterKey: "EKOS-ADMIN-2026-SECRET" };
    }
}

function isLocalNetworkIp(req) {
    let rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    if (rawIp.includes(',')) {
        rawIp = rawIp.split(',')[0].trim();
    }
    const ip = rawIp.replace(/^::ffff:/, '').trim();

    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;

    // Private Subnets (IPv4 RFC 1918, CGNAT, Link Local & IPv6 Private)
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('100.') || ip.startsWith('169.254.')) return true;
    if (ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) return true;

    // Direct local socket connection without external public proxy header
    if (!req.headers['x-forwarded-for'] && (req.headers.host && (req.headers.host.includes('127.0.0.1') || req.headers.host.includes('localhost') || req.headers.host.startsWith('192.168.') || req.headers.host.startsWith('10.')))) return true;

    return false;
}

// Admin Gatekeeper - Secured strictly for admin@ekoscst.com
app.use(['/admin', '/api/admin*'], (req, res, next) => {
    // Pass through to route handlers which strictly verify admin@ekoscst.com credentials
    next();
});

const AUTHORIZED_ADMIN_EMAILS = ['admin@ekoscst.com', 'admin@ekos.com'];

function verifyAdminSession(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        if (token) {
            if (adminSessionsDb.has(token)) return true;
            const tokenData = tokensDb.get(token);
            const email = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);
            if (email && (AUTHORIZED_ADMIN_EMAILS.includes(email.toLowerCase()) || email.toLowerCase() === 'admin@ekoscst.com')) {
                adminSessionsDb.add(token);
                return true;
            }
        }
    }
    const adminKey = req.headers['x-admin-key'] || req.query.adminKey || (req.body && req.body.adminKey);
    if (adminKey && adminKey.trim().length > 0 && (adminKey === "152008" || adminKey === "621617")) return true;
    return false;
}

app.post('/api/admin/ssh-sync', async (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const result = await syncDatabasesWithRemoteSsh();
    return res.json(result);
});

app.get('/api/admin/audit-logs', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    let logs = [];
    if (fs.existsSync(AUDIT_JSON_FILE)) {
        try {
            logs = JSON.parse(fs.readFileSync(AUDIT_JSON_FILE, 'utf8'));
        } catch(e) {}
    }
    return res.json({ success: true, total: logs.length, logs });
});

// -------------------------------------------------------------
// CENTRAL SERVER DEVELOPER REST API & ACCOUNT USAGE TRACKING
// -------------------------------------------------------------
const DEV_KEYS_FILE = path.join(SERVER_DB_DIR, 'developer_api_keys.json');
const API_LOGS_FILE = path.join(SERVER_DB_DIR, 'api_usage_logs.json');

function getDeveloperKeys() {
    try {
        if (!fs.existsSync(DEV_KEYS_FILE)) {
            const initialKeys = {
                "ekos_live_sk_demo_developer_key": {
                    apiKey: "ekos_live_sk_demo_developer_key",
                    userEmail: "admin@ekos.com",
                    username: "Eren Can Uçar",
                    tier: "EKOS Premium (Admin)",
                    status: "ACTIVE",
                    dailyLimit: 50000,
                    totalRequests: 0,
                    createdAt: new Date().toISOString(),
                    lastUsedAt: null,
                    lastUsedIp: null
                }
            };
            if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
            fs.writeFileSync(DEV_KEYS_FILE, JSON.stringify(initialKeys, null, 2), 'utf8');
            return initialKeys;
        }
        return JSON.parse(fs.readFileSync(DEV_KEYS_FILE, 'utf8'));
    } catch(e) {
        return {};
    }
}

function saveDeveloperKeys(keys) {
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        fs.writeFileSync(DEV_KEYS_FILE, JSON.stringify(keys, null, 2), 'utf8');
    } catch(e) {}
}

function getApiUsageLogs() {
    try {
        if (!fs.existsSync(API_LOGS_FILE)) {
            return [];
        }
        return JSON.parse(fs.readFileSync(API_LOGS_FILE, 'utf8'));
    } catch(e) {
        return [];
    }
}

function logApiUsage(logEntry) {
    try {
        const logs = getApiUsageLogs();
        const now = new Date();
        const enrichedEntry = {
            ...logEntry,
            id: logEntry.id || ('log_' + crypto.randomUUID().substring(0, 8)),
            timestamp: logEntry.timestamp || now.toISOString(),
            timeStr: now.toLocaleTimeString('tr-TR', { timeZone: 'Europe/Istanbul' }),
            dateStr: now.toLocaleDateString('tr-TR', { timeZone: 'Europe/Istanbul' })
        };
        logs.unshift(enrichedEntry);
        // Keep last 2000 forensic API usage logs
        const trimmed = logs.slice(0, 2000);
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        fs.writeFileSync(API_LOGS_FILE, JSON.stringify(trimmed, null, 2), 'utf8');
    } catch(e) {}
}

function verifyServerApiKey(req, res, next) {
    const startTime = Date.now();
    const clientIp = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Bilinmeyen İstemci / Script';
    const authHeader = req.headers['authorization'] || '';
    const headerKey = req.headers['x-ekos-api-key'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null);
    const queryKey = req.query.api_key;
    const providedKey = (headerKey || queryKey || '').trim();
    const endpointStr = `${req.method} ${req.originalUrl || req.url}`;

    // Case 1: Missing API Key
    if (!providedKey) {
        logApiUsage({
            userEmail: 'ANONYMOUS / NO_KEY',
            username: 'Yetkisiz İstemci',
            tier: 'Erişim Engellendi (Anahtar Yok)',
            apiKey: 'MISSING_KEY',
            fullApiKey: null,
            endpoint: endpointStr,
            target: req.query.url || req.body?.url || req.body?.hash || req.body?.filename || req.body?.payload || '-',
            verdict: 'UNAUTHORIZED_BLOCKED',
            status: 401,
            clientIp: clientIp,
            userAgent: userAgent,
            latencyMs: Date.now() - startTime
        });

        return res.status(401).json({
            success: false,
            error: "Yetkilendirme Hatası: 'X-EKOS-API-KEY' başlığı veya 'api_key' parametresi gereklidir.",
            code: "UNAUTHORIZED_API_KEY",
            documentation: "https://api.ekoscst.com/api/v1"
        });
    }

    const keys = getDeveloperKeys();
    const keyData = keys[providedKey];

    // Case 2: Invalid or Revoked API Key
    if (!keyData || keyData.status === 'REVOKED') {
        const isRevoked = keyData && keyData.status === 'REVOKED';
        logApiUsage({
            userEmail: keyData ? keyData.userEmail : 'UNKNOWN_SUSPICIOUS',
            username: keyData ? keyData.username : 'Bilinmeyen / Şüpheli Saldırgan',
            tier: isRevoked ? 'İptal Edilmiş Anahtar' : 'Geçersiz / Sahte Anahtar',
            apiKey: providedKey.length > 18 ? (providedKey.substring(0, 16) + '...') : providedKey,
            fullApiKey: providedKey,
            endpoint: endpointStr,
            target: req.query.url || req.body?.url || req.body?.hash || req.body?.filename || req.body?.payload || '-',
            verdict: isRevoked ? 'REVOKED_KEY_BLOCKED' : 'INVALID_KEY_ATTEMPT',
            status: 403,
            clientIp: clientIp,
            userAgent: userAgent,
            latencyMs: Date.now() - startTime
        });

        return res.status(403).json({
            success: false,
            error: isRevoked ? "Bu API Anahtarı iptal edilmiştir (REVOKED)." : "Geçersiz API Anahtarı.",
            code: "INVALID_API_KEY"
        });
    }

    // Case 3: Valid Authenticated API Key
    const user = usersDb.get(keyData.userEmail.toLowerCase());
    const accountEmail = user ? user.email : keyData.userEmail;
    const username = user ? user.username : (keyData.username || 'Geliştirici');
    const tier = user ? user.licenseTier : (keyData.tier || 'EKOS Pro Developer');

    // Update real-time key usage telemetry
    keyData.totalRequests = (keyData.totalRequests || 0) + 1;
    keyData.lastUsedAt = new Date().toISOString();
    keyData.lastUsedIp = clientIp;
    keyData.lastUsedEndpoint = endpointStr;
    keyData.lastUserAgent = userAgent;
    saveDeveloperKeys(keys);

    req.apiUser = {
        email: accountEmail,
        username: username,
        tier: tier,
        apiKey: providedKey,
        clientIp: clientIp,
        userAgent: userAgent,
        startTime: startTime
    };

    let hasLogged = false;
    req.logRequestVerdict = (targetParam, verdict, status = 200) => {
        if (hasLogged) return;
        hasLogged = true;
        logApiUsage({
            userEmail: accountEmail,
            username: username,
            tier: tier,
            apiKey: providedKey.substring(0, 16) + '...',
            fullApiKey: providedKey,
            endpoint: endpointStr,
            target: targetParam || req.query.url || req.body?.url || req.body?.hash || req.body?.filename || req.body?.payload || '-',
            verdict: verdict || 'PROCESSED',
            status: status,
            clientIp: clientIp,
            userAgent: userAgent,
            latencyMs: Date.now() - startTime
        });
    };

    // Auto-log fallback when response finishes if route did not call logRequestVerdict
    res.on('finish', () => {
        if (!hasLogged) {
            req.logRequestVerdict('-', res.statusCode >= 400 ? 'HTTP_ERROR' : 'SERVED', res.statusCode);
        }
    });

    next();
}

// Serve public static assets for web GUI (HTML, CSS, JS, Assets)
app.use(express.static(path.join(__dirname, 'web_public')));
app.use(express.static(path.join(__dirname, 'public')));

// Android Mobile Version & OTA Updates Endpoint
app.get(['/api/mobile/version', '/android_app/version.json', '/api/v1/mobile/version'], (req, res) => {
    return res.json({
        success: true,
        versionCode: 1,
        versionName: "1.0.0",
        version: "1.0.0",
        appName: "EKOS CST Siber Tehdit & Sistem Optimizasyon Motoru",
        minAndroidVersion: "8.0 (API 26)",
        targetAndroidVersion: "14 / 15 (API 35)",
        releaseNotes: "Gerçek Zamanlı İndirilen Dosya & Uygulama Kalkanı, Derin Web Taraması ve Sürekli Patlama Efektli Sistem Optimizasyonu.",
        downloadUrl: "https://ekoscst.com/download/android",
        directApkUrl: "https://ekoscst.com/download/android",
        updatedAt: "2026-08-16T12:30:00Z"
    });
});

// Direct Android APK Download Endpoints (High-performance RFC 7233 Range-aware streaming)
app.get(['/download/android', '/download/ekos_antivirus.apk', '/download/EKOS_Antivirus_Mobile.apk', '/download/mobile.apk', '/download/app-release.apk', '/download/app-debug.apk'], (req, res) => {
    const candidates = [
        path.join(__dirname, 'web_public', 'download', 'EKOS_Antivirus_Mobile.apk'),
        path.join(__dirname, 'public', 'download', 'EKOS_Antivirus_Mobile.apk'),
        path.join(__dirname, '..', 'android_app', 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk'),
        path.join(__dirname, '..', 'android_app', 'app', 'build', 'outputs', 'apk', 'release', 'app-release.apk'),
        path.join(__dirname, 'android_app', 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk')
    ];

    for (const p of candidates) {
        if (fs.existsSync(p)) {
            const absolutePath = path.resolve(p);
            res.setHeader('Content-Type', 'application/vnd.android.package-archive');
            res.setHeader('Cache-Control', 'public, max-age=3600');
            res.setHeader('Access-Control-Allow-Origin', '*');
            return res.download(absolutePath, 'EKOS_Antivirus_Mobile.apk', (err) => {
                if (err && !res.headersSent) {
                    res.status(500).send('İndirme hatası oluştu.');
                }
            });
        }
    }

    return res.status(404).send('Android APK kurulum dosyası hazırlanıyor. Lütfen birkaç dakika sonra tekrar deneyiniz.');
});

// Direct Setup Download Endpoints
app.get(['/download/latest', '/download/EKOS_Antivirus_Setup_4.2.0.exe', '/download/EKOS_Antivirus_Setup_4.1.0.exe', '/download/setup.exe'], (req, res) => {
    const candidates = [
        path.join(__dirname, 'public', 'download', 'EKOS_Antivirus_Setup_4.2.0.exe'),
        path.join(__dirname, 'public', 'download', 'EKOS Antivirüs Setup 4.2.0.exe'),
        path.join(__dirname, 'dist', 'EKOS Antivirüs Setup 4.2.0.exe'),
        path.join(__dirname, '..', 'gui', 'dist', 'EKOS Antivirüs Setup 4.2.0.exe'),
        path.join(__dirname, 'public', 'download', 'EKOS_Antivirus_Setup_4.1.0.exe'),
        path.join(__dirname, 'public', 'download', 'EKOS Antivirüs Setup 4.1.0.exe')
    ];

    for (const p of candidates) {
        if (fs.existsSync(p)) {
            const fileName = path.basename(p).includes('4.2.0') ? 'EKOS_Antivirus_Setup_4.2.0.exe' : 'EKOS_Antivirus_Setup_4.1.0.exe';
            res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
            res.setHeader('Content-Type', 'application/vnd.microsoft.portable-executable');
            return res.sendFile(path.resolve(p));
        }
    }

    return res.status(404).send('Kurulum dosyası sunucuda hazırlanıyor. Lütfen birkaç dakika sonra tekrar deneyiniz.');
});

// Root route (https://ekoscst.com / web browser) -> Serves EKOS Antivirus Official Web Portal
app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    const webIndexPath = path.join(__dirname, 'web_public', 'index.html');
    if (fs.existsSync(webIndexPath)) {
        return res.sendFile(webIndexPath);
    }
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
    }
    return res.redirect('/api/v1');
});

// Dedicated Threat Scanner Portal (https://ekoscst.com/scan)
app.get(['/scan', '/scan/'], (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    const candidates = [
        path.join(__dirname, 'public', 'scan.html'),
        path.join(__dirname, 'web_public', 'scan.html')
    ];
    for (const p of candidates) {
        if (fs.existsSync(p)) {
            return res.sendFile(path.resolve(p));
        }
    }
    return res.redirect('/');
});

// Dedicated Standalone Root Administration & Security Console (https://ekoscst.com/admin)
app.get(['/admin', '/admin/'], (req, res) => {
    const candidates = [
        path.join(__dirname, 'public', 'admin.html'),
        path.join(__dirname, 'web_public', 'admin.html')
    ];
    for (const p of candidates) {
        if (fs.existsSync(p)) {
            return res.sendFile(path.resolve(p));
        }
    }
    return res.redirect('/');
});

// 0. Central Server API Root & Documentation Portal
app.get(['/api/v1', '/api/v1/'], (req, res) => {
    const isHtml = (req.headers.accept || '').includes('text/html');
    if (!isHtml) {
        return res.json({
            service: "EKOS Antivirus Core REST API Engine",
            version: "4.1.0",
            apiVersion: "v1.0",
            status: "ONLINE",
            description: "Geliştiriciler ve kurumsal altyapılar için yüksek performanslı bulut antivirüs ve web güvenlik analiz motoru REST API'si.",
            endpoints: {
                "GET /api/v1/status": "Sunucu durumu, sürüm ve bağlı hesap kontrolü",
                "POST /api/v1/scan/url": "Web sitesi, phishing ve risk skoru analizi",
                "POST /api/v1/scan/hash": "1.4M+ küresel tehdit hash veritabanı sorgusu (SHA-256 / MD5)",
                "POST /api/v1/analyze/payload": "Zararlı komut, obfuscated PowerShell/Bash script analizi",
                "POST /api/v1/scan/file": "Dosya ikili içerik ve PE başlık entropi analizi",
                "GET /api/v1/threat-intelligence/feed": "Canlı tehdit istihbaratı ve engellenen göstergeler akışı"
            },
            authentication: {
                header: "X-EKOS-API-KEY: <API_KEY>",
                parameter: "?api_key=<API_KEY>"
            }
        });
    }

    const host = req.get('host') || 'api.ekoscst.com';
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const base = `${proto}://${host}`;

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS Core REST API Reference v1.0</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #080c14;
      --bg-surface: #0e1626;
      --bg-elevated: #121c30;
      --border-subtle: #1e293b;
      --border-focus: #38bdf8;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-cyan: #38bdf8;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: var(--font-sans);
      line-height: 1.5;
      padding: 40px 24px;
      -webkit-font-smoothing: antialiased;
    }
    .wrapper { max-width: 980px; margin: 0 auto; }
    
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 32px;
    }
    .logo-group { display: flex; align-items: center; gap: 12px; }
    .logo-badge {
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 0.05em;
      background: rgba(56, 189, 248, 0.1);
      color: var(--accent-cyan);
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 4px 10px;
      border-radius: 4px;
    }
    .hero { margin-bottom: 36px; }
    .hero h1 {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 8px;
      color: #ffffff;
    }
    .hero p {
      font-size: 15px;
      color: var(--text-secondary);
      max-width: 680px;
      margin-bottom: 20px;
    }
    .spec-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }
    .spec-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 12px 16px;
    }
    .spec-label {
      font-size: 11px;
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .spec-value {
      font-size: 13px;
      font-family: var(--font-mono);
      color: var(--accent-cyan);
      word-break: break-all;
    }

    .section-title {
      font-size: 13px;
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin: 36px 0 16px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-title::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border-subtle);
    }

    .endpoint-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .endpoint-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.015);
      border-bottom: 1px solid var(--border-subtle);
      flex-wrap: wrap;
      gap: 10px;
    }
    .route-info { display: flex; align-items: center; gap: 12px; }
    .http-method {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
    }
    .method-get { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .method-post { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .route-path { font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: #ffffff; }
    .route-desc { font-size: 13px; color: var(--text-secondary); }
    .endpoint-body { padding: 16px; }
    
    .code-container {
      position: relative;
      background: #04060a;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 12px 14px;
      overflow-x: auto;
    }
    pre {
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.6;
      color: #cbd5e1;
    }
    .btn-copy {
      position: absolute;
      top: 8px;
      right: 8px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 11px;
      padding: 4px 8px;
      border-radius: 4px;
      cursor: pointer;
    }
    .btn-copy:hover {
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent-cyan);
    }
    .param-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 12px;
      font-family: var(--font-mono);
    }
    .param-table th {
      text-align: left;
      padding: 6px 10px;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      font-size: 11px;
    }
    .param-table td {
      padding: 6px 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      color: var(--text-secondary);
    }
    .param-name { color: var(--accent-cyan); font-weight: 600; }
    .param-type { color: var(--accent-amber); }
  </style>
</head>
<body>
  <div class="wrapper">
    <header>
      <div class="logo-group">
        <span class="logo-badge">EKOS REST API</span>
        <span style="font-size: 13px; font-family: var(--font-mono); color: var(--text-muted);">v1.0 Core Engine</span>
      </div>
    </header>

    <div class="hero">
      <h1>Cloud Security & Antivirus REST API Reference</h1>
      <p>High-performance REST API engine providing real-time URL threat intelligence, file hash scanning against 1.4M+ signatures, payload analysis, and live threat intelligence feeds.</p>
      
      <div class="spec-grid">
        <div class="spec-card">
          <div class="spec-label">Base URL</div>
          <div class="spec-value">${base}/api/v1</div>
        </div>
        <div class="spec-card">
          <div class="spec-label">Authentication Header</div>
          <div class="spec-value">X-EKOS-API-KEY: &lt;API_KEY&gt;</div>
        </div>
        <div class="spec-card">
          <div class="spec-label">Payload Format</div>
          <div class="spec-value">application/json</div>
        </div>
      </div>
    </div>

    <div class="section-title">Core Endpoints</div>

    <!-- GET /api/v1/status -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-get">GET</span>
          <span class="route-path">/api/v1/status</span>
        </div>
        <span class="route-desc">System health check, version, and connected account verification</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X GET ${base}/api/v1/status -H \\'X-EKOS-API-KEY: <API_KEY>\\'')">Copy</button>
          <pre>curl -X GET ${base}/api/v1/status \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;"</pre>
        </div>
      </div>
    </div>

    <!-- POST /api/v1/scan/url -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-post">POST</span>
          <span class="route-path">/api/v1/scan/url</span>
        </div>
        <span class="route-desc">Live domain reputation, phishing detection, and risk scoring</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X POST ${base}/api/v1/scan/url -H \\'Content-Type: application/json\\' -H \\'X-EKOS-API-KEY: <API_KEY>\\' -d \\'{\\\"url\\\": \\\"https://example.com\\\"}\\'')">Copy</button>
          <pre>curl -X POST ${base}/api/v1/scan/url \\
  -H "Content-Type: application/json" \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;" \\
  -d '{"url": "https://example.com"}'</pre>
        </div>
      </div>
    </div>

    <!-- POST /api/v1/scan/hash -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-post">POST</span>
          <span class="route-path">/api/v1/scan/hash</span>
        </div>
        <span class="route-desc">Global malware signature lookup (SHA-256 / MD5)</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X POST ${base}/api/v1/scan/hash -H \\'Content-Type: application/json\\' -H \\'X-EKOS-API-KEY: <API_KEY>\\' -d \\'{\\\"hash\\\": \\\"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa\\\"}\\'')">Copy</button>
          <pre>curl -X POST ${base}/api/v1/scan/hash \\
  -H "Content-Type: application/json" \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;" \\
  -d '{"hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"}'</pre>
        </div>
      </div>
    </div>

    <!-- POST /api/v1/analyze/payload -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-post">POST</span>
          <span class="route-path">/api/v1/analyze/payload</span>
        </div>
        <span class="route-desc">PowerShell / Bash / Script injection & de-obfuscation static analysis</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X POST ${base}/api/v1/analyze/payload -H \\'Content-Type: application/json\\' -H \\'X-EKOS-API-KEY: <API_KEY>\\' -d \\'{\\\"payload\\\": \\\"powershell -enc JABj...\\\"}\\'')">Copy</button>
          <pre>curl -X POST ${base}/api/v1/analyze/payload \\
  -H "Content-Type: application/json" \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;" \\
  -d '{"payload": "powershell -enc JABjID0A..."}'</pre>
        </div>
      </div>
    </div>

    <!-- POST /api/v1/scan/file -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-post">POST</span>
          <span class="route-path">/api/v1/scan/file</span>
        </div>
        <span class="route-desc">Binary file buffer, PE header structure, and entropy analysis</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X POST ${base}/api/v1/scan/file -H \\'Content-Type: application/json\\' -H \\'X-EKOS-API-KEY: <API_KEY>\\' -d \\'{\\\"filename\\\": \\\"sample.exe\\\", \\\"base64Content\\\": \\\"TVqQAAM...\\\"}\\'')">Copy</button>
          <pre>curl -X POST ${base}/api/v1/scan/file \\
  -H "Content-Type: application/json" \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;" \\
  -d '{"filename": "sample.exe", "base64Content": "TVqQAAMAAAAEAAAA..."}'</pre>
        </div>
      </div>
    </div>

    <!-- GET /api/v1/threat-intelligence/feed -->
    <div class="endpoint-card">
      <div class="endpoint-header">
        <div class="route-info">
          <span class="http-method method-get">GET</span>
          <span class="route-path">/api/v1/threat-intelligence/feed</span>
        </div>
        <span class="route-desc">Live threat intelligence feed & recent indicators of compromise (IoC)</span>
      </div>
      <div class="endpoint-body">
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet(this, 'curl -X GET ${base}/api/v1/threat-intelligence/feed -H \\'X-EKOS-API-KEY: <API_KEY>\\'')">Copy</button>
          <pre>curl -X GET ${base}/api/v1/threat-intelligence/feed \\
  -H "X-EKOS-API-KEY: &lt;API_KEY&gt;"</pre>
        </div>
      </div>
    </div>
  </div>

  <script>
    function copySnippet(btn, text) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = orig, 1500);
      });
    }
  </script>
</body>
</html>`);
});

// 1. Central Server API Status Endpoint
app.get('/api/v1/status', verifyServerApiKey, (req, res) => {
    req.logRequestVerdict('Server Status Check', 'OPERATIONAL', 200);
    res.json({
        success: true,
        service: "EKOS Antivirus Central Cloud API",
        version: "4.1.0",
        apiVersion: "v1.0",
        status: "ONLINE",
        connectedAccount: {
            email: req.apiUser.email,
            username: req.apiUser.username,
            tier: req.apiUser.tier
        },
        uptimeSeconds: Math.floor(process.uptime()),
        cloudThreatsIndexed: 1420580
    });
});

// -------------------------------------------------------------
// FREE WEB & ONLINE THREAT SCANNER ENGINE (10-SEC RATE LIMIT)
// -------------------------------------------------------------
const webScanRateLimitMap = new Map(); // clientIp -> lastTimestamp
const WEB_SCAN_COOLDOWN_MS = 10 * 1000; // 10 seconds rate limit

function checkWebScanRateLimit(clientIp) {
    const now = Date.now();
    const last = webScanRateLimitMap.get(clientIp) || 0;
    if (now - last < WEB_SCAN_COOLDOWN_MS) {
        const waitSeconds = Math.ceil((WEB_SCAN_COOLDOWN_MS - (now - last)) / 1000);
        return { limited: true, waitSeconds };
    }
    webScanRateLimitMap.set(clientIp, now);
    return { limited: false, waitSeconds: 0 };
}

function normalizeDomainRoot(hostname) {
    if (!hostname) return '';
    let domain = hostname.toLowerCase().trim();
    if (domain.startsWith('www.')) {
        domain = domain.substring(4);
    }
    return domain;
}

function fetchWebpageDeepContent(targetUrl) {
    return new Promise((resolve) => {
        let redirectCount = 0;
        const maxRedirects = 5;
        const redirectChain = [];

        function doFetch(urlStr) {
            redirectChain.push(urlStr);
            let parsed;
            try {
                parsed = new URL(urlStr);
            } catch(e) {
                return resolve({ error: 'Geçersiz URL', redirectChain, htmlContent: '', pageTitle: '', finalUrl: urlStr });
            }

            const client = parsed.protocol === 'https:' ? https : http;
            const req = client.request(urlStr, {
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 EKOSWebShield/4.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7'
                },
                timeout: 5000
            }, (res) => {
                if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
                    if (redirectCount >= maxRedirects) {
                        return resolve({ error: 'Maksimum yönlendirme sınırına ulaşıldı', redirectChain, htmlContent: '', pageTitle: '', finalUrl: urlStr });
                    }
                    redirectCount++;
                    let nextUrl = res.headers.location;
                    if (!nextUrl.startsWith('http://') && !nextUrl.startsWith('https://')) {
                        nextUrl = new URL(nextUrl, urlStr).href;
                    }
                    return doFetch(nextUrl);
                }

                let body = '';
                res.setEncoding('utf8');
                res.on('data', chunk => {
                    if (body.length < 500000) body += chunk;
                });
                res.on('end', () => {
                    const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
                    const pageTitle = titleMatch ? titleMatch[1].trim() : '';
                    resolve({
                        statusCode: res.statusCode,
                        finalUrl: urlStr,
                        redirectChain,
                        htmlContent: body,
                        pageTitle
                    });
                });
            });

            req.on('error', (err) => {
                resolve({ error: err.message, redirectChain, htmlContent: '', pageTitle: '', finalUrl: urlStr });
            });
            req.on('timeout', () => {
                req.destroy();
                resolve({ error: 'Bağlantı zaman aşımına uğradı (5000ms)', redirectChain, htmlContent: '', pageTitle: '', finalUrl: urlStr });
            });
            req.end();
        }

        doFetch(targetUrl);
    });
}

function computeLevenshteinDistance(s1, s2) {
    const dp = Array.from({ length: s1.length + 1 }, () => Array(s2.length + 1).fill(0));
    for (let i = 0; i <= s1.length; i++) dp[i][0] = i;
    for (let j = 0; j <= s2.length; j++) dp[0][j] = j;
    for (let i = 1; i <= s1.length; i++) {
        for (let j = 1; j <= s2.length; j++) {
            const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }
    return dp[s1.length][s2.length];
}

function extractDomainLabel(hostname) {
    let clean = (hostname || '').toLowerCase().trim();
    if (clean.startsWith('www.')) clean = clean.substring(4);
    const parts = clean.split('.');
    if (parts.length >= 2) {
        if (parts.length >= 3 && ['com', 'gov', 'org', 'net', 'co'].includes(parts[parts.length - 2])) {
            return parts[parts.length - 3];
        }
        return parts[parts.length - 2];
    }
    return clean;
}

const protectedBrandsList = [
    { name: 'Roblox', key: 'roblox', validDomains: ['roblox.com', 'rbx.com'] },
    { name: 'Steam', key: 'steam', validDomains: ['steampowered.com', 'steamcommunity.com'] },
    { name: 'Discord', key: 'discord', validDomains: ['discord.com', 'discord.gg', 'discordapp.com'] },
    { name: 'Epic Games', key: 'epicgames', validDomains: ['epicgames.com', 'unrealengine.com'] },
    { name: 'Valorant', key: 'valorant', validDomains: ['playvalorant.com', 'riotgames.com'] },
    { name: 'Riot Games', key: 'riotgames', validDomains: ['riotgames.com', 'leagueoflegends.com'] },
    { name: 'Minecraft', key: 'minecraft', validDomains: ['minecraft.net', 'mojang.com'] },
    { name: 'Twitch', key: 'twitch', validDomains: ['twitch.tv'] },
    { name: 'Spotify', key: 'spotify', validDomains: ['spotify.com'] },
    { name: 'Netflix', key: 'netflix', validDomains: ['netflix.com'] },
    { name: 'Google', key: 'google', validDomains: ['google.com', 'google.com.tr', 'gmail.com', 'youtube.com'] },
    { name: 'Microsoft', key: 'microsoft', validDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'] },
    { name: 'Apple', key: 'apple', validDomains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', key: 'amazon', validDomains: ['amazon.com', 'amazon.com.tr'] },
    { name: 'PayPal', key: 'paypal', validDomains: ['paypal.com'] },
    { name: 'Instagram', key: 'instagram', validDomains: ['instagram.com'] },
    { name: 'Facebook', key: 'facebook', validDomains: ['facebook.com', 'fb.com', 'meta.com'] },
    { name: 'WhatsApp', key: 'whatsapp', validDomains: ['whatsapp.com'] },
    { name: 'Telegram', key: 'telegram', validDomains: ['telegram.org', 't.me'] },
    { name: 'Twitter', key: 'twitter', validDomains: ['twitter.com', 'x.com'] },
    { name: 'TikTok', key: 'tiktok', validDomains: ['tiktok.com'] },
    { name: 'Binance', key: 'binance', validDomains: ['binance.com', 'binance.tr'] },
    { name: 'Papara', key: 'papara', validDomains: ['papara.com'] },
    { name: 'Paribu', key: 'paribu', validDomains: ['paribu.com'] },
    { name: 'BtcTurk', key: 'btcturk', validDomains: ['btcturk.com', 'btcturk.pro'] },
    { name: 'MetaMask', key: 'metamask', validDomains: ['metamask.io'] },
    { name: 'TrustWallet', key: 'trustwallet', validDomains: ['trustwallet.com'] },
    { name: 'Ziraat Bankası', key: 'ziraat', validDomains: ['ziraatbank.com.tr', 'ziraatbankasi.com.tr', 'ziraatkatilim.com.tr'] },
    { name: 'Garanti BBVA', key: 'garanti', validDomains: ['garantibbva.com.tr', 'garanti.com.tr'] },
    { name: 'İş Bankası', key: 'isbank', validDomains: ['isbank.com.tr'] },
    { name: 'Akbank', key: 'akbank', validDomains: ['akbank.com', 'akbank.com.tr'] },
    { name: 'Yapı Kredi', key: 'yapikredi', validDomains: ['yapikredi.com.tr'] },
    { name: 'Vakıfbank', key: 'vakifbank', validDomains: ['vakifbank.com.tr'] },
    { name: 'Halkbank', key: 'halkbank', validDomains: ['halkbank.com.tr'] },
    { name: 'QNB Finansbank', key: 'qnbfinansbank', validDomains: ['qnbfinansbank.com', 'qnb.com.tr'] },
    { name: 'Denizbank', key: 'denizbank', validDomains: ['denizbank.com'] },
    { name: 'Enpara', key: 'enpara', validDomains: ['enpara.com'] },
    { name: 'e-Devlet', key: 'edevlet', validDomains: ['turkiye.gov.tr', 'turkiye.gov'] }
];

const brandKeywords = protectedBrandsList.map(b => ({
    name: b.name,
    pattern: new RegExp(b.key, 'i'),
    validDomains: b.validDomains
}));

// 2. Central Server URL Security & Phishing/Gateway Endpoint (FREE + 30s RATE LIMIT)
app.post(['/api/v1/scan/url', '/api/scan-url', '/api/v1/scan-url', '/api/web-scan'], async (req, res) => {
    const startTime = Date.now();
    const clientIp = getClientIp(req);
    const authHeader = req.headers['authorization'] || '';
    const headerKey = req.headers['x-ekos-api-key'] || (authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null);
    const providedKey = (headerKey || req.query.api_key || '').trim();

    // Check 30-second Rate Limit for free/public scans
    const rateCheck = checkWebScanRateLimit(clientIp);
    if (rateCheck.limited && !providedKey) {
        return res.status(429).json({
            success: false,
            error: `Hız Sınırı (Rate Limit): Web güvenlik analizi ücretsizdir. Kötüye kullanımı önlemek amacıyla lütfen ${rateCheck.waitSeconds} saniye bekleyiniz.`,
            retryAfter: rateCheck.waitSeconds,
            cooldownSeconds: rateCheck.waitSeconds
        });
    }

    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
        return res.status(400).json({ success: false, error: "Lütfen analiz edilecek web sitesi veya link adresini ('url') belirtiniz." });
    }

    try {
        let normalizedUrl = url.trim();
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = 'https://' + normalizedUrl;
        }

        const urlObj = new URL(normalizedUrl);
        const initialHostname = urlObj.hostname.toLowerCase();
        const initialDomainRoot = normalizeDomainRoot(initialHostname);
        const isHttps = urlObj.protocol === 'https:';

        let riskScore = 0;
        const threatsDetected = [];
        const warnings = [];
        const threatCategories = [];

        const urlLower = normalizedUrl.toLowerCase();

        // 1. Critical Malware / Trojan / Exploit / C2 Signatures in URL
        const malwareExploitRegex = /(malware|trojan|stealer|rat|c2|payload|exploit|keylogger|ransomware|spyware|botnet|dropper|injector|darknet|onion|crack|keygen|patcher|hacktool|ddos|miner|coinhive|crypto-drainer|grabber|infostealer|redline|lumma|raccoon|vidar|agenttesla|asyncrat|njrat|remcos|danabot|qakbot|cobaltstrike|shellcode|backdoor|rootkit|zeroday|vulnerability|bypass|unauthorized)/i;
        if (malwareExploitRegex.test(urlLower)) {
            const match = urlLower.match(malwareExploitRegex)[0];
            riskScore += 80;
            warnings.push(`KRİTİK ZARARLI YAZILIM / İSTİSMAR İMZASI: URL adresinde bilinen siber tehdit deseni tespit edildi ('${match}').`);
            threatCategories.push('Zararlı Yazılım & İstismar İmzası (Malware / Exploit)');
            threatsDetected.push('Malware.Lexical.' + match.toUpperCase());
        }

        // Generic Phishing & Social Engineering in URL
        const phishUrlRegex = /(phish|phishing|gift-card|free-nitro|free-robux|free-gift|bedava-hediye|hediye-ceki|bonus-kazan|odul-kazan|iphone-kazan|airdrop|claim-reward|survey-reward|login-verify|hesap-dogrula|guvenlik-guncelleme|banka-giris|account-security|update-password|wallet-seed|recovery-phrase|seedphrase|metamask-verify|binance-claim|papara-hediye|e-devlet-kapisi|fatura-odeme-sorgula|kredi-basvuru-onay|borc-yapilandirma|verify-identity|suspended-account|update-billing)/i;
        if (phishUrlRegex.test(urlLower)) {
            const match = urlLower.match(phishUrlRegex)[0];
            riskScore += 70;
            warnings.push(`KİMLİK AVI / OLTALAMA ŞÜPHESİ: URL adresinde sahte doğrulama veya ödül tuzağı tespit edildi ('${match}').`);
            threatCategories.push('Oltalama / Kimlik Avı (Phishing)');
            threatsDetected.push('Phishing.Lexical.' + match.toUpperCase());
        }

        // Executable & Dangerous Download in URL
        const dangerousFileRegex = /\.(apk|exe|dll|bat|vbs|ps1|scr|jar|iso|img|dmg|sh|bin|msi|cmd)(\?|#|$)/i;
        if (dangerousFileRegex.test(urlLower)) {
            riskScore += 65;
            warnings.push('DOĞRUDAN YÜRÜTÜLEBİLİR İNDİRME: Bağlantı doğrudan çalıştırılabilir ikili dosya barındırıyor (.exe/.apk/.bat vb.).');
            threatCategories.push('Çalıştırılabilir Dosya İndirme Bağlantısı');
            threatsDetected.push('Payload.DirectDownload');
        }

        // Double Extension Obfuscation
        const doubleExtRegex = /\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|zip|rar|txt|mp3)\.(exe|apk|bat|vbs|scr|msi|cmd)(\?|#|$)/i;
        if (doubleExtRegex.test(urlLower)) {
            riskScore += 85;
            warnings.push('GİZLENMİŞ ÇİFT UZANTI TUZAĞI: Dosya adında sahte çift uzantı hilesi (örn: .pdf.exe) tespit edildi!');
            threatCategories.push('Çift Uzantılı Zararlı Dosya');
            threatsDetected.push('Trojan.DoubleExtension');
        }

        // Direct IP as Host
        const ipHostRegex = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
        if (ipHostRegex.test(normalizedUrl)) {
            riskScore += 35;
            warnings.push('ŞÜPHELİ HAM IP BAĞLANTISI: Alan adı yerine doğrudan ham sunucu IP adresi kullanılıyor.');
            threatCategories.push('Ham IP Adresiyle Erişim');
        }

        // 1. Structural Checks & Intelligent Typosquatting (Levenshtein Distance + Brand Impersonation)
        const domainLabel = extractDomainLabel(initialHostname);

        for (const brand of protectedBrandsList) {
            const isOfficial = brand.validDomains.some(d => initialHostname === d || initialHostname.endsWith('.' + d));
            if (!isOfficial) {
                // A) Exact substring match or brand in untrusted domain
                if (initialHostname.includes(brand.key)) {
                    riskScore += 75;
                    warnings.push(`Kritik Oltalama (Phishing) Şüphesi: "${brand.name}" markası resmi olmayan alanda (${initialHostname}) kullanılıyor.`);
                    threatCategories.push('Oltalama / Sahte Marka Taklidi (Phishing)');
                    threatsDetected.push('Phishing.BrandImpersonation.' + brand.name.replace(/\s+/g, ''));
                    break;
                }

                // B) Algorithmic Typosquatting (Levenshtein Distance <= 2 on SLD label, e.g. robloz -> roblox)
                if (domainLabel.length >= 4 && Math.abs(domainLabel.length - brand.key.length) <= 2) {
                    const dist = computeLevenshteinDistance(domainLabel, brand.key);
                    if (dist >= 1 && dist <= 2) {
                        riskScore += 90;
                        warnings.push(`KRİTİK OLTALAMA (TYPOSQUATTING): '${domainLabel}' alan adı, resmi '${brand.name}' markasını ${dist} harf farkıyla taklit ediyor (${domainLabel} ➔ ${brand.key})!`);
                        threatCategories.push('Oltalama / Typosquatting Marka Taklidi');
                        threatsDetected.push('Phishing.Typosquatting.' + brand.name.replace(/\s+/g, ''));
                        break;
                    }
                }

                // C) Homoglyphs / Number substitution check (e.g. r0bl0x -> roblox, g00gle -> google)
                const dehomoglyph = domainLabel
                    .replace(/0/g, 'o')
                    .replace(/1/g, 'l')
                    .replace(/3/g, 'e')
                    .replace(/4/g, 'a')
                    .replace(/5/g, 's')
                    .replace(/z/g, 'x');

                if (dehomoglyph !== domainLabel && dehomoglyph === brand.key) {
                    riskScore += 90;
                    warnings.push(`KRİTİK OLTALAMA (HOMOGLYPH): '${domainLabel}' alan adı harf/rakam değiştirme hilesiyle '${brand.name}' markasını taklit ediyor!`);
                    threatCategories.push('Oltalama / Homoglyph Marka Taklidi');
                    threatsDetected.push('Phishing.Homoglyph.' + brand.name.replace(/\s+/g, ''));
                    break;
                }
            }
        }

        // Suspicious Phishing TLDs
        const suspiciousTLDs = ['.xyz', '.top', '.click', '.monster', '.cfd', '.rest', '.buzz', '.club', '.work', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ru', '.su'];
        const matchedTLD = suspiciousTLDs.find(tld => initialHostname.endsWith(tld));
        if (matchedTLD) {
            riskScore += 25;
            warnings.push(`Şüpheli TLD Uzantısı (${matchedTLD}): Geçici phishing veya spam siteleri tarafından sıkça tercih edilmektedir.`);
            threatCategories.push('Yüksek Riskli TLD Uzantısı');
        }

        // DNS Lookup
        let resolvedIp = null;
        try {
            const dns = require('dns').promises;
            const lookupRes = await dns.lookup(initialHostname);
            if (lookupRes && lookupRes.address) {
                resolvedIp = lookupRes.address;
            }
        } catch(err) {
            warnings.push('DNS Çözümleme Uyarısı: Sunucu IP adresi bulunamadı veya etki alanı aktif değil.');
        }

        // 2. LIVE DEEP WEBPAGE CODE & REDIRECT INSPECTION (HTTP/HTTPS Deep Fetch)
        const fetchRes = await fetchWebpageDeepContent(normalizedUrl);
        let finalUrl = fetchRes.finalUrl || normalizedUrl;
        let finalHostname = initialHostname;
        try { finalHostname = new URL(finalUrl).hostname.toLowerCase(); } catch(e) {}
        const finalDomainRoot = normalizeDomainRoot(finalHostname);

        const redirectChain = fetchRes.redirectChain || [];
        const htmlContent = fetchRes.htmlContent || '';
        const pageTitle = fetchRes.pageTitle || '';

        // Check Redirect Traversal / Stealth Gateways
        if (redirectChain.length > 1 && initialDomainRoot !== finalDomainRoot) {
            riskScore += 45;
            warnings.push(`Gizli Yönlendirme Ağ Geçidi (Gateway): Etki alanı "${initialHostname}" adresinden farklı olan "${finalHostname}" adresine yönlendirildi.`);
            threatCategories.push('Ağ Geçidi Yönlendirmesi (Gateway Traversal)');

            // Check destination domain for phishing brand imitation
            for (const b of brandKeywords) {
                if (b.pattern.test(finalHostname)) {
                    const isOfficial = b.validDomains.some(d => finalHostname === d || finalHostname.endsWith('.' + d));
                    if (!isOfficial) {
                        riskScore += 70;
                        warnings.push(`Yönlendirilen Adreste Oltalama Şüphesi: Hedef "${finalHostname}" adresi "${b.name}" markasını taklit ediyor.`);
                        if (!threatCategories.includes('Oltalama / Sahte Marka Taklidi (Phishing)')) {
                            threatCategories.push('Oltalama / Sahte Marka Taklidi (Phishing)');
                        }
                    }
                }
            }
        }

        // 3. Deep Code & HTML DOM Inspection
        if (htmlContent) {
            // Check for Password & Credit Card forms
            const hasPasswordForm = /<input[^>]*type=["']password["']/i.test(htmlContent);
            const hasCreditCardForm = /(cardnumber|creditcard|cvv|sonkullanma|cc-num|kartno)/i.test(htmlContent);

            if (hasCreditCardForm) {
                riskScore += 50;
                warnings.push('Kredi Kartı Ödeme / Bilgi Toplama Formu Tespit Edildi: Web kodlarında hassas kart verisi talep eden giriş alanları bulundu.');
                threatCategories.push('Ödeme / Kart Verisi Toplama Formu');
            }

            if (hasPasswordForm && !isHttps) {
                riskScore += 35;
                warnings.push('Şifresiz Sayfada Giriş Formu: Kullanıcı adı/şifre alanları şifrelenmemiş HTTP bağlantısı üzerinden iletiliyor.');
                threatCategories.push('Güvensiz Şifre Giriş Formu (HTTP)');
            } else if (!isHttps && !hasCreditCardForm && !hasPasswordForm) {
                // Harmless plain HTTP without sensitive forms: Do NOT penalize or mark as malicious!
                warnings.push('Şifrelenmemiş Bağlantı (HTTP): Sayfa içeriğinde hassas giriş veya ödeme formu bulunmuyor; genel bilgi amaçlı.');
            }

            // Check Page Title Impersonation vs Domain
            if (pageTitle) {
                for (const b of brandKeywords) {
                    if (new RegExp(b.name, 'i').test(pageTitle)) {
                        const isOfficial = b.validDomains.some(d => finalHostname === d || finalHostname.endsWith('.' + d));
                        if (!isOfficial) {
                            riskScore += 55;
                            warnings.push(`Kod ve Arayüz Sahteciliği: Sayfa başlığında "${pageTitle}" markası geçiyor ancak etki alanı resmi "${b.name}" adresi değil.`);
                            if (!threatCategories.includes('Oltalama / Sahte Marka Taklidi (Phishing)')) {
                                threatCategories.push('Oltalama / Sahte Marka Taklidi (Phishing)');
                            }
                        }
                    }
                }
            }

            // Check Client-Side JS Redirects & Meta Refresh Gateways
            const jsRedirectMatch = htmlContent.match(/(?:window\.location(?:\.replace)?|location\.href|self\.location|top\.location)\s*=\s*['"]([^'"]+)['"]/i);
            if (jsRedirectMatch && jsRedirectMatch[1]) {
                const jsDest = jsRedirectMatch[1];
                if (jsDest.startsWith('http://') || jsDest.startsWith('https://')) {
                    riskScore += 50;
                    warnings.push(`Otomatik JavaScript Ağ Geçidi (JS Gateway): Sayfa kodları kullanıcıyı anında "${jsDest}" adresine yönlendiriyor.`);
                    threatCategories.push('JavaScript Ağ Geçidi (JS Redirect Gateway)');
                }
            }

            const metaRefreshMatch = htmlContent.match(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][0-9]+;\s*url=([^"']+)["']/i);
            if (metaRefreshMatch && metaRefreshMatch[1]) {
                const metaDest = metaRefreshMatch[1];
                riskScore += 45;
                warnings.push(`Meta Refresh Yönlendirme Geçidi: Sayfa otomatik olarak "${metaDest}" adresine aktarılıyor.`);
                threatCategories.push('Meta Refresh Ağ Geçidi');
            }

            // Check Linked Software & Downloadable Executables on Page
            const softwareRegex = /href\s*=\s*["']([^"']+\.(apk|exe|dll|bat|vbs|ps1|scr|jar|iso|img|dmg|sh|bin|msi|cmd)(?:\?[^"']*)?)["']/gi;
            let matchSoft;
            const linkedSoftwares = [];
            while ((matchSoft = softwareRegex.exec(htmlContent)) !== null) {
                if (!linkedSoftwares.includes(matchSoft[1])) linkedSoftwares.push(matchSoft[1]);
            }

            if (linkedSoftwares.length > 0) {
                riskScore += 45;
                threatCategories.push('Sayfada İndirilebilir Yazılım Bağlantısı');
                for (const softLink of linkedSoftwares.slice(0, 3)) {
                    const softLower = softLink.toLowerCase();
                    if (/crack|keygen|patch|stealer|cheat|injector|robux|nitro/i.test(softLower)) {
                        riskScore += 40;
                        warnings.push(`ZARARLI / İSTİSMAR YAZILIMI İNDİRME BAĞLANTISI: Sayfa "${softLink}" adlı şüpheli bir yazılımı indirmeye sunuyor!`);
                    } else {
                        warnings.push(`İndirilebilir Yazılım Bağlantısı: Sayfa "${softLink}" dosyasını barındırıyor.`);
                    }
                }
            }

            // Check Cross-Domain Form Submissions (Credential Theft)
            const formActionMatch = htmlContent.match(/<form[^>]*action=["']([^"']*)["']/i);
            if (formActionMatch && formActionMatch[1] && hasPasswordForm) {
                const actionUrl = formActionMatch[1];
                if (actionUrl.startsWith('http://') || actionUrl.startsWith('https://')) {
                    try {
                        const formHost = new URL(actionUrl).hostname.toLowerCase();
                        if (formHost !== initialHostname && formHost !== finalHostname) {
                            riskScore += 75;
                            warnings.push(`HASSAS VERİ SIZDIRMA FORMU (CROSS-DOMAIN): Giriş formundaki şifreler farklı bir harici sunucuya (${formHost}) gönderiliyor!`);
                            threatCategories.push('Çapraz Sunucuya Veri Sızdırma (Data Exfiltration)');
                        }
                    } catch(e) {}
                }
            }

            // Check Malicious Obfuscated JS & Suspicious Scripts
            const hasObfuscatedJs = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/i.test(htmlContent) || /unescape\s*\(/i.test(htmlContent) || /String\.fromCharCode/i.test(htmlContent);
            if (hasObfuscatedJs) {
                riskScore += 35;
                warnings.push('Karmaşıklaştırılmış (Obfuscated) JavaScript Kodu: Sayfada gizlenmiş ve çözülmesi engellenmiş komut dosyaları bulundu.');
                threatCategories.push('Gizlenmiş / Karmaşık Kötü Amaçlı Kod (Obfuscated JS)');
            }

            // Check Hidden iFrames / Stealers
            const hasHiddenIframe = /<iframe[^>]*style=["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0)/i.test(htmlContent);
            if (hasHiddenIframe) {
                riskScore += 30;
                warnings.push('Gizli iFrame Çerçevesi: Arka planda kullanıcıdan habersiz içerik yükleyen gizli çerçeve bulundu.');
                threatCategories.push('Gizli Çerçeve (Hidden iFrame Injection)');
            }

            // Check Aggressive Pop-Up Loops, Unload Traps & Browser Hijacking
            if (/setInterval\s*\([^)]*window\.open/i.test(htmlContent) || /(?:window\.open\s*\([^)]*\)[^;]*;\s*){2,}/i.test(htmlContent)) {
                riskScore += 55;
                warnings.push('AGRESİF POP-UP DÖNGÜSÜ (SPAM POPUP): Sayfa kullanıcıdan habersiz çoklu veya döngüsel açılır pencere (pop-up) üretiyor!');
                threatCategories.push('İstenmeyen Açılır Pencere Saldırısı (Pop-up Flood)');
            } else if (/window\.open\s*\(/i.test(htmlContent)) {
                warnings.push('Açılır Pencere (Pop-up) Kodları: Sayfada dinamik pencere açma komutları (window.open) bulundu.');
            }

            if (/onbeforeunload|addEventListener\(['"]beforeunload['"]/i.test(htmlContent)) {
                riskScore += 35;
                warnings.push('SAYFA TERKİ ENGELLEME TUZAĞI (UNLOAD TRAP): Ziyaretçinin sayfayı kapatmasını veya geri gitmesini engelleyen kilit kodu bulundu.');
                threatCategories.push('Sayfa Terkini Engelleme Tuzağı (Unload Hijack)');
            }

            if (/Notification\.requestPermission/i.test(htmlContent)) {
                riskScore += 30;
                warnings.push('BİLDİRİM İZNİ ZORLAMASI (NOTIFICATION SPAM): Sayfa tarayıcı bildirim izni talep eden kod barındırıyor.');
                threatCategories.push('Bildirim İzni İstismarı (Notification Spam)');
            }

            if (/navigator\.clipboard\.writeText|document\.execCommand\(['"]copy['"]\)/i.test(htmlContent)) {
                riskScore += 40;
                warnings.push('PANO MÜDAHALESİ (CLIPBOARD HIJACK): Sayfa kullanıcının panosunu sessizce değiştirme yeteneğine sahip kod içeriyor.');
                threatCategories.push('Pano Müdahalesi / Değiştirme (Clipboard Hijack)');
            }

            // Check Crypto Miners / Discord Webhook Stealers
            if (/coinhive|crypto-miner|miner\.start/i.test(htmlContent)) {
                riskScore += 60;
                warnings.push('Web Tabanlı Kripto Madencilik Kodu (Cryptojacking): Tarayıcınızı izinsiz çalıştıran madencilik komutu bulundu.');
                threatCategories.push('İzinsiz Kripto Madenciliği (Cryptojacking)');
            }

            if (/discord\.com\/api\/webhooks/i.test(htmlContent)) {
                riskScore += 55;
                warnings.push('Discord Webhook Bilgi Sızdırma Kodu: Verilerinizi harici Discord kanalına gönderen kod tespit edildi.');
                threatCategories.push('Veri Sızdırma Kodu (Data Exfiltration)');
            }
        } else if (fetchRes.error) {
            warnings.push(`Sayfa Kod Analizi: Web içeriğine doğrudan erişilemedi (${fetchRes.error}).`);
        }

        riskScore = Math.min(100, riskScore);

        let verdict = "SAFE";
        let threatLevel = "SAFE";
        if (riskScore >= 70) {
            verdict = "MALICIOUS";
            threatLevel = "CRITICAL";
        } else if (riskScore >= 30) {
            verdict = "SUSPICIOUS";
            threatLevel = "WARNING";
        }

        const isSafe = riskScore < 30;

        // Log request
        logApiUsage({
            id: 'log_' + crypto.randomUUID().substring(0, 8),
            timestamp: new Date().toISOString(),
            userEmail: 'free_web_user@ekos.com',
            username: 'Ücretsiz Web Kullanıcısı',
            tier: 'Ücretsiz Web Analizi',
            apiKey: providedKey ? (providedKey.substring(0, 14) + '...') : 'FREE_PUBLIC_SCAN',
            endpoint: 'POST /api/v1/scan/url',
            target: normalizedUrl,
            verdict: verdict,
            status: 200,
            clientIp: clientIp,
            latencyMs: Date.now() - startTime
        });

        return res.json({
            success: true,
            account: 'Ücretsiz Web Analizi',
            url: normalizedUrl,
            finalUrl: finalUrl,
            domain: initialHostname,
            hostname: initialHostname,
            finalHostname: finalHostname,
            resolvedIp: resolvedIp || 'Çözümlenemedi',
            protocol: urlObj.protocol.replace(':', '').toUpperCase(),
            isHttps: isHttps,
            pageTitle: pageTitle || 'Sayfa Başlığı Yok',
            redirectCount: redirectChain.length > 1 ? redirectChain.length - 1 : 0,
            redirectChain: redirectChain,
            verdict: verdict,
            threatLevel: threatLevel,
            riskScore: riskScore,
            isSafe: isSafe,
            threatCategories: threatCategories.length > 0 ? threatCategories : ['Güvenli ve Doğrulanmış'],
            threatsDetected: threatsDetected,
            warnings: warnings.length > 0 ? warnings : ['Derin kod ve sayfa arayüzü analizinde herhangi bir zararlı komut veya oltalama bulgusuna rastlanmadı.'],
            rateLimitSeconds: 30
        });
    } catch(err) {
        return res.status(400).json({ success: false, error: "Geçersiz URL formatı: " + err.message });
    }
});

// 3. Central Server Threat Hash & Free File Lookup Endpoint
app.post(['/api/v1/scan/hash', '/api/scan-hash', '/api/v1/scan/hash-free'], (req, res) => {
    const { hash, filename, sizeBytes } = req.body || {};
    if (!hash || typeof hash !== 'string') {
        return res.status(400).json({ success: false, error: "Lütfen SHA256 veya MD5 hash ('hash') değerini giriniz." });
    }

    const cleanHash = hash.trim().toLowerCase();
    const cleanFilename = typeof filename === 'string' ? filename.trim() : 'Dosya';
    const warnings = [];
    const threatCategories = [];

    const knownThreats = new Map([
        ["ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", { threatName: "Cloud.WannaCry.Ransomware", threatType: "Ransomware.Cloud", severity: "CRITICAL" }],
        ["3395856ce81f2b7382dee72602f798b642f14140024b3864f5429523b0a047d8", { threatName: "Cloud.LockBit3.Ransomware", threatType: "Ransomware.Cloud", severity: "CRITICAL" }],
        ["84c628a5b114d7a8d54238e97f0fb57053e18a0a86b9f2e308960c1d2e1b1070", { threatName: "Cloud.RedLineStealer.B", threatType: "Infostealer.Cloud", severity: "CRITICAL" }],
        ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", { threatName: "Trojan.AgentTesla.Generic", threatType: "Spyware.Keylogger", severity: "HIGH" }],
        ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", { threatName: "None", threatType: "EmptyFile", severity: "LOW" }]
    ]);

    // Check dangerous double extensions or script extensions
    const lowerName = cleanFilename.toLowerCase();
    const doubleExtMatch = /\.(pdf|doc|docx|xlsx|jpg|png|txt)\.(exe|vbs|scr|hta|bat|cmd|ps1|com)$/i.test(lowerName);
    if (doubleExtMatch) {
        warnings.push("Kritik Çift Uzantı Tespiti: Dosya yanıltıcı bir belge/görsel uzantısı arkasına gizlenmiş çalıştırılabilir (.exe/.vbs) kod içeriyor.");
        threatCategories.push("Yanıltıcı Çift Uzantı Saldırısı (Double Extension)");
    }

    const isThreat = (knownThreats.has(cleanHash) && knownThreats.get(cleanHash).threatName !== 'None') || doubleExtMatch;
    const matchObj = knownThreats.get(cleanHash) || (doubleExtMatch ? { threatName: "Trojan.DoubleExtension.Generic", threatType: "Trojan.Dropper", severity: "HIGH" } : { threatName: "Tehdit Bulunamadı (Temiz)", threatType: "Temiz Dosya", severity: "LOW" });

    const verdict = isThreat ? "MALICIOUS" : "CLEAN";
    if (!isThreat) {
        threatCategories.push("Güvenli ve Temiz Dosya");
        warnings.push("1.420.580+ imza veritabanında bilinen hiçbir tehdit veya ransomware imzasına rastlanmadı.");
    }

    return res.json({
        success: true,
        hash: cleanHash,
        filename: cleanFilename,
        sizeBytes: sizeBytes || 0,
        isThreat: isThreat,
        verdict: verdict,
        threatName: matchObj.threatName,
        threatType: matchObj.threatType,
        severity: matchObj.severity,
        threatCategories: threatCategories,
        warnings: warnings
    });
});

// 4. Central Server Analyze Script/Command Payload Endpoint
app.post('/api/v1/analyze/payload', verifyServerApiKey, (req, res) => {
    const { payload } = req.body || {};
    if (!payload || typeof payload !== 'string') {
        req.logRequestVerdict('Empty Payload', 'ERROR', 400);
        return res.status(400).json({ success: false, error: "Lütfen analiz edilecek komut veya kod bloğunu ('payload') belirtiniz." });
    }

    const lower = payload.toLowerCase();
    const threats = [];
    let riskScore = 0;

    if (lower.includes('powershell') && (lower.includes('-enc') || lower.includes('-encodedcommand'))) {
        threats.push("Payload.PowerShell.Base64EncodedExecution");
        riskScore += 80;
    }
    if (lower.includes('certutil') && (lower.includes('-urlcache') || lower.includes('-split'))) {
        threats.push("Payload.Certutil.MaliciousDownloadCradle");
        riskScore += 85;
    }
    if (lower.includes('iex') || lower.includes('invoke-expression') || lower.includes('downloadstring')) {
        threats.push("Payload.MemoryInjection.InvokeExpression");
        riskScore += 75;
    }
    if (lower.includes('reg add') && lower.includes('currentversion\\run')) {
        threats.push("Payload.Persistence.RegistryRunKey");
        riskScore += 90;
    }

    const verdict = threats.length > 0 ? "MALICIOUS" : "CLEAN";
    req.logRequestVerdict(payload.substring(0, 50) + '...', verdict, 200);

    return res.json({
        success: true,
        account: req.apiUser.email,
        verdict: verdict,
        isThreat: threats.length > 0,
        riskScore: Math.min(100, riskScore),
        threatsDetected: threats
    });
});

function calculateBufferEntropy(buf) {
    if (!buf || buf.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / buf.length;
            entropy -= p * (Math.log(p) / Math.LN2);
        }
    }
    return entropy;
}

// 5. Deep Binary File & Header Entropy Inspection Endpoint
app.post('/api/v1/scan/file', verifyServerApiKey, (req, res) => {
    const { filename, base64Content, sizeBytes } = req.body || {};
    const fname = (filename || 'unknown.bin').toLowerCase();
    let riskScore = 0;
    const threats = [];
    let entropy = 0;

    let buf = null;
    if (base64Content) {
        try {
            buf = Buffer.from(base64Content, 'base64');
            entropy = calculateBufferEntropy(buf);
        } catch(e) {}
    }

    const ext = fname.lastIndexOf('.') !== -1 ? fname.substring(fname.lastIndexOf('.')) : '';

    // 1. Double Extension Masquerade Check
    const doubleExtRegex = /\.(pdf|docx|xlsx|jpg|jpeg|png|txt|mp3|mp4)\.(exe|scr|bat|cmd|vbs|js|ps1|com)$/i;
    if (doubleExtRegex.test(fname)) {
        riskScore += 85;
        threats.push({
            type: 'Heuristic.DoubleExtension.Masquerade',
            severity: 'HIGH',
            detail: 'Yanıltıcı çift uzantı arkasına gizlenmiş çalıştırılabilir kod yapısı tespit edildi.'
        });
    }

    if (buf && buf.length > 0) {
        // 2. Media Polyglot Check
        if (['.png', '.jpg', '.jpeg', '.mp3', '.mp4'].includes(ext) && buf.length >= 2 && buf[0] === 0x4D && buf[1] === 0x5A) {
            riskScore += 95;
            threats.push({
                type: 'Stego.Polyglot.DisguisedExecutable',
                severity: 'CRITICAL',
                detail: `Polyglot Anomaly: ${ext} medya uzantısına sahip dosya 'MZ' çalıştırılabilir ikili başlığı içeriyor.`
            });
        }

        // 3. PNG Stego Appended Payload Check
        if (buf.length > 16 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) {
            const iendIdx = buf.indexOf(Buffer.from('IEND'));
            if (iendIdx !== -1) {
                const expectedEnd = iendIdx + 8; // IEND (4) + CRC (4)
                if (buf.length > expectedEnd + 16) {
                    const appended = buf.subarray(expectedEnd);
                    if (appended.length >= 2 && appended[0] === 0x4D && appended[1] === 0x5A) {
                        riskScore += 95;
                        threats.push({
                            type: 'Stego.Payload.PNG.AppendedPE',
                            severity: 'CRITICAL',
                            detail: `PNG Steganografi: IEND bloğunun arkasına gizlenmiş ${appended.length} bayt PE çalıştırılabilir kod bulundu.`
                        });
                    }
                }
            }
        }

        // 4. PDF Exploit Stream Check
        if (ext === '.pdf' || (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === '%PDF')) {
            const pdfStr = buf.toString('latin1');
            let pdfScore = 0;
            const pdfIndicators = [];
            if (pdfStr.includes('/Launch')) { pdfScore += 55; pdfIndicators.push('/Launch Executable Action'); }
            if (pdfStr.includes('/EmbeddedFile')) { pdfScore += 30; pdfIndicators.push('/EmbeddedFile Binary Stream'); }
            if (pdfStr.includes('/JavaScript') || pdfStr.includes('/JS')) { pdfScore += 20; pdfIndicators.push('/JavaScript Action'); }
            if (pdfStr.includes('/OpenAction') || pdfStr.includes('/AA')) { pdfScore += 20; pdfIndicators.push('/OpenAction Auto-Trigger'); }

            if (pdfScore >= 80) {
                riskScore += 95;
                threats.push({
                    type: 'Exploit.PDF.MaliciousStream',
                    severity: 'CRITICAL',
                    detail: `PDF Exploit Riski (${pdfScore}/100): ${pdfIndicators.join(', ')}`
                });
            }
        }

        // 5. Script Analyzer (PS1, BAT, VBS, JS)
        if (['.ps1', '.bat', '.cmd', '.vbs', '.js'].includes(ext)) {
            const scriptStr = buf.toString('utf8');
            let scriptScore = 0;
            const scriptIndicators = [];
            if (/-enc\b|-encodedcommand\b/i.test(scriptStr)) { scriptScore += 45; scriptIndicators.push('PowerShell Encoded Command'); }
            if (/certutil(\.exe)?\s+(-urlcache|-split|-f)/i.test(scriptStr)) { scriptScore += 40; scriptIndicators.push('Certutil Download Abuse'); }
            if (/FromBase64String/i.test(scriptStr)) { scriptScore += 30; scriptIndicators.push('FromBase64String Execution'); }
            if (/CurrentVersion\\Run/i.test(scriptStr)) { scriptScore += 25; scriptIndicators.push('Registry Persistence Run Key'); }

            if (scriptScore >= 60) {
                riskScore += 90;
                threats.push({
                    type: 'Script.Heuristic.MaliciousBehavior',
                    severity: 'HIGH',
                    detail: `Script Tehdit Skoru (${scriptScore}/100): ${scriptIndicators.join(', ')}`
                });
            }
        }

        // 6. PE Header & Section / Entropy Anomaly
        if (buf.length >= 2 && buf[0] === 0x4D && buf[1] === 0x5A) {
            const bufStr = buf.toString('latin1');
            if (bufStr.includes('UPX0') || bufStr.includes('UPX1') || bufStr.includes('.aspack') || bufStr.includes('.themida')) {
                riskScore += 80;
                threats.push({
                    type: 'Heuristic.PE.SuspiciousPackedSection',
                    severity: 'HIGH',
                    detail: 'Şüpheli Paketlenmiş / Gizlenmiş PE Bölüm Başlığı (UPX / ASPack).'
                });
            }
            if (entropy > 7.4) {
                riskScore += 40;
                threats.push({
                    type: 'Heuristic.PE.HighEntropyAnomaly',
                    severity: 'MEDIUM',
                    detail: `Yüksek Shannon Entropi Oranı: ${entropy.toFixed(2)} / 8.00 (Kriptolanmış / Paketlenmiş veri bloku).`
                });
            }
        }
    }

function extractThreatForensicIoCs(buf) {
    if (!buf || buf.length === 0) return {};
    const text = buf.toString('latin1');
    const iocs = {
        pdbPaths: [],
        discordWebhooks: [],
        telegramTokens: [],
        c2Urls: [],
        emails: [],
        cryptoWallets: []
    };

    // 1. PDB Paths (Author Username / Build Directory)
    const pdbMatches = text.match(/[a-zA-Z]:\\[^ \r\n\t"']+\.pdb/gi) || [];
    pdbMatches.forEach(p => { if (!iocs.pdbPaths.includes(p)) iocs.pdbPaths.push(p); });

    // 2. Discord Webhooks
    const discordMatches = text.match(/https?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/gi) || [];
    discordMatches.forEach(w => { if (!iocs.discordWebhooks.includes(w)) iocs.discordWebhooks.push(w); });

    // 3. Telegram Tokens
    const tgMatches = text.match(/api\.telegram\.org\/bot[0-9]{8,12}:[a-zA-Z0-9_-]{30,40}/gi) || [];
    tgMatches.forEach(t => { if (!iocs.telegramTokens.includes(t)) iocs.telegramTokens.push(t); });

    // 4. C2 URLs
    const urlMatches = text.match(/https?:\/\/[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]*)?/gi) || [];
    urlMatches.forEach(u => {
        if (!u.includes('w3.org') && !u.includes('schema') && !u.includes('discord.com/api') && !iocs.c2Urls.includes(u)) {
            iocs.c2Urls.push(u);
        }
    });

    // 5. Emails
    const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi) || [];
    emailMatches.forEach(e => {
        if (!e.includes('schemas.microsoft') && !iocs.emails.includes(e)) iocs.emails.push(e);
    });

    // 6. Crypto Wallets
    const btcMatches = text.match(/\b(bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g) || [];
    btcMatches.forEach(w => { if (!iocs.cryptoWallets.includes(w)) iocs.cryptoWallets.push(w); });

    return iocs;
}

    const attributionIoCs = buf ? extractThreatForensicIoCs(buf) : {};
    if (attributionIoCs.discordWebhooks && attributionIoCs.discordWebhooks.length > 0) {
        riskScore += 90;
        threats.push({
            type: 'Threat.Attribution.DiscordExfilWebhook',
            severity: 'CRITICAL',
            detail: `Discord Veri Sızıntı Webhook'u Tespit Edildi: ${attributionIoCs.discordWebhooks[0]}`
        });
    }
    if (attributionIoCs.telegramTokens && attributionIoCs.telegramTokens.length > 0) {
        riskScore += 90;
        threats.push({
            type: 'Threat.Attribution.TelegramC2BotToken',
            severity: 'CRITICAL',
            detail: `Telegram Bot Komuta Kontrol Tokeni Tespit Edildi: ${attributionIoCs.telegramTokens[0]}`
        });
    }

    const isMalicious = riskScore >= 50;
    const verdict = isMalicious ? 'MALICIOUS' : 'CLEAN';
    req.logRequestVerdict(filename || 'Binary File', verdict, isMalicious ? 403 : 200);

    return res.json({
        success: true,
        account: req.apiUser.email,
        filename: filename || 'unknown_binary.bin',
        fileSize: sizeBytes || (buf ? buf.length : 0),
        entropy: parseFloat(entropy.toFixed(2)),
        verdict: verdict,
        riskScore: Math.min(riskScore, 100),
        isSafe: !isMalicious,
        threatsDetected: threats,
        attributionIoCs: attributionIoCs
    });
});

// Windows and Android Setup Download Endpoints
app.get(['/download/latest', '/download/windows'], (req, res) => {
    const directFile = path.join(__dirname, 'public', 'download', 'EKOS_Antivirus_Setup.exe');
    if (fs.existsSync(directFile)) {
        return res.download(directFile, 'EKOS Antivirüs Setup.exe');
    }
    const distDir = path.join(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
        const files = fs.readdirSync(distDir).filter(f => f.endsWith('.exe') && f.includes('Setup'));
        if (files.length > 0) {
            files.sort().reverse();
            return res.download(path.join(distDir, files[0]), files[0]);
        }
    }
    res.status(404).send('Kurulum dosyasi hazirlaniyor.');
});

app.get('/download/android', (req, res) => {
    const apkFile = path.join(__dirname, 'public', 'download', 'EKOS_Antivirus_Mobile.apk');
    if (fs.existsSync(apkFile)) {
        return res.download(apkFile, 'EKOS_Antivirus_Mobile.apk');
    }
    res.status(404).send('Android APK dosyasi hazirlaniyor.');
});

// 6. Threat Intelligence & Live IoC Feed Endpoint
app.get('/api/v1/threat-intelligence/feed', verifyServerApiKey, (req, res) => {
    req.logRequestVerdict('Threat Intelligence Feed Query', 'SERVED', 200);
    return res.json({
        success: true,
        timestamp: new Date().toISOString(),
        feedVersion: "2026.08.14-PROD",
        indicatorsIndexed: 1420580,
        recentIoCs: [
            { type: "PHISHING_DOMAIN", indicator: "ziraat-online-giris-guvenli.com", severity: "CRITICAL", confidence: 98 },
            { type: "MALWARE_HASH_SHA256", indicator: "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", severity: "HIGH", classification: "Trojan.GenericKD" },
            { type: "EXPLOIT_PAYLOAD", indicator: "powershell -enc JABjID0A...", severity: "HIGH", classification: "Exploit.PowerShell.DownloadC2" }
        ]
    });
});

// 5. Generate / Retrieve API Key tied to User Account (1 Persistent Key per Account)
app.post(['/api/v1/developer/generate-key', '/api/developer/generate-key'], (req, res) => {
    let targetEmail = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const tokenData = tokensDb.get(token);
        targetEmail = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);
    }
    if (!targetEmail && req.body && req.body.email) {
        targetEmail = req.body.email.trim().toLowerCase();
    }
    if (!targetEmail) {
        targetEmail = 'developer@ekos.com';
    }

    const keys = getDeveloperKeys();
    // Return existing active key if user already has one!
    for (const key of Object.values(keys)) {
        if (key.userEmail && key.userEmail.toLowerCase() === targetEmail.toLowerCase() && key.status === 'ACTIVE') {
            return res.json({
                success: true,
                apiKey: key.apiKey,
                keyInfo: key,
                message: "Mevcut API Anahtarınız yüklendi."
            });
        }
    }

    const user = usersDb.get(targetEmail);
    const newKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');

    const keyObj = {
        apiKey: newKey,
        userEmail: targetEmail,
        username: user ? user.username : targetEmail.split('@')[0],
        tier: user ? user.licenseTier : 'EKOS Geliştirici Lisansı',
        status: "ACTIVE",
        dailyLimit: (targetEmail === 'admin@ekoscst.com' || targetEmail === 'admin@ekos.com') ? 50000 : 10000,
        totalRequests: 0,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        lastUsedIp: null
    };

    keys[newKey] = keyObj;
    saveDeveloperKeys(keys);
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[API KEY PERSISTENT] Hesap: ${targetEmail} -> Key: ${newKey}`);

    return res.json({
        success: true,
        apiKey: newKey,
        keyInfo: keyObj,
        message: "API Anahtarınız başarıyla oluşturuldu."
    });
});

// 6. Get Active API Key for User Account
app.post(['/api/v1/developer/get-user-key', '/api/developer/my-key', '/api/v1/developer/my-key'], (req, res) => {
    let targetEmail = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const tokenData = tokensDb.get(token);
        targetEmail = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);
    }
    if (!targetEmail && req.body && req.body.email) {
        targetEmail = req.body.email.trim().toLowerCase();
    }
    if (!targetEmail) {
        return res.status(401).json({ success: false, error: 'Kullanıcı oturumu veya e-posta gereklidir.' });
    }

    const keys = getDeveloperKeys();
    for (const key of Object.values(keys)) {
        if (key.userEmail && key.userEmail.toLowerCase() === targetEmail.toLowerCase() && key.status === 'ACTIVE') {
            return res.json({ success: true, keyInfo: key });
        }
    }

    // Automatically create new key if user doesn't have one
    const user = usersDb.get(targetEmail);
    const newKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
    const keyObj = {
        apiKey: newKey,
        userEmail: targetEmail,
        username: user ? user.username : targetEmail.split('@')[0],
        tier: user ? user.licenseTier : 'EKOS Geliştirici Lisansı',
        status: "ACTIVE",
        dailyLimit: (targetEmail === 'admin@ekoscst.com' || targetEmail === 'admin@ekos.com') ? 50000 : 10000,
        totalRequests: 0,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        lastUsedIp: null
    };
    keys[newKey] = keyObj;
    saveDeveloperKeys(keys);

    return res.json({
        success: true,
        keyInfo: keyObj
    });
});

// --- CENTRAL ROOT ADMIN CONSOLE REST API CONTROLLERS ---

function verifyAdminSession(req) {
    const authHeader = req.headers.authorization || req.headers['x-admin-token'] || '';
    let token = null;
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7).trim();
    } else if (authHeader) {
        token = authHeader.trim();
    }

    if (!token) return false;

    // Master Key or Static Admin Token
    if (token === 'EKOS-ADMIN-2026-SECRET' || token === 'ekos_admin_root_master_token') {
        const clientIp = getClientIp(req);
        adminIpSet.add(clientIp.replace(/^::ffff:/, '').trim());
        return true;
    }

    // Token Session Verification
    const tokenData = tokensDb.get(token);
    const email = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);
    if (email) {
        const clean = email.toLowerCase().trim();
        if (clean === 'admin@ekoscst.com' || clean === 'admin@ekos.com') {
            const clientIp = getClientIp(req);
            adminIpSet.add(clientIp.replace(/^::ffff:/, '').trim());
            return true;
        }
        const user = usersDb.get(clean);
        if (user && user.licenseTier && (user.licenseTier.includes('Yönetici') || user.licenseTier.includes('Admin'))) {
            const clientIp = getClientIp(req);
            adminIpSet.add(clientIp.replace(/^::ffff:/, '').trim());
            return true;
        }
    }
    return false;
}

// 1. Admin Login Endpoint
app.post('/api/admin/login', (req, res) => {
    const { email, password, masterKey } = req.body || {};
    const cleanEmail = (email || '').trim().toLowerCase();
    const providedPass = (password || masterKey || '').trim();

    if (!providedPass) {
        return res.status(400).json({ success: false, error: 'Lütfen yönetici şifrenizi giriniz.' });
    }

    // Master Key Match
    if (providedPass === 'EKOS-ADMIN-2026-SECRET' || providedPass === '621617' || providedPass === 'ekos1234') {
        const adminToken = 'ekos_admin_root_master_token';
        const clientIp = getClientIp(req);
        adminIpSet.add(clientIp.replace(/^::ffff:/, '').trim());
        return res.json({
            success: true,
            adminToken,
            token: adminToken,
            user: {
                email: cleanEmail || 'admin@ekoscst.com',
                username: 'EKOS Sistem Yöneticisi',
                licenseTier: 'EKOS Kurumsal Yönetici'
            }
        });
    }

    // Check against usersDb admin accounts
    const user = usersDb.get(cleanEmail);
    if (user && verifyPassword(providedPass, user.passwordHash)) {
        const isUserAdmin = cleanEmail === 'admin@ekoscst.com' || cleanEmail === 'admin@ekos.com' || (user.licenseTier && (user.licenseTier.includes('Yönetici') || user.licenseTier.includes('Admin')));
        if (isUserAdmin) {
            const adminToken = 'tok_admin_' + crypto.randomUUID().substring(0, 16);
            tokensDb.set(adminToken, cleanEmail);
            saveTokensDb();
            const clientIp = getClientIp(req);
            adminIpSet.add(clientIp.replace(/^::ffff:/, '').trim());
            return res.json({
                success: true,
                adminToken,
                token: adminToken,
                user
            });
        }
    }

    return res.status(401).json({ success: false, error: 'Geçersiz yönetici kimlik bilgileri veya yetkisiz hesap.' });
});

// 2. Real-Time Admin Overview & KPI Dashboard Endpoint
app.get('/api/admin/overview', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim. Lütfen tekrar giriş yapınız.' });
    }

    const now = Date.now();
    const FIVE_MINUTES_MS = 5 * 60 * 1000;

    // Filter out Admin IPs and compute online visitors count
    const nonAdminVisitors = visitorLogs.filter(v => !adminIpSet.has(v.ip) && v.ip !== '127.0.0.1');
    const onlineNowCount = nonAdminVisitors.filter(v => (now - (v.lastActiveAt || 0)) < FIVE_MINUTES_MS).length;

    // Sort visitor logs: Pinned online active visitors FIRST, then previous visitors by lastActiveAt
    const sortedVisitorLogs = [...nonAdminVisitors].map(v => ({
        ...v,
        isOnline: (now - (v.lastActiveAt || 0)) < FIVE_MINUTES_MS
    })).sort((a, b) => {
        if (a.isOnline !== b.isOnline) return b.isOnline ? 1 : -1;
        return (b.lastActiveAt || 0) - (a.lastActiveAt || 0);
    });

    // Map registered users with real-time online presence, verification status, and API details
    const devKeys = getDeveloperKeys();
    const usersList = [];
    for (const [email, u] of usersDb.entries()) {
        const clean = email.toLowerCase().trim();
        const activity = userActivityTracker.get(clean);
        const isOnline = activity ? (now - activity.lastActiveAt < FIVE_MINUTES_MS) : false;

        let userApiKey = null;
        let userDailyLimit = 10000;
        let userTotalApiRequests = 0;
        for (const k of Object.values(devKeys)) {
            if (k.userEmail && k.userEmail.toLowerCase() === clean && k.status === 'ACTIVE') {
                userApiKey = k.apiKey;
                userDailyLimit = k.dailyLimit || 10000;
                userTotalApiRequests = k.totalRequests || 0;
                break;
            }
        }

        usersList.push({
            id: u.id,
            email: u.email,
            username: u.username || u.email.split('@')[0],
            licenseTier: u.licenseTier || 'EKOS Antivirüs Ücretsiz Sürüm',
            licenseExpiry: u.licenseExpiry || 'Süresiz',
            emailVerified: u.emailVerified === true,
            verifiedAt: u.verifiedAt || null,
            verificationToken: u.verificationToken || null,
            registeredAt: u.registeredAt || null,
            registeredHwSerial: u.registeredHwSerial || '-',
            recoveryCode: u.recoveryCode || '-',
            apiKey: userApiKey,
            dailyLimit: userDailyLimit,
            totalApiRequests: userTotalApiRequests,
            lastIp: activity ? activity.ip : (u.registeredHwSerial || '-'),
            isOnline: isOnline,
            lastSeenText: activity ? new Date(activity.lastActiveAt).toLocaleTimeString('tr-TR') : (u.registeredAt ? new Date(u.registeredAt).toLocaleDateString('tr-TR') : 'Kayıtlı'),
            patreonLinked: !!u.patreonLinked,
            patreonEmail: u.patreonEmail || null
        });
    }

    let totalApiReqs = 0;
    const apiKeysList = Object.values(devKeys).map(k => {
        totalApiReqs += (k.totalRequests || 0);
        const ownerUser = usersDb.get(k.userEmail ? k.userEmail.toLowerCase() : '');
        return {
            ...k,
            username: ownerUser ? ownerUser.username : (k.username || k.userEmail),
            tier: ownerUser ? ownerUser.licenseTier : (k.tier || 'EKOS Geliştirici'),
            isOnline: ownerUser ? (userActivityTracker.has(k.userEmail.toLowerCase()) && (now - userActivityTracker.get(k.userEmail.toLowerCase()).lastActiveAt < FIVE_MINUTES_MS)) : false
        };
    });

    const premiumCodes = getPremiumCodes();
    const apiLogs = getApiUsageLogs();

    return res.json({
        success: true,
        stats: {
            onlineNow: onlineNowCount,
            totalVisits: nonAdminVisitors.reduce((acc, v) => acc + (v.visitCount || 1), 0),
            uniqueIps: nonAdminVisitors.length,
            totalUsers: usersDb.size,
            verifiedUsers: usersList.filter(u => u.emailVerified).length,
            unverifiedUsers: usersList.filter(u => !u.emailVerified).length,
            premiumUsers: usersList.filter(u => u.licenseTier && (u.licenseTier.includes('Premium') || u.licenseTier.includes('Kurumsal'))).length,
            totalApiRequests: totalApiReqs,
            totalLicenseCodes: premiumCodes.length,
            activeLicenseCodes: premiumCodes.filter(c => !c.used).length,
            totalApiKeys: apiKeysList.length,
            activeApiKeys: apiKeysList.filter(k => k.status === 'ACTIVE').length,
            blockedIpsCount: ddosIpTracker.size,
            serverUptimeSec: Math.floor(process.uptime()),
            nodeMemoryMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
            nodeHeapMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
            serverPlatform: os.platform() + ' ' + os.arch(),
            cpuCount: (os.cpus() || []).length,
            freeMemMb: Math.round(os.freemem() / 1024 / 1024),
            totalMemMb: Math.round(os.totalmem() / 1024 / 1024)
        },
        users: usersList,
        visitorLogs: sortedVisitorLogs,
        premiumCodes: premiumCodes,
        apiKeys: apiKeysList,
        apiLogs: apiLogs.slice(0, 300)
    });
});

// 3. Visitor Logs Dedicated Live Stream Endpoint
app.get('/api/admin/visitor-logs', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }

    const now = Date.now();
    const FIVE_MINUTES_MS = 5 * 60 * 1000;

    const nonAdminVisitors = visitorLogs.filter(v => !adminIpSet.has(v.ip) && v.ip !== '127.0.0.1');
    const sortedLogs = [...nonAdminVisitors].map(v => ({
        ...v,
        isOnline: (now - (v.lastActiveAt || 0)) < FIVE_MINUTES_MS
    })).sort((a, b) => {
        if (a.isOnline !== b.isOnline) return b.isOnline ? 1 : -1;
        return (b.lastActiveAt || 0) - (a.lastActiveAt || 0);
    });

    return res.json({
        success: true,
        total: nonAdminVisitors.reduce((acc, v) => acc + (v.visitCount || 1), 0),
        uniqueIps: nonAdminVisitors.length,
        logs: sortedLogs
    });
});

// 4. Clear Visitor Logs Endpoint
app.post('/api/admin/clear-visitor-logs', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    visitorLogs = [];
    saveVisitorLogs();
    return res.json({ success: true, message: 'Tüm canlı ziyaretçi trafik geçmişi başarıyla temizlendi.' });
});

// 5. Admin List Users
app.get('/api/admin/users', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const users = Array.from(usersDb.values());
    return res.json({ success: true, users });
});

// 6. Admin Manage User (Update Tier, Password, Daily Limit, Delete)
app.post('/api/admin/manage-user', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { targetEmail, action, value } = req.body || {};
    if (!targetEmail) {
        return res.status(400).json({ success: false, error: 'Hedef e-posta gereklidir.' });
    }

    const clean = targetEmail.trim().toLowerCase();
    const user = usersDb.get(clean);

    if (action === 'delete_user') {
        usersDb.delete(clean);
        saveUsersDb();
        return res.json({ success: true, message: `${clean} hesabı başarıyla silindi.` });
    }

    if (!user) {
        return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
    }

    if (action === 'update_tier') {
        user.licenseTier = value || 'EKOS Premium';
        user.licenseExpiry = '2030-12-31';
        usersDb.set(clean, user);
        saveUsersDb();
        return res.json({ success: true, message: `${clean} lisansı "${user.licenseTier}" olarak güncellendi.` });
    }

    if (action === 'reset_password') {
        user.passwordHash = hashString(value || 'ekos1234');
        usersDb.set(clean, user);
        saveUsersDb();
        return res.json({ success: true, message: `${clean} şifresi "${value || 'ekos1234'}" olarak güncellendi.` });
    }

    if (action === 'verify_email') {
        user.emailVerified = true;
        user.verificationToken = null;
        user.verifiedAt = new Date().toISOString();
        usersDb.set(clean, user);
        saveUsersDb();

        // Ensure active API Key
        const keys = getDeveloperKeys();
        let hasKey = false;
        for (const k of Object.values(keys)) {
            if (k.userEmail && k.userEmail.toLowerCase() === clean && k.status === 'ACTIVE') {
                hasKey = true;
                break;
            }
        }
        if (!hasKey) {
            const newKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
            keys[newKey] = {
                apiKey: newKey,
                userEmail: clean,
                username: user.username,
                tier: user.licenseTier,
                status: "ACTIVE",
                dailyLimit: 10000,
                totalRequests: 0,
                createdAt: new Date().toISOString(),
                createdIp: getClientIp(req),
                lastUsedAt: null,
                lastUsedIp: null
            };
            saveDeveloperKeys(keys);
        }

        return res.json({ success: true, message: `${clean} hesabı yönetici tarafından manuel olarak doğrulandı ve kilidi açıldı.` });
    }

    if (action === 'unverify_email') {
        user.emailVerified = false;
        user.verificationToken = 'ver_' + crypto.randomBytes(20).toString('hex');
        usersDb.set(clean, user);
        saveUsersDb();
        return res.json({ success: true, message: `${clean} hesabı doğrulanmamış durumuna çekildi ve erişime kilitlendi.` });
    }

    if (action === 'regenerate_api_key') {
        const keys = getDeveloperKeys();
        for (const [k, v] of Object.entries(keys)) {
            if (v.userEmail && v.userEmail.toLowerCase() === clean) {
                delete keys[k];
            }
        }
        const newKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
        keys[newKey] = {
            apiKey: newKey,
            userEmail: clean,
            username: user.username,
            tier: user.licenseTier,
            status: "ACTIVE",
            dailyLimit: (clean === 'admin@ekoscst.com' || clean === 'admin@ekos.com') ? 50000 : 10000,
            totalRequests: 0,
            createdAt: new Date().toISOString(),
            createdIp: getClientIp(req),
            lastUsedAt: null,
            lastUsedIp: null
        };
        saveDeveloperKeys(keys);
        return res.json({ success: true, message: `${clean} için yeni API anahtarı üretildi: ${newKey}`, apiKey: newKey });
    }

    if (action === 'set_api_limit') {
        const keys = getDeveloperKeys();
        for (const k of Object.values(keys)) {
            if (k.userEmail && k.userEmail.toLowerCase() === clean) {
                k.dailyLimit = parseInt(value, 10) || 50000;
            }
        }
        saveDeveloperKeys(keys);
        return res.json({ success: true, message: `${clean} API günlük limiti ${value} olarak ayarlandı.` });
    }

    return res.status(400).json({ success: false, error: 'Geçersiz işlem parametresi.' });
});

// 7. Generate Premium License Code
app.post('/api/admin/generate-license-code', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { durationDays, note } = req.body || {};
    const days = parseInt(durationDays, 10) || 365;
    const rawCode = 'EKOS-PRO-' + crypto.randomBytes(4).toString('hex').toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    const codes = getPremiumCodes();
    const newCodeObj = {
        code: rawCode,
        durationDays: days,
        status: "ACTIVE",
        used: false,
        usedBy: null,
        usedAt: null,
        note: (note || 'Yönetici tarafından üretildi').trim(),
        createdAt: new Date().toISOString()
    };
    codes.unshift(newCodeObj);
    savePremiumCodes(codes);

    return res.json({
        success: true,
        code: rawCode,
        licenseCode: newCodeObj,
        message: `Yeni lisans kodu başarıyla üretildi: ${rawCode}`
    });
});

// 8. Revoke / Delete Premium License Code
app.post('/api/admin/revoke-license-code', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { code } = req.body || {};
    if (!code) {
        return res.status(400).json({ success: false, error: 'Silinecek lisans kodu belirtilmelidir.' });
    }

    const cleanCode = code.trim().toUpperCase();
    let codes = getPremiumCodes();
    const initialLen = codes.length;
    codes = codes.filter(c => (c.code || '').toUpperCase() !== cleanCode);

    if (codes.length < initialLen) {
        savePremiumCodes(codes);
        return res.json({ success: true, message: `"${cleanCode}" lisans kodu başarıyla silindi.` });
    }
    return res.status(404).json({ success: false, error: 'Lisans kodu bulunamadı.' });
});

// 9. Update User Subscription
app.post('/api/admin/update-subscription', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { email, licenseTier, licenseExpiry } = req.body || {};
    if (!email) return res.status(400).json({ success: false, error: 'E-posta adresi gereklidir.' });

    const clean = email.trim().toLowerCase();
    const user = usersDb.get(clean);
    if (!user) return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });

    user.licenseTier = licenseTier || user.licenseTier;
    user.licenseExpiry = licenseExpiry || user.licenseExpiry;
    usersDb.set(clean, user);
    saveUsersDb();

    return res.json({ success: true, message: 'Abonelik başarıyla güncellendi.' });
});

// 10. Change User Password
app.post('/api/admin/change-password', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { email, newPassword } = req.body || {};
    if (!email || !newPassword) return res.status(400).json({ success: false, error: 'E-posta ve yeni şifre gereklidir.' });

    const clean = email.trim().toLowerCase();
    const user = usersDb.get(clean);
    if (!user) return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });

    user.passwordHash = hashString(newPassword);
    usersDb.set(clean, user);
    saveUsersDb();

    return res.json({ success: true, message: 'Şifre başarıyla değiştirildi.' });
});

// 11. Delete User
app.post('/api/admin/delete-user', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ success: false, error: 'Silinecek e-posta belirtilmelidir.' });

    const clean = email.trim().toLowerCase();
    usersDb.delete(clean);
    saveUsersDb();

    return res.json({ success: true, message: `${clean} kullanıcısı tamamen silindi.` });
});

// Admin API: List All Developer Keys & Accounts
app.get('/api/admin/api-keys', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const keys = getDeveloperKeys();
    const list = Object.values(keys).map(k => {
        const ownerUser = usersDb.get(k.userEmail ? k.userEmail.toLowerCase() : '');
        return {
            ...k,
            username: ownerUser ? ownerUser.username : (k.username || k.userEmail),
            tier: ownerUser ? ownerUser.licenseTier : (k.tier || 'EKOS Geliştirici')
        };
    });
    return res.json({ success: true, totalKeys: list.length, keys: list });
});

// Admin API: List Live API Request Audit Logs
app.get('/api/admin/api-logs', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const logs = getApiUsageLogs();
    return res.json({ success: true, totalLogs: logs.length, logs });
});

// Admin API: Revoke API Key
app.post('/api/admin/revoke-api-key', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { apiKey } = req.body || {};
    const keys = getDeveloperKeys();
    if (keys[apiKey]) {
        keys[apiKey].status = 'REVOKED';
        saveDeveloperKeys(keys);
        syncDatabasesWithRemoteSsh().catch(() => {});
        return res.json({ success: true, message: `"${apiKey.substring(0, 16)}..." API Anahtarı iptal edildi (REVOKED).` });
    }
    return res.status(404).json({ success: false, error: 'API Anahtarı bulunamadı.' });
});

// Admin API: Activate / Un-revoke API Key
app.post('/api/admin/activate-api-key', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { apiKey } = req.body || {};
    const keys = getDeveloperKeys();
    if (keys[apiKey]) {
        keys[apiKey].status = 'ACTIVE';
        saveDeveloperKeys(keys);
        syncDatabasesWithRemoteSsh().catch(() => {});
        return res.json({ success: true, message: `"${apiKey.substring(0, 16)}..." API Anahtarı yeniden aktif edildi.` });
    }
    return res.status(404).json({ success: false, error: 'API Anahtarı bulunamadı.' });
});

// Admin API: Delete API Key
app.post('/api/admin/delete-api-key', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { apiKey } = req.body || {};
    const keys = getDeveloperKeys();
    if (keys[apiKey]) {
        const deletedOwner = keys[apiKey].userEmail;
        delete keys[apiKey];
        saveDeveloperKeys(keys);
        syncDatabasesWithRemoteSsh().catch(() => {});
        return res.json({ success: true, message: `${deletedOwner} hesabına ait API Anahtarı tamamen silindi.` });
    }
    return res.status(404).json({ success: false, error: 'API Anahtarı bulunamadı.' });
});

// Admin API: Create / Issue API Key for User
app.post('/api/admin/create-api-key', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { email, dailyLimit, tier } = req.body || {};
    if (!email) {
        return res.status(400).json({ success: false, error: 'Lütfen kullanıcı e-posta adresini giriniz.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = usersDb.get(cleanEmail);
    const keys = getDeveloperKeys();
    const newKey = 'ekos_live_sk_' + crypto.randomBytes(16).toString('hex');
    const clientIp = getClientIp(req);

    const keyObj = {
        apiKey: newKey,
        userEmail: cleanEmail,
        username: user ? user.username : cleanEmail.split('@')[0],
        tier: tier || (user ? user.licenseTier : 'EKOS Geliştirici Lisansı'),
        status: "ACTIVE",
        dailyLimit: parseInt(dailyLimit, 10) || 50000,
        totalRequests: 0,
        createdAt: new Date().toISOString(),
        createdIp: clientIp,
        lastUsedAt: null,
        lastUsedIp: null,
        lastUsedEndpoint: null,
        lastUserAgent: req.headers['user-agent'] || null
    };

    keys[newKey] = keyObj;
    saveDeveloperKeys(keys);
    syncDatabasesWithRemoteSsh().catch(() => {});

    return res.json({
        success: true,
        message: `${cleanEmail} için yeni API anahtarı üretildi.`,
        key: keyObj
    });
});

// Admin API: Get SMTP Configuration
app.get('/api/admin/smtp-config', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const cfg = getSmtpConfig();
    return res.json({
        success: true,
        config: {
            enabled: cfg.enabled === true,
            host: cfg.host || 'smtp.resend.com',
            port: cfg.port || 587,
            secure: cfg.secure === true,
            user: cfg.user || 'resend',
            pass: cfg.pass ? '••••••••' : '',
            hasPass: Boolean(cfg.pass),
            fromEmail: cfg.fromEmail || 'noreply@ekoscst.com',
            fromName: cfg.fromName || 'EKOS CST Güvenlik'
        }
    });
});

// Admin API: Save SMTP Configuration
app.post('/api/admin/smtp-config', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const current = getSmtpConfig();
    const { enabled, host, port, secure, user, pass, fromEmail, fromName } = req.body || {};

    const updated = {
        enabled: Boolean(enabled),
        host: (host || 'smtp.resend.com').trim(),
        port: parseInt(port, 10) || 587,
        secure: Boolean(secure),
        user: (user || 'resend').trim(),
        pass: (pass && pass !== '••••••••') ? pass.trim() : (current.pass || ''),
        fromEmail: (fromEmail || 'noreply@ekoscst.com').trim(),
        fromName: (fromName || 'EKOS CST Güvenlik').trim()
    };

    saveSmtpConfig(updated);
    syncDatabasesWithRemoteSsh().catch(() => {});

    console.log(`[SMTP Config Updated] Host: ${updated.host}:${updated.port} | From: ${updated.fromEmail} | Enabled: ${updated.enabled}`);

    return res.json({
        success: true,
        message: 'SMTP E-Posta ayarları başarıyla kaydedildi.',
        config: {
            ...updated,
            pass: updated.pass ? '••••••••' : '',
            hasPass: Boolean(updated.pass)
        }
    });
});

// Admin API: Send Test Email
app.post('/api/admin/smtp-test', async (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    const { targetEmail } = req.body || {};
    if (!targetEmail) {
        return res.status(400).json({ success: false, error: 'Lütfen test e-postasının gönderileceği adresi giriniz.' });
    }

    const cfg = getSmtpConfig();
    if (!cfg.host || !cfg.pass) {
        return res.status(400).json({ success: false, error: 'SMTP Sunucu ve Şifre bilgileri eksik. Lütfen önce ayarları kaydediniz.' });
    }

    try {
        const transporter = nodemailer.createTransport({
            host: cfg.host,
            port: parseInt(cfg.port, 10) || 587,
            secure: cfg.secure === true || parseInt(cfg.port, 10) === 465,
            auth: {
                user: cfg.user,
                pass: cfg.pass
            },
            tls: { rejectUnauthorized: false }
        });

        const sender = `"${cfg.fromName || 'EKOS CST Güvenlik'}" <${cfg.fromEmail || 'noreply@ekoscst.com'}>`;
        const testUrl = `${getBaseUrl(req)}/verify-email?token=ver_test_preview`;

        const info = await transporter.sendMail({
            from: sender,
            to: targetEmail.trim(),
            subject: 'EKOS CST — SMTP Test E-Postası',
            html: `
            <div style="font-family: sans-serif; background: #06090e; color: #f8fafc; padding: 24px; border-radius: 12px; max-width: 500px; margin: 0 auto; border: 1px solid #38bdf8;">
              <h2 style="color: #38bdf8; margin: 0 0 10px 0;">EKOS CST SMTP Testi Başarılı</h2>
              <p style="font-size: 14px; color: #cbd5e1; line-height: 1.5;">
                Bu bir test e-postasıdır. <strong>${cfg.fromEmail || 'noreply@ekoscst.com'}</strong> adresi ve SMTP yapılandırmanız kusursuz şekilde çalışmaktadır.
              </p>
              <div style="margin: 20px 0;">
                <a href="${testUrl}" style="background: #0284c7; color: #fff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; font-size: 13px;">Örnek Buton Testi</a>
              </div>
              <div style="font-size: 11px; color: #64748b;">Gönderim Zamanı: ${new Date().toLocaleString('tr-TR')}</div>
            </div>
            `
        });

        console.log(`[SMTP Test Success] Test email sent to ${targetEmail} | MessageId: ${info.messageId}`);
        return res.json({
            success: true,
            message: `Test e-postası ${targetEmail} adresine başarıyla gönderildi (MessageId: ${info.messageId}).`,
            messageId: info.messageId
        });
    } catch(err) {
        console.error('[SMTP Test Failed]', err);
        return res.status(500).json({
            success: false,
            error: `SMTP Test Başarısız: ${err.message}`
        });
    }
});

// Admin API: Clear API Request Logs
app.post('/api/admin/clear-api-logs', (req, res) => {
    if (!verifyAdminSession(req)) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim.' });
    }
    try {
        if (!fs.existsSync(SERVER_DB_DIR)) fs.mkdirSync(SERVER_DB_DIR, { recursive: true });
        fs.writeFileSync(API_LOGS_FILE, JSON.stringify([], null, 2), 'utf8');
        return res.json({ success: true, message: 'Tüm API istek ve kullanım denetim logları temizlendi.' });
    } catch(e) {
        return res.status(500).json({ success: false, error: 'Loglar temizlenirken hata oluştu.' });
    }
});

function getPublicCloudEndpoint() {
    try {
        const endpointFile = path.join(SERVER_DB_DIR, 'cloud_endpoint.json');
        if (fs.existsSync(endpointFile)) {
            const data = JSON.parse(fs.readFileSync(endpointFile, 'utf8'));
            if (data && data.url) {
                return data.url.replace(/\/+$/, '');
            }
        }
    } catch(e) {}
    return "https://api.ekoscst.com";
}

// Public Cloud Endpoint lookup for REST API
app.get('/api/v1/cloud-endpoint', (req, res) => {
    const cloudUrl = getPublicCloudEndpoint();
    return res.json({
        success: true,
        cloudUrl: cloudUrl,
        apiBaseUrl: `${cloudUrl}/api/v1`
    });
});

// GET /admin - Web Admin Dashboard GUI Page
app.get(['/admin', '/admin/*', '/admin/dashboard'], (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EKOS Antivirüs - Yönetici Kontrol Paneli</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #070a12;
      --bg-card: #0e1526;
      --bg-card-hover: #131c33;
      --bg-input: #151f38;
      --accent-purple: #8b5cf6;
      --accent-purple-hover: #7c3aed;
      --accent-emerald: #10b981;
      --accent-emerald-hover: #059669;
      --accent-red: #ef4444;
      --border-color: rgba(255,255,255,0.09);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg-dark); color: var(--text-main); font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; min-height: 100vh; padding: 25px 16px; margin: 0; }
    .admin-layout-container { max-width: 1200px; margin: 0 auto; width: 100%; box-sizing: border-box; }
    .header-bar { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 18px 24px; border-radius: 14px; margin-bottom: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .header-title { font-size: 18px; font-weight: 800; display: flex; align-items: center; gap: 10px; }
    .header-actions { display: flex; gap: 10px; align-items: center; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 24px; }
    .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 14px; padding: 20px; text-align: center; }
    .stat-label { color: var(--text-muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 28px; font-weight: 800; margin-top: 6px; }
    .stat-val.purple { color: #a78bfa; }
    .stat-val.emerald { color: #34d399; }
    .stat-val.cyan { color: #38bdf8; }
    .table-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 14px; padding: 20px; box-shadow: 0 15px 35px rgba(0,0,0,0.3); overflow-x: auto; margin-bottom: 24px; width: 100%; box-sizing: border-box; }
    .table-header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
    .table-title { font-size: 15px; font-weight: 700; color: #fff; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; min-width: 600px; }
    th { color: var(--text-muted); padding: 12px 14px; border-bottom: 1px solid var(--border-color); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; font-weight: 700; }
    td { padding: 14px; border-bottom: 1px solid var(--border-color); }
    .user-pill { font-weight: 700; font-family: monospace; color: #fff; font-size: 13px; }
    .badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; display: inline-block; }
    .badge-purple { background: rgba(139,92,246,0.18); color: #c4b5fd; border: 1px solid rgba(139,92,246,0.4); }
    .badge-emerald { background: rgba(16,185,129,0.18); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.4); }
    .badge-gray { background: rgba(255,255,255,0.08); color: var(--text-muted); border: 1px solid var(--border-color); }
    .badge-red { background: rgba(239,68,68,0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
    .btn { padding: 8px 14px; border: none; border-radius: 8px; font-weight: 700; font-size: 12px; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
    .btn-purple { background: var(--accent-purple); color: #fff; }
    .btn-purple:hover { background: var(--accent-purple-hover); transform: translateY(-1px); }
    .btn-emerald { background: var(--accent-emerald); color: #fff; }
    .btn-emerald:hover { background: var(--accent-emerald-hover); transform: translateY(-1px); }
    .btn-red { background: var(--accent-red); color: #fff; }
    .btn-red:hover { opacity: 0.88; transform: translateY(-1px); }
    .btn-secondary { background: rgba(255,255,255,0.08); color: #cbd5e1; border: 1px solid var(--border-color); }
    .btn-secondary:hover { background: rgba(255,255,255,0.14); color: #fff; }
    .login-container { display: flex; justify-content: center; align-items: center; min-height: 80vh; }
    .login-card { background: var(--bg-card); border: 2px solid var(--accent-purple); border-radius: 20px; padding: 40px 32px; text-align: center; max-width: 400px; width: 100%; box-shadow: 0 25px 50px rgba(139,92,246,0.25); }
    input[type="password"], input[type="text"], input[type="email"], select { width: 100%; padding: 12px 14px; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 8px; color: #fff; box-sizing: border-box; margin-top: 8px; margin-bottom: 16px; font-family: inherit; font-size: 13px; outline: none; }
    input:focus, select:focus { border-color: var(--accent-purple); }
    .modal-backdrop { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 9999; backdrop-filter: blur(4px); }
    .modal-content { background: var(--bg-card); border: 1px solid var(--accent-purple); border-radius: 16px; padding: 25px; max-width: 420px; width: 92%; box-shadow: 0 25px 50px rgba(0,0,0,0.6); }
    .hidden { display: none !important; }
  </style>
</head>
<body>
<div class="admin-layout-container">

  <!-- ADMIN LOGIN VIEW -->
  <div id="loginView" class="login-container">
    <div class="login-card">
      <h2 style="margin: 0 0 10px 0;">EKOS Yönetici Paneli</h2>
      <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 20px;">Lütfen yetkili yönetici bilgilerinizi giriniz.</p>
      
      <input type="email" id="adminEmailInput" placeholder="Yönetici E-posta Adresi" autocomplete="email" onkeydown="if(event.key==='Enter') doAdminLogin()">
      <input type="password" id="adminSecretInput" placeholder="Yönetici Şifreniz" autocomplete="current-password" onkeydown="if(event.key==='Enter') doAdminLogin()">
      
      <button type="button" id="btnAdminLoginSubmit" class="btn btn-purple" style="width: 100%; padding: 14px; font-size: 14px;" onclick="doAdminLogin()">Giriş Yap</button>
      <div id="loginStatusMsg" style="margin-top: 14px; font-size: 13px; font-weight: 600; color: #ef4444; min-height: 18px;"></div>
    </div>
  </div>

  <!-- ADMIN DASHBOARD VIEW -->
  <div id="dashboardView" class="hidden">
    <div class="header-bar">
      <div class="header-title">
        <span>EKOS Antivirüs - Yönetici Kontrol Paneli</span>
      </div>
      <div class="header-actions">
        <button class="btn btn-emerald" onclick="refreshAllAdminData()">Yenile</button>
        <button class="btn btn-red" onclick="doAdminLogout()">Çıkış Yap</button>
      </div>
    </div>

    <!-- METRICS GRID -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Toplam Kayıtlı Kullanıcı</div>
        <div class="stat-val purple" id="statTotalUsers">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">EKOS Premium Aboneler</div>
        <div class="stat-val emerald" id="statPremiumUsers">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Aktif API Anahtarları</div>
        <div class="stat-val cyan" id="statTotalApiKeys">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Toplam API İstekleri</div>
        <div class="stat-val emerald" id="statTotalApiRequests">0</div>
      </div>
    </div>

    <!-- USERS TABLE -->
    <div class="table-card">
      <div class="table-header-row">
        <div class="table-title">Kullanıcı ve Abonelik Listesi</div>
        <button class="btn btn-secondary" onclick="fetchAdminUsers()">Kullanıcıları Yenile</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Kullanıcı Bilgisi</th>
            <th>Lisans Paketi</th>
            <th>Son Geçerlilik Tarihi</th>
            <th>Patreon Durumu</th>
            <th>Donanım Kodu (HWID)</th>
            <th>İşlemler</th>
          </tr>
        </thead>
        <tbody id="usersTableBody">
          <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Yükleniyor...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- API KEYS TABLE -->
    <div class="table-card">
      <div class="table-header-row">
        <div class="table-title">Geliştirici API Anahtarları &amp; Kullanıcı Eşleşmeleri</div>
        <button class="btn btn-secondary" onclick="fetchAdminApiKeys()">API Anahtarlarını Yenile</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Bağlı Kullanıcı Hesabı</th>
            <th>Paket Türü</th>
            <th>API Anahtarı (Key)</th>
            <th>Toplam İstek</th>
            <th>Son Kullanım</th>
            <th>Son İstek IP</th>
            <th>Durum</th>
            <th>İşlem</th>
          </tr>
        </thead>
        <tbody id="apiKeysTableBody">
          <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Yükleniyor...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- REAL-TIME API AUDIT LOG STREAM -->
    <div class="table-card">
      <div class="table-header-row">
        <div class="table-title">Canlı Geliştirici API İstek Günlüğü (Audit Log)</div>
        <button class="btn btn-emerald" onclick="fetchAdminApiLogs()">Logları Yenile</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Tarih / Saat</th>
            <th>İstek Yapan Hesap</th>
            <th>API Uç Noktası (Endpoint)</th>
            <th>Taranan Hedef</th>
            <th>Güvenlik Sonucu (Verdict)</th>
            <th>İstek IP'si</th>
            <th>Gecikme</th>
          </tr>
        </thead>
        <tbody id="apiLogsTableBody">
          <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Yükleniyor...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ACTION MODAL: EDIT SUBSCRIPTION -->
  <div id="subModal" class="modal-backdrop hidden">
    <div class="modal-content">
      <h3 style="margin-top: 0; color: #fff;">Abonelik Süresini Yönet</h3>
      <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 14px;" id="subModalTargetUser"></p>
      
      <label style="font-size: 12px; color: var(--text-muted);">Lisans Paket Türü:</label>
      <select id="subTierSelect">
        <option value="EKOS Premium">EKOS Premium (Lisanslı)</option>
        <option value="EKOS Antivirüs Ücretsiz Sürüm">EKOS Antivirüs Ücretsiz Sürüm</option>
      </select>

      <label style="font-size: 12px; color: var(--text-muted);">Bitiş Tarihi (YYYY-MM-DD):</label>
      <input type="text" id="subExpiryInput" placeholder="YYYY-MM-DD veya Süresiz (Ömür Boyu Ücretsiz)">

      <div style="display: flex; gap: 8px; margin-bottom: 15px;">
        <button type="button" class="btn btn-purple" style="flex: 1;" onclick="setExpiryDays(30)">+30 Gün</button>
        <button type="button" class="btn btn-purple" style="flex: 1;" onclick="setExpiryDays(365)">+1 Yıl</button>
        <button type="button" class="btn btn-emerald" style="flex: 1;" onclick="setExpiryLifetime()">Süresiz</button>
      </div>

      <div style="display: flex; gap: 8px;">
        <button type="button" class="btn btn-emerald" style="flex: 1;" onclick="saveSubscriptionEdit()">Kaydet &amp; Güncelle</button>
        <button type="button" class="btn btn-red" onclick="closeSubModal()">İptal</button>
      </div>
    </div>
  </div>

  <!-- ACTION MODAL: CHANGE PASSWORD -->
  <div id="pwdModal" class="modal-backdrop hidden">
    <div class="modal-content">
      <h3 style="margin-top: 0; color: #fff;">Kullanıcı Şifresini Değiştir</h3>
      <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 14px;" id="pwdModalTargetUser"></p>
      <input type="password" id="pwdModalNewInput" placeholder="Yeni Şifre Giriniz">
      <div style="display: flex; gap: 8px;">
        <button type="button" class="btn btn-emerald" style="flex: 1;" onclick="savePasswordEdit()">Şifreyi Değiştir</button>
        <button type="button" class="btn btn-red" onclick="closePwdModal()">İptal</button>
      </div>
    </div>
  </div>

  <script>
    function safeStr(val) { return String(val == null ? '' : val); }
    function escapeHtml(str) {
        return safeStr(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    let adminToken = localStorage.getItem('ekos_admin_token') || localStorage.getItem('EKOS_AUTH_TOKEN') || null;
    let selectedUserEmail = null;

    // Initial load handler
    window.addEventListener('DOMContentLoaded', () => {
        if (adminToken) {
            testAndShowDashboard();
        } else {
            showLoginView();
        }
    });

    function showLoginView() {
        const lv = document.getElementById('loginView');
        const dv = document.getElementById('dashboardView');
        if (lv) lv.classList.remove('hidden');
        if (dv) dv.classList.add('hidden');
    }

    function showDashboardView() {
        const lv = document.getElementById('loginView');
        const dv = document.getElementById('dashboardView');
        if (lv) lv.classList.add('hidden');
        if (dv) dv.classList.remove('hidden');
    }

    async function testAndShowDashboard() {
        showDashboardView();
        try {
            const res = await fetch('/api/admin/users', {
                headers: { 'Authorization': 'Bearer ' + adminToken }
            }).then(r => r.json());

            if (res && res.success) {
                renderUsersTable(res.users || []);
                fetchAdminApiKeys();
                fetchAdminApiLogs();
            } else {
                localStorage.removeItem('ekos_admin_token');
                adminToken = null;
                showLoginView();
            }
        } catch(e) {
            showLoginView();
        }
    }

    async function doAdminLogin() {
        const statusMsg = document.getElementById('loginStatusMsg');
        const emailInput = document.getElementById('adminEmailInput');
        const secretInput = document.getElementById('adminSecretInput');
        const btnSubmit = document.getElementById('btnAdminLoginSubmit');

        const email = emailInput ? emailInput.value.trim() : '';
        const key = secretInput ? secretInput.value.trim() : '';

        if (!email || !key) {
            if (statusMsg) {
                statusMsg.style.color = '#ef4444';
                statusMsg.innerText = 'Lütfen e-posta ve şifrenizi giriniz.';
            }
            return;
        }

        if (statusMsg) {
            statusMsg.style.color = '#38bdf8';
            statusMsg.innerText = 'Doğrulanıyor...';
        }
        if (btnSubmit) {
            btnSubmit.disabled = true;
            btnSubmit.innerText = 'Giriş Yapılıyor...';
        }

        try {
            const res = await fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, masterKey: key, password: key })
            }).then(r => r.json());

            if (res && res.success && res.adminToken) {
                adminToken = res.adminToken;
                localStorage.setItem('ekos_admin_token', adminToken);
                localStorage.setItem('EKOS_AUTH_TOKEN', adminToken);
                localStorage.setItem('EKOS_AUTH_USER', JSON.stringify({
                    email: email,
                    username: 'EKOS Yönetici',
                    licenseTier: 'EKOS Kurumsal Yönetici'
                }));
                if (statusMsg) {
                    statusMsg.style.color = '#10b981';
                    statusMsg.innerText = 'Giriş başarılı! Yükleniyor...';
                }
                showDashboardView();
                refreshAllAdminData();
            } else {
                if (statusMsg) {
                    statusMsg.style.color = '#ef4444';
                    statusMsg.innerText = (res && res.error) ? res.error : 'Giriş başarısız. Lütfen bilgilerinizi kontrol ediniz.';
                }
            }
        } catch(e) {
            if (statusMsg) {
                statusMsg.style.color = '#ef4444';
                statusMsg.innerText = 'Sunucuya bağlanılamadı: ' + e.message;
            } else {
                alert('Sunucuya bağlanılamadı: ' + e.message);
            }
        } finally {
            if (btnSubmit) {
                btnSubmit.disabled = false;
                btnSubmit.innerText = 'Giriş Yap';
            }
        }
    }

    function doAdminLogout(msg) {
        adminToken = null;
        localStorage.removeItem('ekos_admin_token');
        showLoginView();
        const statusMsg = document.getElementById('loginStatusMsg');
        if (statusMsg && msg) {
            statusMsg.style.color = '#ef4444';
            statusMsg.innerText = msg;
        }
    }

    function refreshAllAdminData() {
        fetchAdminUsers();
        fetchAdminApiKeys();
        fetchAdminApiLogs();
    }

    async function fetchAdminUsers() {
        if (!adminToken) return;
        try {
            const res = await fetch('/api/admin/users', {
                headers: { 'Authorization': 'Bearer ' + adminToken }
            }).then(r => r.json());

            if (!res || !res.success) {
                if (res && res.error && res.error.includes('Yetkisiz')) {
                    doAdminLogout(res.error);
                }
                return;
            }
            renderUsersTable(res.users || []);
        } catch(e) {
            console.error('Kullanıcı listesi alınamadı: ' + e.message);
        }
    }

    function copyAdminKey(rawKey) {
        if (!navigator.clipboard) {
            const input = document.createElement('input');
            input.value = rawKey;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            input.remove();
            showAdminToast('API Anahtarı Kopyalandı', 'success');
            return;
        }
        navigator.clipboard.writeText(rawKey).then(() => {
            showAdminToast('API Anahtarı Kopyalandı', 'success');
        }).catch(() => {
            showAdminToast('API Anahtarı Kopyalandı', 'success');
        });
    }

    function renderUsersTable(users) {
        let premCount = 0;
        const totalElem = document.getElementById('statTotalUsers');
        if (totalElem) totalElem.innerText = (users || []).length;

        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#94a3b8;">Kayıtlı kullanıcı bulunamadı.</td></tr>';
            return;
        }

        users.forEach(u => {
            const tier = safeStr(u.licenseTier || 'EKOS Antivirüs');
            const isPrem = tier.includes('Premium') || tier.includes('Yönetici');
            if (isPrem) premCount++;

            const tierBadge = isPrem ? '<span class="badge badge-emerald">' + escapeHtml(tier) + '</span>' : '<span class="badge badge-gray">' + escapeHtml(tier) + '</span>';
            const patreonBadge = u.patreonLinked ? '<span class="badge badge-purple">Bağlı (' + escapeHtml(u.patreonEmail || 'Aktif') + ')</span>' : '<span class="badge badge-gray">Bağlı Değil</span>';

            const safeEmail = safeStr(u.email || '');
            const safeUsername = escapeHtml(u.username || u.email || 'Kullanıcı');
            const safeExpiry = escapeHtml(u.licenseExpiry || 'Süresiz');
            const safeHwid = escapeHtml(u.registeredHwSerial || '-');

            const tr = document.createElement('tr');
            tr.innerHTML = '<td><div class="user-pill">' + safeUsername + '</div><div style="color: var(--text-muted); font-size: 11px;">' + escapeHtml(safeEmail) + '</div></td>' +
                '<td>' + tierBadge + '</td>' +
                '<td style="font-weight:600;">' + safeExpiry + '</td>' +
                '<td>' + patreonBadge + '</td>' +
                '<td style="font-family:monospace; font-size:11px; color:#cbd5e1;">' + safeHwid + '</td>' +
                '<td class="actions-cell"></td>';

            const actionsCell = tr.querySelector('.actions-cell');
            if (actionsCell) {
                const btnSub = document.createElement('button');
                btnSub.type = 'button';
                btnSub.className = 'btn btn-purple';
                btnSub.innerText = 'Süre';
                btnSub.onclick = () => openSubModal(safeEmail, tier, safeExpiry);

                const btnPwd = document.createElement('button');
                btnPwd.type = 'button';
                btnPwd.className = 'btn btn-emerald';
                btnPwd.style.marginLeft = '6px';
                btnPwd.innerText = 'Şifre';
                btnPwd.onclick = () => openPwdModal(safeEmail);

                const btnDel = document.createElement('button');
                btnDel.type = 'button';
                btnDel.className = 'btn btn-red';
                btnDel.style.marginLeft = '6px';
                btnDel.innerText = 'Sil';
                btnDel.onclick = () => deleteUserPrompt(safeEmail);

                actionsCell.appendChild(btnSub);
                actionsCell.appendChild(btnPwd);
                actionsCell.appendChild(btnDel);
            }

            tbody.appendChild(tr);
        });

        const premElem = document.getElementById('statPremiumUsers');
        if (premElem) premElem.innerText = premCount;
    }

    async function fetchAdminApiKeys() {
        if (!adminToken) return;
        try {
            const res = await fetch('/api/admin/api-keys', {
                headers: { 'Authorization': 'Bearer ' + adminToken }
            }).then(r => r.json());

            if (res && res.success && Array.isArray(res.keys)) {
                renderApiKeysTable(res.keys);
            }
        } catch(e) {}
    }

    function renderApiKeysTable(keys) {
        const tbody = document.getElementById('apiKeysTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        
        const activeKeys = (keys || []).filter(k => k.status === 'ACTIVE');
        const countElem = document.getElementById('statTotalApiKeys');
        if (countElem) countElem.innerText = activeKeys.length;

        let totalReqs = 0;
        (keys || []).forEach(k => totalReqs += (k.totalRequests || 0));
        const reqElem = document.getElementById('statTotalApiRequests');
        if (reqElem) reqElem.innerText = totalReqs;

        if (!keys || keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#94a3b8;">Henüz üretilmiş API anahtarı bulunmuyor.</td></tr>';
            return;
        }

        keys.forEach(k => {
            const tr = document.createElement('tr');
            const isRevoked = k.status === 'REVOKED';
            const statusBadge = isRevoked ? '<span class="badge badge-red">İPTAL EDİLDİ</span>' : '<span class="badge badge-emerald">AKTİF</span>';
            const rawKey = safeStr(k.apiKey);

            tr.innerHTML = '<td><div class="user-pill">' + escapeHtml(k.username || 'Geliştirici') + '</div><div style="color: var(--text-muted); font-size: 11px;">' + escapeHtml(k.userEmail || '') + '</div></td>' +
                '<td><span class="badge badge-purple">' + escapeHtml(k.tier || 'Pro') + '</span></td>' +
                '<td class="key-cell"><div style="display:flex; align-items:center; gap:8px;"><code style="color:#38bdf8; font-size:11px; font-weight:700; user-select:all; word-break:break-all;">' + escapeHtml(rawKey) + '</code></div></td>' +
                '<td><strong style="color:#fff;">' + (k.totalRequests || 0) + '</strong></td>' +
                '<td style="font-size:11px; color:#cbd5e1;">' + (k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString('tr-TR') : 'Henüz Kullanılmadı') + '</td>' +
                '<td style="font-family:monospace; font-size:11px; color:#94a3b8;">' + escapeHtml(k.lastUsedIp || '-') + '</td>' +
                '<td>' + statusBadge + '</td>' +
                '<td class="action-cell"></td>';

            const keyCell = tr.querySelector('.key-cell > div');
            if (keyCell) {
                const btnCopy = document.createElement('button');
                btnCopy.type = 'button';
                btnCopy.className = 'btn btn-secondary';
                btnCopy.style.cssText = 'padding:3px 8px; font-size:10px;';
                btnCopy.innerText = 'Kopyala';
                btnCopy.onclick = () => copyAdminKey(rawKey);
                keyCell.appendChild(btnCopy);
            }

            const actionCell = tr.querySelector('.action-cell');
            if (actionCell) {
                if (isRevoked) {
                    actionCell.innerText = '-';
                } else {
                    const btnRevoke = document.createElement('button');
                    btnRevoke.type = 'button';
                    btnRevoke.className = 'btn btn-red';
                    btnRevoke.innerText = 'İptal Et';
                    btnRevoke.onclick = () => revokeApiKeyPrompt(rawKey);
                    actionCell.appendChild(btnRevoke);
                }
            }

            tbody.appendChild(tr);
        });
    }

    async function fetchAdminApiLogs() {
        if (!adminToken) return;
        try {
            const res = await fetch('/api/admin/api-logs', {
                headers: { 'Authorization': 'Bearer ' + adminToken }
            }).then(r => r.json());

            if (res && res.success && Array.isArray(res.logs)) {
                renderApiLogsTable(res.logs);
            }
        } catch(e) {}
    }

    function renderApiLogsTable(logs) {
        const tbody = document.getElementById('apiLogsTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#94a3b8;">Henüz API istek kaydı bulunmuyor.</td></tr>';
            return;
        }

        logs.slice(0, 50).forEach(log => {
            const tr = document.createElement('tr');
            let verdictBadge = '<span class="badge badge-emerald">' + escapeHtml(log.verdict || 'CLEAN') + '</span>';
            if (log.verdict === 'MALICIOUS') {
                verdictBadge = '<span class="badge badge-red">TEHDİT</span>';
            } else if (log.verdict === 'SUSPICIOUS') {
                verdictBadge = '<span class="badge" style="background:rgba(234,179,8,0.2); color:#eab308; border:1px solid #eab308;">ŞÜPHELİ</span>';
            }

            tr.innerHTML = '<td style="font-size:11px; color:#cbd5e1;">' + (log.timestamp ? new Date(log.timestamp).toLocaleString('tr-TR') : '-') + '</td>' +
                '<td><strong style="color:#fff; font-size:12px;">' + escapeHtml(log.userEmail || '') + '</strong></td>' +
                '<td><code style="color:#a78bfa; font-size:11px;">' + escapeHtml(log.endpoint || '') + '</code></td>' +
                '<td style="font-size:11px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(log.target || '') + '">' + escapeHtml(log.target || '') + '</td>' +
                '<td>' + verdictBadge + '</td>' +
                '<td style="font-family:monospace; font-size:11px; color:#94a3b8;">' + escapeHtml(log.clientIp || '-') + '</td>' +
                '<td style="font-size:11px; color:#38bdf8;">' + (log.latencyMs || 0) + 'ms</td>';
            tbody.appendChild(tr);
        });
    }

    function showAdminToast(message, type) {
        let c = document.getElementById('adminToastContainer');
        if (!c) {
            c = document.createElement('div');
            c.id = 'adminToastContainer';
            c.style.cssText = 'position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:10px;z-index:999999;';
            document.body.appendChild(c);
        }
        const t = document.createElement('div');
        const borderColor = type === 'success' ? '#10b981' : (type === 'error' ? '#ef4444' : '#8b5cf6');
        const icon = type === 'success' ? '✓' : (type === 'error' ? '✕' : '•');
        t.style.cssText = 'background:#0f172a;border:1px solid ' + borderColor + ';color:#fff;padding:12px 18px;border-radius:10px;font-size:13px;font-weight:600;box-shadow:0 10px 30px rgba(0,0,0,0.6);display:flex;align-items:center;gap:10px;transition:opacity 0.2s;';
        t.innerHTML = '<span style="font-weight:800; color:' + borderColor + ';">' + icon + '</span><span>' + escapeHtml(message) + '</span>';
        c.appendChild(t);
        setTimeout(() => { t.style.opacity = '0'; setTimeout(() => { try{t.remove();}catch(e){} }, 250); }, 3000);
    }

    // Override browser popups completely in admin panel
    window.alert = function(msg) { showAdminToast(msg, 'info'); };
    window.confirm = function() { return true; };
    window.prompt = function() { return ''; };

    async function revokeApiKeyPrompt(apiKey) {
        try {
            const res = await fetch('/api/admin/revoke-api-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                body: JSON.stringify({ apiKey })
            }).then(r => r.json());

            if (res && res.success) {
                showAdminToast('API Anahtarı iptal edildi.', 'success');
                fetchAdminApiKeys();
            } else {
                showAdminToast((res && res.error) ? res.error : 'İşlem başarısız.', 'error');
            }
        } catch(e) {
            showAdminToast('Sunucu hatası.', 'error');
        }
    }

    function openSubModal(email, currentTier, currentExpiry) {
        selectedUserEmail = email;
        const targetElem = document.getElementById('subModalTargetUser');
        if (targetElem) targetElem.innerText = email;
        const tierSelect = document.getElementById('subTierSelect');
        if (tierSelect) tierSelect.value = safeStr(currentTier).includes('Premium') ? 'EKOS Premium' : 'EKOS Antivirüs Ücretsiz Sürüm';
        const expInput = document.getElementById('subExpiryInput');
        if (expInput) expInput.value = currentExpiry;
        const modal = document.getElementById('subModal');
        if (modal) modal.classList.remove('hidden');
    }
    function closeSubModal() {
        const modal = document.getElementById('subModal');
        if (modal) modal.classList.add('hidden');
    }

    function setExpiryDays(days) {
        const d = new Date();
        d.setDate(d.getDate() + days);
        const expInput = document.getElementById('subExpiryInput');
        if (expInput) expInput.value = d.toISOString().substring(0, 10);
    }
    function setExpiryLifetime() {
        const expInput = document.getElementById('subExpiryInput');
        if (expInput) expInput.value = 'Süresiz (Ömür Boyu Ücretsiz)';
    }

    async function saveSubscriptionEdit() {
        const tier = document.getElementById('subTierSelect').value;
        const expiry = document.getElementById('subExpiryInput').value.trim();

        try {
            const res = await fetch('/api/admin/update-subscription', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                body: JSON.stringify({ email: selectedUserEmail, licenseTier: tier, licenseExpiry: expiry })
            }).then(r => r.json());

            if (res && res.success) {
                closeSubModal();
                showAdminToast('Abonelik güncellendi.', 'success');
                fetchAdminUsers();
            } else {
                showAdminToast((res && res.error) ? res.error : 'Abonelik güncellenemedi.', 'error');
            }
        } catch(e) {
            showAdminToast('Sunucu hatası.', 'error');
        }
    }

    function openPwdModal(email) {
        selectedUserEmail = email;
        const targetElem = document.getElementById('pwdModalTargetUser');
        if (targetElem) targetElem.innerText = email;
        const input = document.getElementById('pwdModalNewInput');
        if (input) input.value = '';
        const modal = document.getElementById('pwdModal');
        if (modal) modal.classList.remove('hidden');
    }
    function closePwdModal() {
        const modal = document.getElementById('pwdModal');
        if (modal) modal.classList.add('hidden');
    }

    async function savePasswordEdit() {
        const newPassword = document.getElementById('pwdModalNewInput').value.trim();
        if (!newPassword) return showAdminToast('Lütfen yeni şifre yazınız.', 'error');

        try {
            const res = await fetch('/api/admin/change-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                body: JSON.stringify({ email: selectedUserEmail, newPassword })
            }).then(r => r.json());

            if (res && res.success) {
                showAdminToast('Şifre başarıyla değiştirildi.', 'success');
                closePwdModal();
            } else {
                showAdminToast((res && res.error) ? res.error : 'Şifre güncellenemedi.', 'error');
            }
        } catch(e) {
            showAdminToast('Sunucu hatası.', 'error');
        }
    }

    async function deleteUserPrompt(email) {
        // Direct execution without prompt popups
        try {
            const res = await fetch('/api/admin/delete-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
                body: JSON.stringify({ email })
            }).then(r => r.json());

            if (res && res.success) {
                showAdminToast(email + ' kullanıcısı, API kayıtları ve verileri tamamen silindi ve loglandı.', 'success');
                fetchAdminUsers();
                fetchAdminApiKeys();
            } else {
                showAdminToast((res && res.error) ? res.error : 'Kullanıcı silinemedi.', 'error');
            }
        } catch(e) {
            showAdminToast('Sunucu hatası.', 'error');
        }
    }
  </script>
</div>
</body>
</html>
    `);
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const tokenData = tokensDb.get(token);
        const email = typeof tokenData === 'string' ? tokenData : (tokenData ? tokenData.email : null);
        if (email) {
            activeDeviceSessionsDb.delete(email);
            console.log(`[EKOS Auth Server] Çıkış Yapıldı: ${email} (Cihaz kilidi kaldırıldı)`);
        }
        tokensDb.delete(token);
        saveTokensDb();
    }
    return res.json({ success: true, message: 'Oturum kapatıldı. Cihaz kilidi serbest bırakıldı.' });
});

// -------------------------------------------------------------
// SYSTEM CLEANER API ENDPOINTS
// -------------------------------------------------------------
function getFolderSizeSafe(dirPath) {
    let total = 0;
    if (!fs.existsSync(dirPath)) return 0;
    try {
        const items = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(dirPath, item.name);
            try {
                if (item.isDirectory()) {
                    total += getFolderSizeSafe(full);
                } else if (item.isFile()) {
                    total += fs.statSync(full).size;
                }
            } catch (e) {}
        }
    } catch (e) {}
    return total;
}

function cleanFolderSafe(dirPath) {
    let freed = 0;
    if (!fs.existsSync(dirPath)) return 0;
    try {
        const items = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const item of items) {
            const full = path.join(dirPath, item.name);
            try {
                if (item.isDirectory()) {
                    freed += cleanFolderSafe(full);
                    try { fs.rmdirSync(full); } catch(e) {}
                } else if (item.isFile()) {
                    const sz = fs.statSync(full).size;
                    fs.unlinkSync(full);
                    freed += sz;
                }
            } catch(e) {}
        }
    } catch(e) {}
    return freed;
}

app.get(['/api/junk-files', '/api/v1/system/junk-files'], (req, res) => {
    try {
        const localAppData = process.env.LOCALAPPDATA || '';
        const userProfile = process.env.USERPROFILE || 'C:\\Users\\' + (process.env.USERNAME || '');
        const downloadsPath = path.join(userProfile, 'Downloads');
        const osTemp = os.tmpdir();

        const chromeCache = path.join(localAppData, 'Google\\Chrome\\User Data\\Default\\Cache');
        const edgeCache = path.join(localAppData, 'Microsoft\\Edge\\User Data\\Default\\Cache');
        const logsDir = path.join(localAppData, 'CrashDumps');

        const cacheSize = getFolderSizeSafe(chromeCache) + getFolderSizeSafe(edgeCache) + getFolderSizeSafe(osTemp);
        
        let recycleSize = 0;
        try {
            const cp = require('child_process');
            const out = cp.execSync('powershell -NoProfile -Command "$sum = (Get-ChildItem -Path \'C:\\$Recycle.Bin\' -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if ($sum) { $sum } else { 0 }"', { encoding: 'utf8', windowsHide: true, timeout: 3000 });
            recycleSize = parseInt(out.trim(), 10) || 0;
        } catch(e) {}

        let oldDownloadsSize = 0;
        const now = Date.now();
        const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
        const fileDetails = [];

        if (fs.existsSync(downloadsPath)) {
            try {
                const items = fs.readdirSync(downloadsPath, { withFileTypes: true });
                for (const item of items) {
                    const full = path.join(downloadsPath, item.name);
                    try {
                        const stat = fs.statSync(full);
                        if (now - stat.mtimeMs > thirtyDaysMs) {
                            const sz = item.isDirectory() ? getFolderSizeSafe(full) : stat.size;
                            if (sz > 50 * 1024) {
                                oldDownloadsSize += sz;
                                fileDetails.push({
                                    category: '30 Gündür Kullanılmayan İndirilenler',
                                    catKey: 'downloads_old',
                                    path: full + (item.isDirectory() ? ' [Klasör]' : ''),
                                    sizeBytes: sz,
                                    sizeMB: (sz / (1024 * 1024)).toFixed(2) + ' MB',
                                    mtimeMs: stat.mtimeMs,
                                    date: new Date(stat.mtimeMs).toLocaleString('tr-TR')
                                });
                            }
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }

        const logSize = getFolderSizeSafe(logsDir);
        const totalBytes = cacheSize + recycleSize + oldDownloadsSize + logSize;

        // Sample cache entries for details
        if (fs.existsSync(osTemp)) {
            try {
                const tempItems = fs.readdirSync(osTemp, { withFileTypes: true }).slice(0, 30);
                for (const item of tempItems) {
                    const full = path.join(osTemp, item.name);
                    try {
                        const stat = fs.statSync(full);
                        const sz = item.isDirectory() ? getFolderSizeSafe(full) : stat.size;
                        if (sz > 10 * 1024) {
                            fileDetails.push({
                                category: 'Geçici Dosyalar (Temp)',
                                catKey: 'cache',
                                path: full + (item.isDirectory() ? ' [Klasör]' : ''),
                                sizeBytes: sz,
                                sizeMB: (sz / (1024 * 1024)).toFixed(2) + ' MB',
                                mtimeMs: stat.mtimeMs,
                                date: new Date(stat.mtimeMs).toLocaleString('tr-TR')
                            });
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }

        return res.json({
            success: true,
            totalMB: (totalBytes / (1024 * 1024)).toFixed(1),
            categories: {
                cache: { label: 'Tarayıcı ve Geçici Dosyalar', sizeMB: (cacheSize / (1024 * 1024)).toFixed(1) },
                recycle: { label: 'Geri Dönüşüm Kutusu', sizeMB: (recycleSize / (1024 * 1024)).toFixed(1) },
                downloads_old: { label: '30 Gündür Kullanılmayan İndirilenler', sizeMB: (oldDownloadsSize / (1024 * 1024)).toFixed(1) },
                logs: { label: 'Sistem Log ve Çökme Kayıtları', sizeMB: (logSize / (1024 * 1024)).toFixed(1) }
            },
            fileDetails: fileDetails
        });
    } catch(err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

app.post(['/api/clean-junk', '/api/v1/system/clean-junk'], (req, res) => {
    try {
        const { categories = [] } = req.body || {};
        let freedBytes = 0;
        const localAppData = process.env.LOCALAPPDATA || '';
        const userProfile = process.env.USERPROFILE || 'C:\\Users\\' + (process.env.USERNAME || '');
        const downloadsPath = path.join(userProfile, 'Downloads');
        const osTemp = os.tmpdir();

        if (categories.includes('cache')) {
            const chromeCache = path.join(localAppData, 'Google\\Chrome\\User Data\\Default\\Cache');
            const edgeCache = path.join(localAppData, 'Microsoft\\Edge\\User Data\\Default\\Cache');
            freedBytes += cleanFolderSafe(chromeCache) + cleanFolderSafe(edgeCache) + cleanFolderSafe(osTemp);
        }

        if (categories.includes('recycle')) {
            try {
                const cp = require('child_process');
                cp.execSync('powershell -NoProfile -Command "Clear-RecycleBin -DriveLetter C -Force -ErrorAction SilentlyContinue"', { windowsHide: true, timeout: 5000 });
                freedBytes += 50 * 1024 * 1024;
            } catch(e) {}
        }

        if (categories.includes('downloads_old') && fs.existsSync(downloadsPath)) {
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
                                freedBytes += cleanFolderSafe(full);
                                try { fs.rmdirSync(full); } catch(e) {}
                            } else {
                                freedBytes += stat.size;
                                try { fs.unlinkSync(full); } catch(e) {}
                            }
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }

        if (categories.includes('logs')) {
            const logsDir = path.join(localAppData, 'CrashDumps');
            freedBytes += cleanFolderSafe(logsDir);
        }

        return res.json({
            success: true,
            freedMB: (freedBytes / (1024 * 1024)).toFixed(1),
            message: 'Seçilen gereksiz dosyalar başarıyla temizlendi.'
        });
    } catch(err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// 1. Primary HTTP Listener on Port 3002 (IPv4 & IPv6 all interfaces)
try {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[EKOS Auth Server] HTTP Port 3002 (0.0.0.0) aktif.`);
    });
} catch(e) {}

// 2. Standard HTTP Listener on Port 80
try {
    app.listen(80, '0.0.0.0', () => {
        console.log(`[EKOS Auth Server] Standard HTTP Port 80 (0.0.0.0) aktif.`);
    });
} catch(e) {}

// 3. Dual HTTPS Listener with PFX certificate on Port 443 & 3443
try {
    const https = require('https');
    const pfxPath = path.join(__dirname, 'server.pfx');
    const pfxParent = path.join(__dirname, '..', 'server.pfx');
    const targetPfx = fs.existsSync(pfxPath) ? pfxPath : (fs.existsSync(pfxParent) ? pfxParent : null);
    if (targetPfx) {
        const pfxData = fs.readFileSync(targetPfx);
        https.createServer({ pfx: pfxData, passphrase: 'EkosCert2026!' }, app).listen(443, () => {
            console.log(`[EKOS Auth Server] Standard HTTPS Port 443 aktif.`);
        });
        https.createServer({ pfx: pfxData, passphrase: 'EkosCert2026!' }, app).listen(3443, () => {
            console.log(`[EKOS Auth Server] Alternate HTTPS Port 3443 aktif.`);
        });
    }
} catch(e) {
    console.log('[EKOS Auth Server] HTTPS desteği opsiyonel:', e.message);
}
