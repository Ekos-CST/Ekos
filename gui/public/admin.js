/**
 * EKOS Antivirus — Standalone Root Administration & Security Console Client
 * High-performance real-time traffic monitoring & user management.
 */

let adminToken = null;
let adminUser = null;
let adminPollInterval = null;
let currentAdminTab = 'visitors';

document.addEventListener('DOMContentLoaded', () => {
    initAdminSession();
    startClock();
});

function startClock() {
    const clockEl = document.getElementById('liveClockText');
    if (!clockEl) return;
    const updateTime = () => {
        const now = new Date();
        clockEl.innerText = now.toLocaleTimeString('tr-TR', { timeZone: 'Europe/Istanbul' }) + ' TSİ';
    };
    updateTime();
    setInterval(updateTime, 1000);
}

function showToast(msg, type = 'info') {
    const container = document.getElementById('adminToastBox') || document.body;
    const toast = document.createElement('div');
    toast.className = 'admin-toast';
    let icon = '•';
    if (type === 'success') { icon = '✓'; toast.style.borderColor = '#10b981'; toast.style.color = '#34d399'; }
    else if (type === 'error') { icon = '✕'; toast.style.borderColor = '#ef4444'; toast.style.color = '#f87171'; }
    else { icon = 'ℹ'; toast.style.borderColor = '#38bdf8'; toast.style.color = '#38bdf8'; }

    toast.innerHTML = `<span style="font-weight:800; margin-right:6px;">${icon}</span><span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.25s ease';
        setTimeout(() => toast.remove(), 250);
    }, 3200);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function initAdminSession() {
    const savedToken = localStorage.getItem('EKOS_AUTH_TOKEN');
    const savedUserJson = localStorage.getItem('EKOS_AUTH_USER');

    if (savedToken && savedUserJson) {
        try {
            const parsedUser = JSON.parse(savedUserJson);
            const isUserAdmin = parsedUser && (
                parsedUser.email === 'admin@ekoscst.com' ||
                parsedUser.email === 'admin@ekos.com' ||
                (parsedUser.licenseTier && (parsedUser.licenseTier.includes('Yönetici') || parsedUser.licenseTier.includes('Admin')))
            );

            if (isUserAdmin) {
                adminToken = savedToken;
                adminUser = parsedUser;
                showDashboard();
                loadAdminDashboardData();
                startLivePolling();
                return;
            }
        } catch(e) {}
    }

    showAuthLock();
}

function showAuthLock() {
    const lockOverlay = document.getElementById('adminAuthOverlay');
    const dashContent = document.getElementById('adminDashboardContent');
    if (lockOverlay) {
        lockOverlay.classList.remove('hidden');
        lockOverlay.style.display = 'flex';
    }
    if (dashContent) {
        dashContent.classList.add('hidden');
        dashContent.style.display = 'none';
    }
    if (adminPollInterval) clearInterval(adminPollInterval);
}

function showDashboard() {
    const lockOverlay = document.getElementById('adminAuthOverlay');
    const dashContent = document.getElementById('adminDashboardContent');
    if (lockOverlay) {
        lockOverlay.classList.add('hidden');
        lockOverlay.style.display = 'none';
    }
    if (dashContent) {
        dashContent.classList.remove('hidden');
        dashContent.style.display = 'block';
    }
}

async function handleAdminLoginSubmit(e) {
    if (e) e.preventDefault();
    const email = document.getElementById('txtAdminLoginEmail').value.trim();
    const password = document.getElementById('txtAdminLoginPassword').value;
    const btn = document.getElementById('btnAdminLoginSubmit');
    const alertBox = document.getElementById('adminLoginAlert');

    if (!email || !password) return;
    if (btn) btn.disabled = true;
    if (alertBox) alertBox.classList.add('hidden');

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, hwSerial: 'WEB-ADMIN-CONSOLE' })
        });
        const data = await res.json();

        if (data.success && data.token && data.user) {
            const isUserAdmin = data.user.email === 'admin@ekoscst.com' ||
                                data.user.email === 'admin@ekos.com' ||
                                (data.user.licenseTier && (data.user.licenseTier.includes('Yönetici') || data.user.licenseTier.includes('Admin')));

            if (!isUserAdmin) {
                if (alertBox) {
                    alertBox.innerText = 'Bu hesaba Sistem Yöneticisi erişim yetkisi tanımlanmamış.';
                    alertBox.classList.remove('hidden');
                }
                if (btn) btn.disabled = false;
                return;
            }

            adminToken = data.token;
            adminUser = data.user;
            localStorage.setItem('EKOS_AUTH_TOKEN', adminToken);
            localStorage.setItem('EKOS_AUTH_USER', JSON.stringify(adminUser));

            showDashboard();
            loadAdminDashboardData();
            startLivePolling();
            showToast('Yönetici girişi doğrulandı.', 'success');
        } else {
            if (alertBox) {
                alertBox.innerText = data.error || 'Geçersiz yönetici kimlik bilgileri.';
                alertBox.classList.remove('hidden');
            }
        }
    } catch(err) {
        if (alertBox) {
            alertBox.innerText = 'Sunucuya bağlanırken ağ hatası oluştu.';
            alertBox.classList.remove('hidden');
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

function handleAdminLogout() {
    localStorage.removeItem('EKOS_AUTH_TOKEN');
    localStorage.removeItem('EKOS_AUTH_USER');
    adminToken = null;
    adminUser = null;
    if (adminPollInterval) clearInterval(adminPollInterval);
    showAuthLock();
    showToast('Oturum kapatıldı.', 'info');
}

function switchAdminTab(tabName) {
    currentAdminTab = tabName;
    const btns = document.querySelectorAll('.admin-tab-btn');
    btns.forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
    });

    const panels = document.querySelectorAll('.admin-view-panel');
    panels.forEach(p => {
        p.classList.toggle('hidden', p.getAttribute('data-panel') !== tabName);
    });

    // Refresh active tab data immediately
    pollAdminOverviewSilently();
}

function startLivePolling() {
    if (adminPollInterval) clearInterval(adminPollInterval);
    adminPollInterval = setInterval(() => {
        pollAdminOverviewSilently();
    }, 3000);
}

async function pollAdminOverviewSilently() {
    if (!adminToken) return;
    try {
        const res = await fetch('/api/admin/overview', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const data = await res.json();

        if (data.success && data.stats) {
            // Update KPI Metric Cards
            const kpiOnline = document.getElementById('kpiOnlineNow');
            const kpiVis = document.getElementById('kpiTotalVisitors');
            const kpiIps = document.getElementById('kpiUniqueIps');
            const kpiUsers = document.getElementById('kpiTotalUsers');
            const kpiReqs = document.getElementById('kpiApiRequests');
            const kpiCodes = document.getElementById('kpiLicenseCodes');

            if (kpiOnline) kpiOnline.innerText = `${data.stats.onlineNow || 1} Aktif`;
            if (kpiVis) kpiVis.innerText = (data.stats.totalVisits || 0).toLocaleString('tr-TR');
            if (kpiIps) kpiIps.innerText = (data.stats.uniqueIps || 0).toLocaleString('tr-TR');
            if (kpiUsers) kpiUsers.innerText = (data.stats.totalUsers || 0).toLocaleString('tr-TR');
            if (kpiReqs) kpiReqs.innerText = (data.stats.totalApiRequests || 0).toLocaleString('tr-TR');
            if (kpiCodes) kpiCodes.innerText = (data.stats.totalLicenseCodes || 0).toLocaleString('tr-TR');

            // Seamlessly update users and logs tables
            if (data.users) renderUsersTable(data.users);
            if (data.visitorLogs) renderVisitorLogsTable(data.visitorLogs);
            if (data.premiumCodes) renderCodesTable(data.premiumCodes);
        } else if (res.status === 401 || res.status === 403) {
            handleAdminLogout();
        }
    } catch(e) {}
}

async function loadAdminDashboardData() {
    await pollAdminOverviewSilently();
}

async function loadVisitorLogsOnly() {
    if (!adminToken) return;
    const tbody = document.getElementById('visitorLogsTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="text-dim" style="text-align:center; padding:16px;">Canlı trafik akışı çekiliyor...</td></tr>';

    try {
        const res = await fetch('/api/admin/visitor-logs', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('kpiTotalVisitors').innerText = (data.total || 0).toLocaleString('tr-TR');
            document.getElementById('kpiUniqueIps').innerText = (data.uniqueIps || 0).toLocaleString('tr-TR');
            renderVisitorLogsTable(data.logs || []);
            showToast('Canlı trafik güncellendi.', 'info');
        }
    } catch(e) {
        showToast('Ziyaretçi kayıtları alınamadı.', 'error');
    }
}

async function loadVisitorLogsSilently() {
    if (!adminToken) return;
    try {
        const res = await fetch('/api/admin/visitor-logs', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('kpiTotalVisitors').innerText = (data.total || 0).toLocaleString('tr-TR');
            document.getElementById('kpiUniqueIps').innerText = (data.uniqueIps || 0).toLocaleString('tr-TR');
            renderVisitorLogsTable(data.logs || []);
        }
    } catch(e) {}
}

function renderVisitorLogsTable(logs) {
    const tbody = document.getElementById('visitorLogsTableBody');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-dim" style="text-align:center; padding:24px;">Henüz kaydedilmiş ziyaretçi akışı bulunmuyor.</td></tr>';
        return;
    }

    const now = Date.now();
    tbody.innerHTML = logs.map(l => {
        const timePart = l.timeFormatted ? l.timeFormatted.split(' ')[1] || l.timeFormatted : '-';
        const methodCls = l.method === 'GET' ? 'method-get' : (l.method === 'POST' ? 'method-post' : 'method-other');
        const statusCls = (l.statusCode >= 200 && l.statusCode < 300) ? 'status-200' : ((l.statusCode === 403) ? 'status-403' : 'status-400');
        
        const logTime = l.lastActiveAt || (l.timestamp ? new Date(l.timestamp).getTime() : 0);
        const isOnline = l.isOnline === true || ((now - logTime) < 5 * 60 * 1000);
        const liveDot = isOnline 
            ? '<span class="online-pulse-dot" style="margin-right: 8px; vertical-align: middle;" title="Şu An Web Sitesinde Aktif (Canlı Ziyaretçi)"></span>' 
            : '<span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#475569; margin-right:8px; vertical-align:middle;" title="Geçmiş Ziyaretçi (Ayrıldı)"></span>';
        
        const visitBadge = (l.visitCount && l.visitCount > 1) 
            ? `<span style="font-size:10px; padding:1px 6px; border-radius:8px; background:rgba(56,189,248,0.18); color:#38bdf8; font-weight:700; margin-left:6px;" title="Bu IP'den gelen toplam sayfa/indirme isteği">${l.visitCount} İstek</span>` 
            : '';

        return `
            <tr style="${isOnline ? 'background: rgba(34, 197, 94, 0.04);' : ''}">
                <td style="font-family: var(--font-mono); font-size: 12px; color: ${isOnline ? '#4ade80' : '#94a3b8'}; white-space: nowrap;">
                    <div style="display:flex; align-items:center;">
                        ${liveDot}<span>${escapeHtml(timePart)}</span>${visitBadge}
                    </div>
                </td>
                <td style="white-space: nowrap;">
                    <span class="country-flag-badge">${escapeHtml(l.country || 'TR')}</span>
                    <span class="visitor-ip-badge" style="${isOnline ? 'border-color: rgba(34,197,94,0.5); color: #86efac;' : ''}">${escapeHtml(l.ip)}</span>
                    <span style="font-size: 11px; color: #64748b; margin-left: 4px;">${escapeHtml(l.city && l.city !== '-' ? l.city : '')}</span>
                </td>
                <td style="white-space: nowrap;">
                    <span class="visitor-method-badge ${methodCls}">${escapeHtml(l.method)}</span>
                    <span class="visitor-path" style="font-family: var(--font-mono); font-size: 12px; color: #f1f5f9;">${escapeHtml(l.path)}</span>
                </td>
                <td style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: #cbd5e1;" title="${escapeHtml(l.userAgent || '')}">
                    ${escapeHtml(l.deviceSummary || l.userAgent || 'Web Tarayıcı')}
                </td>
                <td style="white-space: nowrap;">
                    <span class="visitor-status-badge ${statusCls}">${escapeHtml(l.statusCode || 200)} • ${l.durationMs || 0}ms</span>
                </td>
                <td style="white-space: nowrap;">
                    <button type="button" class="btn-row-action" onclick="navigator.clipboard.writeText('${escapeHtml(l.ip)}'); showToast('IP kopyalandı: ${escapeHtml(l.ip)}', 'success');">IP Kopyala</button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-dim" style="text-align:center; padding:24px;">Henüz kayıtlı kullanıcı bulunmuyor.</td></tr>';
        return;
    }

    tbody.innerHTML = users.map(u => {
        const tier = u.licenseTier || 'Standart';
        const pillCls = (tier.includes('Premium') || tier.includes('Kurumsal') || tier.includes('Yönetici')) ? 'tier-pill-gold' : 'tier-pill-cyan';
        const statusBadge = u.isOnline 
            ? `<span class="badge-online"><span class="online-pulse-dot"></span> Çevrimiçi</span>`
            : `<span class="badge-offline">Çevrimdışı</span>`;

        return `
            <tr>
                <td>${statusBadge}</td>
                <td><strong style="color: #f8fafc; font-size: 13px;">${escapeHtml(u.email)}</strong></td>
                <td><span class="visitor-ip-badge">${escapeHtml(u.lastIp || '-')}</span></td>
                <td>${escapeHtml(u.username)}</td>
                <td><span class="${pillCls}">${escapeHtml(tier)}</span></td>
                <td><span style="font-size: 12px; color: #94a3b8; font-weight: 600;">${escapeHtml(u.lastSeenText || 'Kayıtlı')}</span></td>
                <td class="font-mono text-amber" style="font-weight:700;">${(u.totalRequests || 0).toLocaleString('tr-TR')}</td>
                <td>
                    <div class="btn-action-group">
                        <button type="button" class="btn-row-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'update_tier', 'EKOS Kurumsal Premium')" title="Premium Pakete Yükselt">Premium</button>
                        <button type="button" class="btn-row-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'set_api_limit', 100000)" title="100k API Kotası Tanımla">100k Kota</button>
                        <button type="button" class="btn-row-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'reset_password', 'ekos1234')" title="Şifreyi ekos1234 Yap">Şifre Sıfırla</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function renderCodesTable(codes) {
    const tbody = document.getElementById('codesTableBody');
    if (!tbody) return;

    if (!codes || codes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-dim" style="text-align:center; padding:24px;">Henüz üretilmiş lisans anahtarı bulunmuyor.</td></tr>';
        return;
    }

    tbody.innerHTML = codes.map(c => `
        <tr>
            <td class="font-mono" style="color: #38bdf8; font-weight: 800; font-size: 13px;">${escapeHtml(c.code)}</td>
            <td>${c.durationDays === 9999 ? 'Ömür Boyu (Süresiz)' : escapeHtml(c.durationDays) + ' Gün'}</td>
            <td><span class="${c.status === 'USED' ? 'badge-offline' : 'badge-online'}">${c.status === 'USED' ? 'Kullanıldı' : 'Aktif (Boşta)'}</span></td>
            <td>${escapeHtml(c.usedBy || '-')}</td>
            <td>
                <div class="btn-action-group">
                    <button type="button" class="btn-row-action" onclick="navigator.clipboard.writeText('${escapeHtml(c.code)}'); showToast('Lisans anahtarı panoya kopyalandı.', 'success');">Kopyala</button>
                    <button type="button" class="btn-row-action btn-row-danger" onclick="handleAdminRevokeLicenseKey('${escapeHtml(c.code)}')">Sil</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function handleAdminGenerateLicenseKey() {
    const days = parseInt(document.getElementById('selAdminLicenseDays').value, 10) || 365;
    const note = document.getElementById('txtAdminLicenseNote').value.trim();

    try {
        const res = await fetch('/api/admin/generate-license-code', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ durationDays: days, note })
        });
        const data = await res.json();
        if (data.success) {
            const newCode = data.code || (data.licenseCode && data.licenseCode.code) || 'Başarılı';
            showToast(`Yeni lisans kodu üretildi: ${newCode}`, 'success');
            document.getElementById('txtAdminLicenseNote').value = '';
            pollAdminOverviewSilently();
        } else {
            showToast('Hata: ' + (data.error || 'Kod üretilemedi.'), 'error');
        }
    } catch(e) {
        showToast('Sunucu hatası: ' + e.message, 'error');
    }
}

async function handleAdminRevokeLicenseKey(code) {
    if (!confirm(`"${code}" lisans kodunu kalıcı olarak silmek istediğinize emin misiniz?`)) return;

    try {
        const res = await fetch('/api/admin/revoke-license-code', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.success) {
            showToast('Lisans kodu silindi.', 'success');
            loadAdminDashboardData();
        } else {
            showToast('Hata: ' + (data.error || 'İşlem başarısız.'), 'error');
        }
    } catch(e) {
        showToast('Sunucu hatası.', 'error');
    }
}

async function handleAdminClearVisitorLogs() {
    if (!confirm('Tüm canlı ziyaretçi trafik geçmişini temizlemek istediğinize emin misiniz?')) return;

    try {
        const res = await fetch('/api/admin/clear-visitor-logs', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message, 'success');
            loadVisitorLogsOnly();
        } else {
            showToast('Hata: ' + (data.error || 'Temizlenemedi.'), 'error');
        }
    } catch(e) {
        showToast('Sunucu hatası.', 'error');
    }
}

async function handleAdminManageUser(targetEmail, action, value) {
    let confirmMsg = `${targetEmail} kullanıcısı için "${action}" işlemi yapılsın mı?`;
    if (action === 'update_tier') confirmMsg = `${targetEmail} hesabının lisansı "${value}" yapılsın mı?`;
    if (action === 'reset_password') confirmMsg = `${targetEmail} hesabının şifresi "${value}" olarak güncellensin mi?`;
    if (action === 'set_api_limit') confirmMsg = `${targetEmail} hesabının günlük API kotası ${value} yapılsın mı?`;

    if (!confirm(confirmMsg)) return;

    try {
        const res = await fetch('/api/admin/manage-user', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ targetEmail, action, value })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message, 'success');
            loadAdminDashboardData();
        } else {
            showToast('Hata: ' + (data.error || 'İşlem başarısız.'), 'error');
        }
    } catch(e) {
        showToast('Sunucu hatası.', 'error');
    }
}
