/**
 * EKOS Antivirus Web Platform Client Application
 * Dedicated Login Modal (Email + 20s Auto-Refreshing QR),
 * Dedicated Register Modal,
 * Account Settings & Developer REST API Key Management.
 */

// Global State
let currentUser = null;
let currentToken = null;
let currentApiKey = null;

// Code Snippet State
let currentSnippetLang = 'curl';

// --- Anti-Inspect, Anti-Extension & DevTools / Context Menu Security Lock ---
document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    return false;
});

document.addEventListener('keydown', (e) => {
    // F12 key
    if (e.key === 'F12' || e.keyCode === 123) {
        e.preventDefault();
        return false;
    }
    // Ctrl+Shift+I / J / C (DevTools)
    if (e.ctrlKey && e.shiftKey && (['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key) || [73, 74, 67].includes(e.keyCode))) {
        e.preventDefault();
        return false;
    }
    // Ctrl+U (View Source)
    if (e.ctrlKey && (e.key === 'U' || e.key === 'u' || e.keyCode === 85)) {
        e.preventDefault();
        return false;
    }
    // Ctrl+S (Save Page)
    if (e.ctrlKey && (e.key === 'S' || e.key === 's' || e.keyCode === 83)) {
        e.preventDefault();
        return false;
    }
});

// --- BROWSER EXTENSION INJECTION & DOM INTEGRITY SHIELD ---
(function initAntiExtensionShield() {
    try {
        const blockedPatterns = [
            'chrome-extension:', 'moz-extension:', 'safari-extension:', 'ms-browser-extension:',
            'data-extension-id', '__grammarly', 'lpform', 'bitwarden', 'lastpass', 'dashlane'
        ];

        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    if (node.nodeType === 1) {
                        const tag = node.tagName.toLowerCase();
                        const id = (node.id || '').toLowerCase();
                        const src = (node.src || '').toLowerCase();
                        const href = (node.href || '').toLowerCase();
                        const cls = (typeof node.className === 'string' ? node.className : '').toLowerCase();

                        const isExtensionOrigin = blockedPatterns.some(p => src.includes(p) || href.includes(p) || id.includes(p) || cls.includes(p));
                        const isUntrustedScript = tag === 'script' && !src.includes('ekoscst.com') && !src.includes('googleapis') && src.includes('://');

                        if (isExtensionOrigin || isUntrustedScript) {
                            try { node.remove(); } catch(e) {}
                        }
                    }
                }
            }
        });

        observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch(e) {}
})();

// Helper: XSS-safe HTML Escaper
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// --- NO-PROMPT IN-PAGE TOAST NOTIFICATION SYSTEM ---
function showToast(message, type = 'info') {
    if (!message) return;
    const container = document.getElementById('toastContainer') || document.body;
    const toast = document.createElement('div');
    toast.className = `ekos-toast toast-${type}`;
    
    let icon = '•';
    if (type === 'success') icon = '✓';
    else if (type === 'error') icon = '✕';

    toast.innerHTML = `<span style="font-size: 14px; font-weight: 800;">${icon}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(12px)';
        setTimeout(() => {
            try { toast.remove(); } catch(e) {}
        }, 250);
    }, 3200);
}

// Override all browser prompt/alert dialogs completely
window.alert = function(msg) {
    showToast(msg, 'info');
};
window.confirm = function() {
    return true;
};
window.prompt = function() {
    return '';
};

// DOM Ready Init
document.addEventListener('DOMContentLoaded', () => {
    initAuthSession();
    updateConsoleTemplate();

    // Close modals on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
});

// =========================================================================
// AUTHENTICATION & SESSION MANAGEMENT
// =========================================================================

function initAuthSession() {
    const savedToken = localStorage.getItem('EKOS_AUTH_TOKEN');
    const savedUserJson = localStorage.getItem('EKOS_AUTH_USER');

    if (savedToken && savedUserJson) {
        try {
            currentToken = savedToken;
            currentUser = JSON.parse(savedUserJson);
            currentApiKey = currentUser.apiKey || localStorage.getItem('EKOS_API_KEY');
            updateHeaderProfileUI();
            fetchLatestUserStatus();
        } catch(e) {
            clearSession();
        }
    } else {
        updateHeaderProfileUI();
    }
}

async function fetchLatestUserStatus() {
    if (!currentToken) return;
    try {
        const res = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await res.json();
        if (data.success && data.user) {
            currentUser = data.user;
            if (data.user.apiKey) currentApiKey = data.user.apiKey;
            localStorage.setItem('EKOS_AUTH_USER', JSON.stringify(currentUser));
            if (currentApiKey) localStorage.setItem('EKOS_API_KEY', currentApiKey);
            updateHeaderProfileUI();
        }
    } catch(e) {}
}

let adminLivePollInterval = null;

function updateHeaderProfileUI() {
    const navLoggedOutGroup = document.getElementById('navLoggedOutGroup');
    const navProfileBtn = document.getElementById('navProfileBtn');
    const navAdminBtn = document.getElementById('navAdminBtn');
    const navUsernameText = document.getElementById('navUsernameText');
    const navTierBadge = document.getElementById('navTierBadge');

    const isUserAdmin = currentUser && (
        currentUser.email === 'admin@ekoscst.com' ||
        currentUser.email === 'admin@ekos.com' ||
        (currentUser.licenseTier && (currentUser.licenseTier.includes('Yönetici') || currentUser.licenseTier.includes('Admin')))
    );

    if (currentUser && currentToken) {
        if (navLoggedOutGroup) navLoggedOutGroup.classList.add('hidden');
        if (navAdminBtn) {
            if (isUserAdmin) navAdminBtn.classList.remove('hidden');
            else navAdminBtn.classList.add('hidden');
        }
        if (navProfileBtn) {
            navProfileBtn.classList.remove('hidden');
            let displayName = currentUser.username || currentUser.email.split('@')[0];
            if (displayName.toLowerCase().includes('yönetici') || displayName.toLowerCase().includes('admin')) {
                displayName = 'Ekos';
            }
            if (navUsernameText) navUsernameText.innerText = displayName;
            if (navTierBadge) {
                const tier = currentUser.licenseTier || 'Standart';
                if (isUserAdmin) {
                    navTierBadge.innerText = 'Yönetici';
                } else if (tier.includes('Premium')) {
                    navTierBadge.innerText = 'Premium';
                } else {
                    navTierBadge.innerText = 'Standart';
                }
            }
        }
    } else {
        if (navLoggedOutGroup) navLoggedOutGroup.classList.remove('hidden');
        if (navProfileBtn) navProfileBtn.classList.add('hidden');
        if (navAdminBtn) navAdminBtn.classList.add('hidden');
    }
}

function openAdminPanelDirectly() {
    window.open('/admin', '_blank');
}

function handleApiCtaClick() {
    if (currentUser && currentToken) {
        openAccountSettingsModal();
    } else {
        openLoginModal('email');
    }
}

function clearSession() {
    currentUser = null;
    currentToken = null;
    currentApiKey = null;
    localStorage.removeItem('EKOS_AUTH_TOKEN');
    localStorage.removeItem('EKOS_AUTH_USER');
    localStorage.removeItem('EKOS_API_KEY');
    updateHeaderProfileUI();
}

function handleLogout() {
    clearSession();
    closeAccountModal();
    showToast('Oturumunuz başarıyla kapatıldı.', 'info');
}

// =========================================================================
// MODAL CONTROLLERS
// =========================================================================

function closeAllModals() {
    closeLoginModal();
    closeRegisterModal();
    closeAccountModal();
}

function handleBackdropClick(event, modalId) {
    if (event.target && event.target.id === modalId) {
        closeAllModals();
    }
}

// --- 1. LOGIN MODAL (Email & Password) ---
function openLoginModal() {
    closeRegisterModal();
    closeAccountModal();

    const modal = document.getElementById('loginModal');
    if (!modal) return;
    modal.classList.remove('hidden');
    hideLoginAlert();
    showLoginView();
}

function closeLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.classList.add('hidden');
}

function showLoginView() {
    hideLoginAlert();
    const viewEmail = document.getElementById('loginViewEmail');
    const viewForgot = document.getElementById('loginViewForgot');
    const modalLoginTitle = document.getElementById('modalLoginTitle');

    if (modalLoginTitle) modalLoginTitle.innerText = 'EKOS Hesabına Giriş Yap';
    if (viewEmail) viewEmail.classList.remove('hidden');
    if (viewForgot) viewForgot.classList.add('hidden');
}

function showForgotView() {
    hideLoginAlert();
    const viewEmail = document.getElementById('loginViewEmail');
    const viewForgot = document.getElementById('loginViewForgot');
    const modalLoginTitle = document.getElementById('modalLoginTitle');

    if (modalLoginTitle) modalLoginTitle.innerText = 'Şifremi Unuttum & Sıfırlama';
    if (viewEmail) viewEmail.classList.add('hidden');
    if (viewForgot) viewForgot.classList.remove('hidden');
}

function showLoginAlert(msg, type = 'error') {
    const box = document.getElementById('loginAlertBox');
    if (!box) return;
    box.className = `modal-alert-box alert-${type}`;
    box.innerText = msg;
    box.classList.remove('hidden');
}

function hideLoginAlert() {
    const box = document.getElementById('loginAlertBox');
    if (box) box.classList.add('hidden');
}

function switchToRegisterModal() {
    closeLoginModal();
    openRegisterModal();
}

// Global QR Register Polling State
let regPairPollInterval = null;
let regTimerInterval = null;
let regCurrentPairToken = null;

// --- 2. REGISTER MODAL (Zorunlu Mobil QR Eşleme) ---
function openRegisterModal() {
    closeLoginModal();
    closeAccountModal();

    const modal = document.getElementById('registerModal');
    if (!modal) return;
    modal.classList.remove('hidden');
    hideRegisterAlert();
    backToRegForm();
}

function closeRegisterModal() {
    stopRegPairPolling();
    const modal = document.getElementById('registerModal');
    if (modal) modal.classList.add('hidden');
}

function showRegisterAlert(msg, type = 'error') {
    const box = document.getElementById('registerAlertBox');
    if (!box) return;
    box.className = `modal-alert-box alert-${type}`;
    box.innerText = msg;
    box.classList.remove('hidden');
}

function hideRegisterAlert() {
    const box = document.getElementById('registerAlertBox');
    if (box) box.classList.add('hidden');
}

function backToRegForm() {
    stopRegPairPolling();
    hideRegisterAlert();
    const vForm = document.getElementById('regViewForm');
    const vQR = document.getElementById('regViewQR');
    const vSuccess = document.getElementById('regViewSuccess');
    const modalTitle = document.getElementById('regModalTitle');

    if (modalTitle) modalTitle.innerText = 'Yeni EKOS Hesabı Oluştur';
    if (vForm) vForm.classList.remove('hidden');
    if (vQR) vQR.classList.add('hidden');
    if (vSuccess) vSuccess.classList.add('hidden');
}

function stopRegPairPolling() {
    if (regPairPollInterval) {
        clearInterval(regPairPollInterval);
        regPairPollInterval = null;
    }
    if (regTimerInterval) {
        clearInterval(regTimerInterval);
        regTimerInterval = null;
    }
    regCurrentPairToken = null;
}

function finishRegistration() {
    closeRegisterModal();
    openAccountSettingsModal();
    showToast('Hesabınız aktif! EKOS platformuna hoş geldiniz.', 'success');
}

function switchToLoginModal() {
    closeRegisterModal();
    openLoginModal();
}

// =========================================================================
// FORM SUBMISSIONS (Login, Register with QR Pairing, Forgot Password)
// =========================================================================

async function handleLoginSubmit(event) {
    event.preventDefault();
    hideLoginAlert();

    const email = document.getElementById('txtLoginEmail').value.trim();
    const password = document.getElementById('txtLoginPassword').value;
    const btnSubmit = document.getElementById('btnLoginSubmit');

    if (!email || !password) {
        showLoginAlert('Lütfen e-posta ve şifrenizi giriniz.');
        return;
    }

    btnSubmit.disabled = true;
    btnSubmit.innerText = 'Giriş yapılıyor...';

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, hwSerial: 'WEB-CLIENT' })
        });
        const data = await res.json();

        if (data.success && data.token) {
            currentToken = data.token;
            currentUser = data.user;
            currentApiKey = data.apiKey || (data.user && data.user.apiKey);

            localStorage.setItem('EKOS_AUTH_TOKEN', currentToken);
            localStorage.setItem('EKOS_AUTH_USER', JSON.stringify(currentUser));
            if (currentApiKey) localStorage.setItem('EKOS_API_KEY', currentApiKey);

            showLoginAlert('Giriş başarılı!', 'success');
            updateHeaderProfileUI();

            setTimeout(() => {
                closeLoginModal();
                openAccountSettingsModal();
            }, 500);
        } else {
            showLoginAlert(data.error || 'E-posta adresi veya şifre hatalı.');
        }
    } catch(err) {
        showLoginAlert('Sunucuya bağlanılamadı. Lütfen internet bağlantınızı kontrol ediniz.');
    } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerText = 'Giriş Yap';
    }
}

async function handleRegisterSubmit(event) {
    event.preventDefault();
    hideRegisterAlert();

    const email = document.getElementById('txtRegEmail').value.trim();
    const username = document.getElementById('txtRegUsername').value.trim();
    const password = document.getElementById('txtRegPassword').value;
    const securityQuestion = (document.getElementById('selRegSecurityQuestion') ? document.getElementById('selRegSecurityQuestion').value : 'İlk evcil hayvanınızın adı nedir?');
    const securityAnswer = (document.getElementById('txtRegSecurityAnswer') ? document.getElementById('txtRegSecurityAnswer').value.trim() : 'ekos');
    const btnSubmit = document.getElementById('btnRegSubmit');

    if (!email || !password || !username) {
        showRegisterAlert('Lütfen tüm alanları doldurunuz.');
        return;
    }

    if (password.length < 4) {
        showRegisterAlert('Şifreniz en az 4 karakter olmalıdır.');
        return;
    }

    btnSubmit.disabled = true;
    btnSubmit.innerText = 'QR Kod Hazırlanıyor...';

    try {
        const res = await fetch('/api/auth/register-init', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                username,
                password,
                securityQuestion,
                securityAnswer,
                hwSerial: 'WEB-CLIENT'
            })
        });
        const data = await res.json();

        if (data.success && data.pairToken && data.pairQrUrl) {
            regCurrentPairToken = data.pairToken;

            // Switch to QR View
            const vForm = document.getElementById('regViewForm');
            const vQR = document.getElementById('regViewQR');
            const modalTitle = document.getElementById('regModalTitle');
            const qrImg = document.getElementById('regQrCodeImg');
            const timerEl = document.getElementById('regTimerText');
            const statusEl = document.getElementById('regPairStatusText');

            if (modalTitle) modalTitle.innerText = 'Güvenlik: Telefon Eşleme Adımı';
            if (vForm) vForm.classList.add('hidden');
            if (vQR) vQR.classList.remove('hidden');

            if (qrImg) {
                qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(data.pairQrUrl)}`;
            }

            if (statusEl) statusEl.innerText = 'Telefonunuzdan onay bekleniyor...';

            // Start 10-minute countdown
            let remainingSec = 600;
            if (regTimerInterval) clearInterval(regTimerInterval);
            regTimerInterval = setInterval(() => {
                remainingSec--;
                if (remainingSec <= 0) {
                    clearInterval(regTimerInterval);
                    stopRegPairPolling();
                    showRegisterAlert('QR kod süresi doldu. Lütfen tekrar deneyiniz.');
                    backToRegForm();
                    return;
                }
                const m = Math.floor(remainingSec / 60).toString().padStart(2, '0');
                const s = (remainingSec % 60).toString().padStart(2, '0');
                if (timerEl) timerEl.innerText = `Kalan Süre: ${m}:${s}`;
            }, 1000);

            // Start Polling check-pair
            if (regPairPollInterval) clearInterval(regPairPollInterval);
            regPairPollInterval = setInterval(async () => {
                if (!regCurrentPairToken) return;
                try {
                    const checkRes = await fetch('/api/auth/register-check-pair', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pairToken: regCurrentPairToken })
                    });
                    const checkData = await checkRes.json();

                    if (checkData.success && checkData.status === 'paired' && checkData.token) {
                        // Successfully Paired and Registered!
                        stopRegPairPolling();

                        currentToken = checkData.token;
                        currentUser = checkData.user;
                        currentApiKey = checkData.apiKey;

                        localStorage.setItem('EKOS_AUTH_TOKEN', currentToken);
                        localStorage.setItem('EKOS_AUTH_USER', JSON.stringify(currentUser));
                        if (currentApiKey) localStorage.setItem('EKOS_API_KEY', currentApiKey);

                        updateHeaderProfileUI();

                        const vQR = document.getElementById('regViewQR');
                        const vSuccess = document.getElementById('regViewSuccess');
                        const recCodeEl = document.getElementById('regRecoveryCode');

                        if (vQR) vQR.classList.add('hidden');
                        if (vSuccess) vSuccess.classList.remove('hidden');
                        if (recCodeEl && checkData.recoveryCode) {
                            recCodeEl.innerText = checkData.recoveryCode;
                        }
                    }
                } catch(e) {}
            }, 2000);

        } else {
            showRegisterAlert(data.error || 'Kayıt başlatılamadı. Lütfen bilgilerinizi kontrol ediniz.');
        }
    } catch(err) {
        showRegisterAlert('Sunucuya bağlanılamadı. Lütfen internet bağlantınızı kontrol ediniz.');
    } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerText = '📱 QR Kod ile Mobil Eşle & Kayıt Ol';
    }
}

async function handleForgotSubmit(event) {
    event.preventDefault();
    hideLoginAlert();

    const email = document.getElementById('txtForgotEmail').value.trim();
    const newPassword = document.getElementById('txtForgotNewPassword').value;
    const btnSubmit = document.getElementById('btnForgotSubmit');

    if (!email || !newPassword) {
        showLoginAlert('Lütfen e-posta adresinizi ve yeni şifrenizi giriniz.');
        return;
    }

    btnSubmit.disabled = true;
    btnSubmit.innerText = 'Şifre güncelleniyor...';

    try {
        const res = await fetch('/api/auth/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, newPassword })
        });
        const data = await res.json();

        if (data.success) {
            showLoginAlert(data.message || 'Şifreniz güncellendi. Giriş yapabilirsiniz.', 'success');
            setTimeout(() => {
                switchLoginTab('email');
                const loginEmailInput = document.getElementById('txtLoginEmail');
                if (loginEmailInput) loginEmailInput.value = email;
            }, 1400);
        } else {
            showLoginAlert(data.error || 'Şifre sıfırlanamadı.');
        }
    } catch(err) {
        showLoginAlert('Sunucuya bağlanılamadı.');
    } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerText = 'Şifremi Sıfırla ve Güncelle';
    }
}

// =========================================================================
// ACCOUNT SETTINGS MODAL & API KEY MANAGEMENT
// =========================================================================

async function openAccountSettingsModal() {
    if (!currentUser || !currentToken) {
        openLoginModal('email');
        return;
    }

    closeLoginModal();
    closeRegisterModal();

    const modal = document.getElementById('accountModal');
    if (!modal) return;

    // Populate user info
    const accProfileUsername = document.getElementById('accProfileUsername');
    const accProfileEmail = document.getElementById('accProfileEmail');
    const accProfileTierBadge = document.getElementById('accProfileTierBadge');
    const accProfileExpiryBadge = document.getElementById('accProfileExpiryBadge');
    const accSubTierText = document.getElementById('accSubTierText');
    const accSubExpiryText = document.getElementById('accSubExpiryText');

    let displayName = currentUser.username || currentUser.email.split('@')[0];
    if (displayName.toLowerCase().includes('yönetici') || displayName.toLowerCase().includes('admin')) {
        displayName = 'Ekos';
    }
    if (accProfileUsername) accProfileUsername.innerText = displayName;
    if (accProfileEmail) accProfileEmail.innerText = currentUser.email;

    const tier = currentUser.licenseTier || 'EKOS Geliştirici';
    const displayTier = (tier.includes('Yönetici') || tier.includes('Admin')) ? 'EKOS Premium' : tier;
    const expiry = currentUser.licenseExpiry || 'Süresiz (Ömür Boyu)';

    if (accProfileTierBadge) accProfileTierBadge.innerText = displayTier;
    if (accProfileExpiryBadge) accProfileExpiryBadge.innerText = expiry;
    if (accSubTierText) accSubTierText.innerText = displayTier;
    if (accSubExpiryText) accSubExpiryText.innerText = expiry;

    // Fetch user's persistent API Key & usage statistics
    try {
        const res = await fetch('/api/developer/my-key', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email: currentUser.email })
        });
        const data = await res.json();

        if (data && data.success && data.keyInfo) {
            currentApiKey = data.keyInfo.apiKey;
            localStorage.setItem('EKOS_API_KEY', currentApiKey);

            const accApiKeyDisplay = document.getElementById('accApiKeyDisplay');
            const accTotalReqCount = document.getElementById('accTotalReqCount');
            const accRemainingQuotaCount = document.getElementById('accRemainingQuotaCount');

            if (accApiKeyDisplay) accApiKeyDisplay.value = currentApiKey;
            if (accTotalReqCount) accTotalReqCount.innerText = (data.keyInfo.totalRequests || 0).toLocaleString('tr-TR');
            if (accRemainingQuotaCount) {
                const limit = data.keyInfo.dailyLimit || 10000;
                const used = data.keyInfo.totalRequests || 0;
                accRemainingQuotaCount.innerText = Math.max(0, limit - used).toLocaleString('tr-TR');
            }
        }
    } catch(e) {}

    const modalCard = modal.querySelector('.modal-card');
    if (modalCard) modalCard.style.maxWidth = '520px';

    modal.classList.remove('hidden');
}

function toggleAccountApiKeyVisibility() {
    const input = document.getElementById('accApiKeyDisplay');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function copyAccountApiKeyToClipboard() {
    const input = document.getElementById('accApiKeyDisplay');
    if (!input || !input.value) return;

    navigator.clipboard.writeText(input.value).then(() => {
        showToast('API Anahtarınız panoya kopyalandı.', 'success');
    }).catch(() => {
        input.type = 'text';
        input.select();
        document.execCommand('copy');
        showToast('API Anahtarınız kopyalandı.', 'success');
    });
}

// =========================================================================
// ADMIN SUPERUSER PANEL CONTROLLERS (Visitors, Users, License Codes)
// =========================================================================

function switchAdminTab(tabName) {
    const btns = document.querySelectorAll('.admin-tab-btn');
    btns.forEach(b => {
        const txt = b.innerText.toLowerCase();
        b.classList.toggle('active', (tabName === 'visitors' && txt.includes('ziyaretçi')) ||
                                     (tabName === 'users' && txt.includes('kullanıcı')) ||
                                     (tabName === 'codes' && txt.includes('kod')));
    });

    const vVisitors = document.getElementById('admViewVisitors');
    const vUsers = document.getElementById('admViewUsers');
    const vCodes = document.getElementById('admViewCodes');

    if (vVisitors) vVisitors.classList.toggle('hidden', tabName !== 'visitors');
    if (vUsers) vUsers.classList.toggle('hidden', tabName !== 'users');
    if (vCodes) vCodes.classList.toggle('hidden', tabName !== 'codes');

    if (tabName === 'visitors') {
        loadAdminVisitorLogsOnly();
    }
}

async function loadAdminOverviewData() {
    if (!currentToken) return;
    try {
        const res = await fetch('/api/admin/overview', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await res.json();

        if (data.success && data.stats) {
            const admOnlineNow = document.getElementById('admOnlineNow');
            const admTotalUsers = document.getElementById('admTotalUsers');
            const admPremiumUsers = document.getElementById('admPremiumUsers');
            const admFreeUsers = document.getElementById('admFreeUsers');
            const admTotalApiReqs = document.getElementById('admTotalApiReqs');
            const admTotalVisitors = document.getElementById('admTotalVisitors');
            const admUniqueIps = document.getElementById('admUniqueIps');

            if (admOnlineNow) admOnlineNow.innerText = `${data.stats.onlineNow || 1} Aktif`;
            if (admTotalVisitors) admTotalVisitors.innerText = (data.stats.totalVisits || 0).toLocaleString();
            if (admUniqueIps) admUniqueIps.innerText = (data.stats.uniqueIps || 0).toLocaleString();
            if (admTotalUsers) admTotalUsers.innerText = (data.stats.totalUsers || 0).toLocaleString();
            if (admTotalApiReqs) admTotalApiReqs.innerText = (data.stats.totalApiRequests || 0).toLocaleString();

            // Populate Visitor Logs Table
            renderVisitorLogsTable(data.visitorLogs || []);

            // Populate Generated Codes Table
            const codesTbody = document.getElementById('admCodesTableBody');
            if (codesTbody && data.premiumCodes) {
                if (data.premiumCodes.length === 0) {
                    codesTbody.innerHTML = '<tr><td colspan="5" class="text-dim" style="text-align:center; padding:12px;">Henüz lisans kodu üretilmemiş.</td></tr>';
                } else {
                    codesTbody.innerHTML = data.premiumCodes.map(c => `
                        <tr>
                            <td class="font-mono text-cyan font-bold">${escapeHtml(c.code)}</td>
                            <td>${c.durationDays === 9999 ? 'Ömür Boyu' : escapeHtml(c.durationDays) + ' Gün'}</td>
                            <td><span class="${c.status === 'USED' ? 'badge-used' : 'badge-unused'}">${c.status === 'USED' ? 'Kullanıldı' : 'Aktif'}</span></td>
                            <td>${escapeHtml(c.usedBy || '-')}</td>
                            <td>
                                <button type="button" class="btn-sm-action" onclick="navigator.clipboard.writeText('${escapeHtml(c.code)}'); showToast('Kod panoya kopyalandı.', 'success');">Kopyala</button>
                                <button type="button" class="btn-sm-action btn-sm-danger" onclick="handleAdminRevokeLicenseKey('${escapeHtml(c.code)}')">Sil</button>
                            </td>
                        </tr>
                    `).join('');
                }
            }

            // Populate Users Table
            const usersTbody = document.getElementById('admUsersTableBody');
            if (usersTbody && data.users) {
                if (data.users.length === 0) {
                    usersTbody.innerHTML = '<tr><td colspan="8" class="text-dim" style="text-align:center; padding:16px;">Henüz kayıtlı kullanıcı bulunmuyor.</td></tr>';
                } else {
                    usersTbody.innerHTML = data.users.map(u => {
                        const tier = u.licenseTier || 'Standart';
                        const pillCls = (tier.includes('Premium') || tier.includes('Kurumsal') || tier.includes('Yönetici')) ? 'tier-pill-gold' : 'tier-pill-cyan';
                        const statusBadge = u.isOnline 
                            ? `<span class="badge-online"><span class="online-pulse-dot"></span> Çevrimiçi</span>`
                            : `<span class="badge-offline">Çevrimdışı</span>`;
                        return `
                            <tr>
                                <td>${statusBadge}</td>
                                <td><strong style="color: #f8fafc;">${escapeHtml(u.email)}</strong></td>
                                <td><span class="visitor-ip-badge">${escapeHtml(u.lastIp || '-')}</span></td>
                                <td>${escapeHtml(u.username)}</td>
                                <td><span class="${pillCls}">${escapeHtml(tier)}</span></td>
                                <td><span style="font-size:11px; color:#94a3b8; font-weight:600;">${escapeHtml(u.lastSeenText || 'Kayıtlı')}</span></td>
                                <td class="font-mono text-amber">${(u.totalRequests || 0).toLocaleString()}</td>
                                <td>
                                    <button type="button" class="btn-sm-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'update_tier', 'EKOS Kurumsal Premium')" title="Premium Yap">Premium</button>
                                    <button type="button" class="btn-sm-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'set_api_limit', 100000)" title="100k Limit Ver">100k Kota</button>
                                    <button type="button" class="btn-sm-action" onclick="handleAdminManageUser('${escapeHtml(u.email)}', 'reset_password', 'ekos1234')" title="Şifre Sıfırla">Şifre Sıfırla</button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }
            }
        }
    } catch(e) {
        console.error('Admin overview fetch error:', e);
    }
}

function renderVisitorLogsTable(logs) {
    const tbody = document.getElementById('admVisitorLogsTableBody');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-dim" style="text-align:center; padding:16px;">Henüz ziyaretçi kaydı bulunmuyor.</td></tr>';
        return;
    }

    const now = Date.now();
    tbody.innerHTML = logs.map(l => {
        const timePart = l.timeFormatted ? l.timeFormatted.split(' ')[1] || l.timeFormatted : '-';
        const methodCls = l.method === 'GET' ? 'method-get' : (l.method === 'POST' ? 'method-post' : 'method-other');
        const statusCls = (l.statusCode >= 200 && l.statusCode < 300) ? 'status-200' : ((l.statusCode === 403) ? 'status-403' : 'status-400');
        
        const logTime = l.timestamp ? new Date(l.timestamp).getTime() : 0;
        const isRecent = (now - logTime) < 3 * 60 * 1000;
        const liveIndicator = isRecent ? '<span class="online-pulse-dot" style="margin-right: 5px;" title="Canlı Ziyaretçi"></span>' : '';

        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 11px; color: #94a3b8; white-space: nowrap;">${liveIndicator}${escapeHtml(timePart)}</td>
                <td style="white-space: nowrap;">
                    <span class="country-flag-badge">${escapeHtml(l.country || 'TR')}</span>
                    <span class="visitor-ip-badge">${escapeHtml(l.ip)}</span>
                    <span style="font-size: 10px; color: #64748b; margin-left: 3px;">${escapeHtml(l.city && l.city !== '-' ? l.city : '')}</span>
                </td>
                <td style="white-space: nowrap;">
                    <span class="visitor-method-badge ${methodCls}">${escapeHtml(l.method)}</span>
                    <span class="visitor-path">${escapeHtml(l.path)}</span>
                </td>
                <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; color: #cbd5e1;" title="${escapeHtml(l.userAgent || '')}">
                    ${escapeHtml(l.deviceSummary || l.userAgent || 'Web Tarayıcı')}
                </td>
                <td style="white-space: nowrap;">
                    <span class="visitor-status-badge ${statusCls}">${escapeHtml(l.statusCode || 200)} • ${l.durationMs || 0}ms</span>
                </td>
            </tr>
        `;
    }).join('');
}

async function loadAdminVisitorLogsOnly() {
    if (!currentToken) return;
    const tbody = document.getElementById('admVisitorLogsTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-dim" style="text-align:center; padding:12px;">Canlı trafik çekiliyor...</td></tr>';

    try {
        const res = await fetch('/api/admin/visitor-logs', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await res.json();
        if (data.success) {
            const admTotalVisitors = document.getElementById('admTotalVisitors');
            const admUniqueIps = document.getElementById('admUniqueIps');
            if (admTotalVisitors) admTotalVisitors.innerText = (data.total || 0).toLocaleString();
            if (admUniqueIps) admUniqueIps.innerText = (data.uniqueIps || 0).toLocaleString();

            renderVisitorLogsTable(data.logs || []);
            showToast('Ziyaretçi trafiği güncellendi.', 'info');
        }
    } catch(e) {
        showToast('Ziyaretçi logları alınamadı.', 'error');
    }
}

async function handleAdminClearVisitorLogs() {
    if (!confirm('Tüm canlı ziyaretçi erişim günlüklerini temizlemek istediğinize emin misiniz?')) return;

    try {
        const res = await fetch('/api/admin/clear-visitor-logs', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message, 'success');
            loadAdminVisitorLogsOnly();
        }
    } catch(e) {
        showToast('İşlem başarısız.', 'error');
    }
}

async function handleAdminGenerateLicenseKey() {
    const selDays = document.getElementById('selAdminLicenseDays');
    const txtNote = document.getElementById('txtAdminLicenseNote');

    const durationDays = selDays ? parseInt(selDays.value, 10) : 365;
    const note = txtNote ? txtNote.value.trim() : '';

    try {
        const res = await fetch('/api/admin/generate-license-key', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ durationDays, note })
        });
        const data = await res.json();

        if (data.success && data.licenseCode) {
            if (txtNote) txtNote.value = '';
            alert('Yeni Lisans Kodu Başarıyla Üretildi:\n' + data.licenseCode.code);
            loadAdminOverviewData();
        } else {
            alert('Hata: ' + (data.error || 'Lisans kodu üretilemedi.'));
        }
    } catch(e) {
        alert('Sunucu bağlantı hatası.');
    }
}

async function handleAdminRevokeLicenseKey(code) {
    if (!confirm(`Bu lisans kodunu (${code}) iptal etmek/silmek istediğinize emin misiniz?`)) return;

    try {
        const res = await fetch('/api/admin/revoke-license-key', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.success) {
            loadAdminOverviewData();
        } else {
            alert('Hata: ' + (data.error || 'İşlem başarısız.'));
        }
    } catch(e) {
        alert('Sunucu hatası.');
    }
}

async function handleAdminManageUser(targetEmail, action, value) {
    let confirmMsg = `Kullanıcı (${targetEmail}) için işlem yapılsın mı?`;
    if (action === 'update_tier') confirmMsg = `${targetEmail} hesabının lisansı "${value}" olarak yükseltilsin mi?`;
    if (action === 'reset_password') confirmMsg = `${targetEmail} hesabının şifresi "${value}" olarak sıfırlansın mı?`;
    if (action === 'set_api_limit') confirmMsg = `${targetEmail} hesabının günlük API kotası ${value} olarak güncellensin mi?`;

    if (!confirm(confirmMsg)) return;

    try {
        const res = await fetch('/api/admin/manage-user', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ targetEmail, action, value })
        });
        const data = await res.json();
        if (data.success) {
            alert(data.message);
            loadAdminOverviewData();
        } else {
            alert('Hata: ' + (data.error || 'İşlem başarısız.'));
        }
    } catch(e) {
        alert('Sunucu hatası.');
    }
}

async function loadAdminVisitorLogsSilently() {
    if (!currentToken) return;
    try {
        const res = await fetch('/api/admin/visitor-logs', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await res.json();
        if (data.success) {
            const admTotalVisitors = document.getElementById('admTotalVisitors');
            const admUniqueIps = document.getElementById('admUniqueIps');
            if (admTotalVisitors) admTotalVisitors.innerText = (data.total || 0).toLocaleString();
            if (admUniqueIps) admUniqueIps.innerText = (data.uniqueIps || 0).toLocaleString();

            renderVisitorLogsTable(data.logs || []);
        }
    } catch(e) {}
}

function closeAccountModal() {
    if (adminLivePollInterval) {
        clearInterval(adminLivePollInterval);
        adminLivePollInterval = null;
    }
    const modal = document.getElementById('accountModal');
    if (modal) modal.classList.add('hidden');
}



// =========================================================================
// CODE SNIPPET CONSOLE LOGIC
// =========================================================================

function switchSnippetLang(lang) {
    currentSnippetLang = lang;
    const btns = document.querySelectorAll('.code-tab-btns .tab-btn');
    btns.forEach(b => {
        b.classList.toggle('active', b.innerText.toLowerCase().includes(lang) || (lang === 'csharp' && b.innerText.includes('C#')));
    });
    updateConsoleTemplate();
}

function updateConsoleTemplate() {
    const sel = document.getElementById('apiEndpointSelect');
    const endpoint = sel ? sel.value : '/api/v1/scan/url';
    const pre = document.getElementById('liveCodeSnippet');
    if (!pre) return;

    const baseUrl = 'https://api.ekoscst.com';
    let code = '';

    if (currentSnippetLang === 'curl') {
        if (endpoint === '/api/v1/scan/url') {
            code = `curl -X POST ${baseUrl}/api/v1/scan/url \\\n  -H "Content-Type: application/json" \\\n  -d '{"url": "https://suspicious-domain.com/login"}'`;
        } else if (endpoint === '/api/v1/scan/hash') {
            code = `curl -X POST ${baseUrl}/api/v1/scan/hash \\\n  -H "Content-Type: application/json" \\\n  -d '{"hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"}'`;
        } else if (endpoint === '/api/v1/analyze/payload') {
            code = `curl -X POST ${baseUrl}/api/v1/analyze/payload \\\n  -H "Content-Type: application/json" \\\n  -d '{"payload": "powershell -enc JABjID0A..."}'`;
        } else if (endpoint === '/api/v1/scan/file') {
            code = `curl -X POST ${baseUrl}/api/v1/scan/file \\\n  -H "Content-Type: application/json" \\\n  -d '{"filename": "update.exe", "base64Content": "TVqQAAMAAAA..."}'`;
        } else if (endpoint === '/api/v1/threat-intelligence/feed') {
            code = `curl -X GET ${baseUrl}/api/v1/threat-intelligence/feed`;
        } else {
            code = `curl -X GET ${baseUrl}/api/v1/status`;
        }
    } else if (currentSnippetLang === 'python') {
        code = `import requests\n\nurl = "${baseUrl}${endpoint}"\nheaders = {\n    "Content-Type": "application/json"\n}\npayload = {"url": "https://suspicious-domain.com"}\n\nresponse = requests.post(url, json=payload, headers=headers)\nprint(response.json())`;
    } else if (currentSnippetLang === 'node') {
        code = `const fetch = require('node-fetch');\n\nasync function queryEkos() {\n  const res = await fetch('${baseUrl}${endpoint}', {\n    method: 'POST',\n    headers: {\n      'Content-Type': 'application/json'\n    },\n    body: JSON.stringify({ url: 'https://suspicious-domain.com' })\n  });\n  const data = await res.json();\n  console.log(data);\n}\nqueryEkos();`;
    } else if (currentSnippetLang === 'csharp') {
        code = `using System;\nusing System.Net.Http;\nusing System.Text;\nusing System.Threading.Tasks;\n\nclass Program {\n    static async Task Main() {\n        var client = new HttpClient();\n        var json = "{\\"url\\": \\"https://suspicious-domain.com\\"}";\n        var content = new StringContent(json, Encoding.UTF8, "application/json");\n        var response = await client.PostAsync("${baseUrl}${endpoint}", content);\n        Console.WriteLine(await response.Content.ReadAsStringAsync());\n    }\n}`;
    }

    pre.innerText = code;
}

// =========================================================================
// ONLINE LIVE THREAT SCANNER CLIENT CONTROLLERS
// =========================================================================
let urlCooldownInterval = null;

function switchScannerTab(tab) {
    const btnUrl = document.getElementById('tabBtnUrlScan');
    const btnFile = document.getElementById('tabBtnFileScan');
    const paneUrl = document.getElementById('paneUrlScan');
    const paneFile = document.getElementById('paneFileScan');

    if (tab === 'url') {
        if (btnUrl) btnUrl.classList.add('active');
        if (btnFile) btnFile.classList.remove('active');
        if (paneUrl) paneUrl.classList.remove('hidden');
        if (paneFile) paneFile.classList.add('hidden');
    } else {
        if (btnFile) btnFile.classList.add('active');
        if (btnUrl) btnUrl.classList.remove('active');
        if (paneFile) paneFile.classList.remove('hidden');
        if (paneUrl) paneUrl.classList.add('hidden');
    }
}

function startUrlCooldownTimer(seconds) {
    let rem = seconds;
    const timerElem = document.getElementById('urlCooldownTimer');
    const btnSubmit = document.getElementById('btnSubmitUrlScan');

    if (urlCooldownInterval) clearInterval(urlCooldownInterval);

    if (timerElem) {
        timerElem.style.display = 'inline-block';
        timerElem.innerText = `⏱️ Sonraki tarama için kalan süre: ${rem}s`;
    }
    if (btnSubmit) btnSubmit.disabled = true;

    urlCooldownInterval = setInterval(() => {
        rem--;
        if (rem <= 0) {
            clearInterval(urlCooldownInterval);
            if (timerElem) timerElem.style.display = 'none';
            if (btnSubmit) btnSubmit.disabled = false;
        } else {
            if (timerElem) timerElem.innerText = `⏱️ Sonraki tarama için kalan süre: ${rem}s`;
        }
    }, 1000);
}

async function handleLiveUrlScan(e) {
    if (e) e.preventDefault();
    const input = document.getElementById('liveScanUrlInput');
    const btn = document.getElementById('btnSubmitUrlScan');
    const resultBox = document.getElementById('urlScanResult');

    const url = input ? input.value.trim() : '';
    if (!url) return;

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span>Taranıyor...</span>';
    }

    try {
        const res = await fetch('/api/v1/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        const data = await res.json();

        if (res.status === 429) {
            showToast(data.error || 'Lütfen bekleyiniz.', 'error');
            startUrlCooldownTimer(data.retryAfter || 30);
            return;
        }

        if (data && data.success) {
            renderUrlScanResult(data);
            showToast('Web sitesi analizi tamamlandı.', 'success');
            startUrlCooldownTimer(30);
        } else {
            showToast((data && data.error) ? data.error : 'Tarama başarısız.', 'error');
        }
    } catch(err) {
        showToast('Sunucuya bağlanılamadı.', 'error');
    } finally {
        if (btn && !urlCooldownInterval) {
            btn.disabled = false;
            btn.innerHTML = '<span>Taramayı Başlat</span>';
        }
    }
}

function renderUrlScanResult(data) {
    const box = document.getElementById('urlScanResult');
    if (!box) return;

    const isSafe = data.isSafe;
    const isMalicious = data.verdict === 'MALICIOUS';
    const isSuspicious = data.verdict === 'SUSPICIOUS';
    const badgeClass = isMalicious ? 'scan-verdict-malicious' : (isSuspicious ? 'scan-verdict-suspicious' : 'scan-verdict-safe');
    const badgeText = isMalicious ? '⚠️ KRİTİK OLTALAMA / ZARARLI' : (isSuspicious ? '⚡ ŞÜPHELİ / YÜKSEK RİSK' : '✓ GÜVENLİ VE DOĞRULANMIŞ');

    let categoriesHtml = '';
    if (data.threatCategories && data.threatCategories.length > 0) {
        categoriesHtml = '<div style="margin-top:14px;"><div style="font-size:11px; color:#94a3b8; font-weight:700; text-transform:uppercase; margin-bottom:6px;">Tespit Edilen Güvenlik Kategorileri:</div><div style="display:flex; gap:6px; flex-wrap:wrap;">' +
            data.threatCategories.map(c => '<span class="badge" style="background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.3); font-size:11px; padding:4px 10px; border-radius:6px;">' + escapeHtml(c) + '</span>').join('') + '</div></div>';
    }

    let warningsHtml = '';
    if (data.warnings && data.warnings.length > 0) {
        warningsHtml = '<div style="margin-top:14px; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px;"><div style="font-size:11px; color:#cbd5e1; font-weight:700; text-transform:uppercase; margin-bottom:6px;">Gelişmiş Güvenlik Bulguları &amp; Uyarılar:</div><ul style="margin:0; padding-left:18px; font-size:12px; line-height:1.7; color:' + (isSafe ? '#6ee7b7' : '#fca5a5') + ';">' +
            data.warnings.map(w => '<li>' + escapeHtml(w) + '</li>').join('') + '</ul></div>';
    }

    let protocolStr = data.isHttps ? 'HTTPS (Şifreli SSL Bağlantısı)' : 'HTTP (Şifrelenmemiş Bağlantı)';
    if (data.redirectCount > 0) {
        protocolStr += ` | ${data.redirectCount} Yönlendirme (${escapeHtml(data.finalHostname || '')})`;
    }

    box.innerHTML = `
        <div class="scan-res-header">
            <div>
                <span class="scan-verdict-badge ${badgeClass}">${badgeText}</span>
                <span style="margin-left: 10px; font-size: 14px; font-weight: 700; color: #fff;">${escapeHtml(data.hostname || data.domain || '')}</span>
                ${data.pageTitle && data.pageTitle !== 'Sayfa Başlığı Yok' ? `<span style="margin-left: 8px; font-size: 12px; color: #94a3b8;">("${escapeHtml(data.pageTitle)}")</span>` : ''}
            </div>
            <div style="font-size: 14px; font-weight: 800; color: ${isMalicious ? '#ef4444' : (isSafe ? '#10b981' : '#f59e0b')}">
                Risk Skoru: %${data.riskScore || 0}
            </div>
        </div>
        <div class="scan-meta-grid">
            <div class="scan-meta-box">
                <div class="scan-meta-k">Etki Alanı (Domain)</div>
                <div class="scan-meta-v">${escapeHtml(data.domain || data.hostname || '-')}</div>
            </div>
            <div class="scan-meta-box">
                <div class="scan-meta-k">Sunucu IP Adresi</div>
                <div class="scan-meta-v" style="font-family:monospace; color:#38bdf8;">${escapeHtml(data.resolvedIp || 'Bilinmiyor')}</div>
            </div>
            <div class="scan-meta-box">
                <div class="scan-meta-k">İletişim Protokolü</div>
                <div class="scan-meta-v">${escapeHtml(protocolStr)}</div>
            </div>
        </div>
        ${categoriesHtml}
        ${warningsHtml}
    `;
    box.classList.remove('hidden');
}

async function handleLiveFileSelect(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    showToast(file.name + ' inceleniyor (SHA-256 hesaplanıyor)...', 'info');

    try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        const res = await fetch('/api/v1/scan/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hashHex, filename: file.name, sizeBytes: file.size })
        });
        const data = await res.json();

        if (data && data.success) {
            renderFileScanResult(data);
            showToast('Dosya analizi tamamlandı.', 'success');
        } else {
            showToast('Dosya analizi başarısız.', 'error');
        }
    } catch(err) {
        showToast('Dosya okunamadı veya analiz edilemedi.', 'error');
    }
}

async function handleLiveHashScan() {
    const input = document.getElementById('liveScanHashInput');
    const hash = input ? input.value.trim() : '';
    if (!hash) return showToast('Lütfen geçerli bir hash giriniz.', 'error');

    showToast('Tehdit veritabanı sorgulanıyor...', 'info');

    try {
        const res = await fetch('/api/v1/scan/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hash })
        });
        const data = await res.json();

        if (data && data.success) {
            renderFileScanResult(data);
            showToast('Hash analizi tamamlandı.', 'success');
        } else {
            showToast((data && data.error) ? data.error : 'Sorgulama başarısız.', 'error');
        }
    } catch(err) {
        showToast('Sunucu hatası.', 'error');
    }
}

function renderFileScanResult(data) {
    const box = document.getElementById('fileScanResult');
    if (!box) return;

    const isThreat = data.isThreat;
    const badgeClass = isThreat ? 'scan-verdict-malicious' : 'scan-verdict-safe';
    const badgeText = isThreat ? '⚠️ ZARARLI DOSYA TESPİT EDİLDİ' : '✓ DOSYA TEMİZ (GÜVENLİ)';

    let warningsHtml = '';
    if (data.warnings && data.warnings.length > 0) {
        warningsHtml = '<div style="margin-top:14px; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px;"><div style="font-size:11px; color:#cbd5e1; font-weight:700; text-transform:uppercase; margin-bottom:6px;">Güvenlik &amp; İmza Analizi:</div><ul style="margin:0; padding-left:18px; font-size:12px; line-height:1.7; color:' + (isThreat ? '#fca5a5' : '#6ee7b7') + ';">' +
            data.warnings.map(w => '<li>' + escapeHtml(w) + '</li>').join('') + '</ul></div>';
    }

    box.innerHTML = `
        <div class="scan-res-header">
            <div>
                <span class="scan-verdict-badge ${badgeClass}">${badgeText}</span>
                <span style="margin-left: 10px; font-size: 13px; color: #fff; font-weight: 700;">${escapeHtml(data.filename || 'Dosya')}</span>
            </div>
            <div style="font-size: 12px; color: #38bdf8; font-weight: 600;">
                1.420.580+ İmza Kontrol Edildi
            </div>
        </div>
        <div class="scan-meta-grid">
            <div class="scan-meta-box" style="grid-column: 1 / -1;">
                <div class="scan-meta-k">SHA-256 İmzası (Hash)</div>
                <div class="scan-meta-v" style="font-family: monospace; font-size: 11px; word-break: break-all; color: #38bdf8;">${escapeHtml(data.hash || '-')}</div>
            </div>
            <div class="scan-meta-box">
                <div class="scan-meta-k">Tehdit İsmi</div>
                <div class="scan-meta-v ${isThreat ? 'text-danger' : 'text-green'}">${escapeHtml(data.threatName || 'Yok')}</div>
            </div>
            <div class="scan-meta-box">
                <div class="scan-meta-k">Tehdit Türü / Sınıfı</div>
                <div class="scan-meta-v">${escapeHtml(data.threatType || 'Temiz')}</div>
            </div>
            <div class="scan-meta-box">
                <div class="scan-meta-k">Risk / Önem Derecesi</div>
                <div class="scan-meta-v" style="color:${isThreat ? '#ef4444' : '#10b981'}; font-weight:700;">${escapeHtml(data.severity || 'LOW')}</div>
            </div>
        </div>
        ${warningsHtml}
    `;
    box.classList.remove('hidden');
}

// Adaptive Multi-Device (Mobile vs Desktop) Initialization
function initDeviceAdaptiveLayout() {
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || window.innerWidth < 768;
    const heroHub = document.getElementById('heroActionsHub');
    const btnWin = document.getElementById('btnHeroWindows');
    const btnAndroid = document.getElementById('btnHeroAndroid');

    if (isMobile && heroHub && btnAndroid && btnWin) {
        // Prioritize Android download button on mobile devices
        heroHub.prepend(btnAndroid);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDeviceAdaptiveLayout);
} else {
    initDeviceAdaptiveLayout();
}

