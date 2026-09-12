// Context-Aware Script - Highlight Event Dinleyicisi

// --- Güvenli Eklenti API Yardımcıları ---
function getExtIconUrl() {
    try {
        if (chrome.runtime && !!chrome.runtime.id) return chrome.runtime.getURL('icons/icon.png');
    } catch (e) {}
    return '';
}

function safeSendMessage(message, callback) {
    try {
        if (chrome.runtime && !!chrome.runtime.id) {
            chrome.runtime.sendMessage(message, callback);
        } else {
            console.warn("Eklenti bağlamı koptu.");
            alert("TracePoint eklentisi güncellendi. Lütfen çalışmaya devam etmek için sayfayı yenileyin (F5).");
        }
    } catch (e) {
        console.warn("Context invalidated error:", e);
        alert("TracePoint eklentisi güncellendi. Lütfen çalışmaya devam etmek için sayfayı yenileyin (F5).");
    }
}

// Güvenlik Regex Kontrolleri
const regexes = {
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    url: /^(https?:\/\/)?([\w.-]+)\.([a-z]{2,})(:\d+)?(\/.*)?$/i,
    email: /^[\w\.-]+@[\w\.-]+\.\w+$/,
    base64: /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    hex: /^(?:[A-Fa-f0-9]{2})+$/,
    urlencoded: /(?:%[0-9A-Fa-f]{2})+/
};

let currentBtn = null;

function determineType(text) {
    text = text.trim();
    if (regexes.md5.test(text) || regexes.sha1.test(text) || regexes.sha256.test(text)) return { type: 'hash', value: text };
    if (regexes.ipv4.test(text)) return { type: 'ipv4', value: text };
    if (regexes.email.test(text)) return { type: 'email', value: text };
    if (regexes.url.test(text)) {
        if (text.includes(" ") || text.length < 4) return null;
        return { type: 'url', value: text };
    }

    // Heuristic PowerShell Detection
    const psKeywords = [
        // Malicious / Obfuscation indicators
        /invoke-expression/i, /\biex\b/i, /-encodedcommand/i, /-enc\b/i, /-nop\b/i, /-w hidden/i, /downloadstring/i, /new-object\s+net\.webclient/i, /\bpowershell\b/i, /\[system\.convert\]::frombase64string/i,
        // Standard Cmdlets (Greylist)
        /get-service/i, /get-date/i, /out-file/i, /where-object/i
    ];

    let psScore = 0;
    for (let r of psKeywords) {
        if (r.test(text)) psScore++;
    }

    // Check for variables ($) and pipes (|) patterns
    const dollarCount = (text.match(/\$/g) || []).length;
    const pipeCount = (text.match(/\|/g) || []).length;

    if ((psScore >= 1 || (dollarCount >= 2 && pipeCount >= 1)) && text.length > 15) {
        return { type: 'powershell', value: text };
    }
    // Heuristic URL Encode Detection
    if (text.includes('%') && regexes.urlencoded.test(text)) {
        try {
            if (decodeURIComponent(text) !== text) return { type: 'urlencoded', value: text };
        } catch (e) { }
    }
    // Heuristic Hex Detection (Avoid mistaking short words as hex, need enough length, > 12 chars)
    if (text.length >= 12 && !text.includes(" ") && regexes.hex.test(text)) {
        return { type: 'hex', value: text };
    }
    // Heuristic Base64 Detection (En az 16 karakter, boşluk içermez)
    if (text.length >= 16 && !text.includes(" ") && regexes.base64.test(text)) {
        try {
            // Test decode to confirm
            if (atob(text)) return { type: 'base64', value: text };
        } catch (e) { }
    }
    return null;
}

function removeButton() {
    if (currentBtn) {
        currentBtn.remove();
        currentBtn = null;
    }
}

document.addEventListener('mouseup', function (e) {
    const selectedText = window.getSelection().toString().trim();

    // Daha önce buton varsa ve seçimin içine/dışına tıklandıysa kaldır
    setTimeout(() => {
        if (!window.getSelection().toString().trim()) {
            removeButton();
        }
    }, 10);

    if (selectedText.length > 5) { // En az 5 karakterlik bir seçim (1.1.1.1 veya domain ihtimali)
        const match = determineType(selectedText);

        if (match) {
            removeButton(); // Varsa eskisini kaldır

            // Tara butonu oluştur (Prompt-to-Scan)
            const btn = document.createElement('div');
            btn.className = 'soc-scanner-btn';

            if (match.type === 'base64' || match.type === 'hex' || match.type === 'urlencoded') {
                btn.innerHTML = `<span class="soc-btn-logo"></span> Decode Et: ${match.type.toUpperCase()}`;
            } else if (match.type === 'powershell') {
                btn.innerHTML = `<span class="soc-btn-logo"></span> SOC Tara: PowerShell Analizi`;
            } else {
                btn.innerHTML = `<span class="soc-btn-logo"></span> İzini Sür: ${match.type.toUpperCase()}`;
            }

            // Seçimin biraz sağ altına yerleştir
            btn.style.left = `${e.pageX + 10}px`;
            btn.style.top = `${e.pageY + 10}px`;

            btn.addEventListener('mousedown', function (e) {
                e.preventDefault(); // Metin seçimini bozmamak için
                e.stopPropagation();

                if (match.type === 'base64' || match.type === 'hex' || match.type === 'urlencoded') {
                    showDecodedPanel(match.value, match.type);
                } else {
                    showInPagePanel(match.value, match.type); // Hemen In-Page Paneli göster!

                    // Arka plana mesaj gönder!
                    safeSendMessage({
                        action: "scan_threat",
                        dataType: match.type,
                        dataValue: match.value
                    }, function (response) {
                        if (response) {
                            updateInPagePanel(response);
                        }
                    });
                }
                removeButton(); // Tarama butonunu sil
            });

            btn.addEventListener('mouseup', function (e) {
                e.stopPropagation(); // Seçimi iptal etmemesi için Document up tetiklenmemeli
            });

            document.body.appendChild(btn);
            currentBtn = btn;
        }
    }
});

// Ekranda scroll veya tıklama yapıldığında seçimi temizle/butonu kaldır
document.addEventListener('mousedown', function (e) {
    // Ekranda açık bir In-Page paneli varsa, panele tıklayınca kaybolmasını (remove) İPTAL ET
    let inpagePanel = document.getElementById('soc-ext-inpage-panel');
    if (inpagePanel && (e.target === inpagePanel || inpagePanel.contains(e.target))) {
        return; // İşlemi iptal et, panel açık kalsın
    }

    if (currentBtn && e.target !== currentBtn && !currentBtn.contains(e.target)) {
        removeButton();
    }
});

// --- In-Page Ekran Tasarımı (Kullanıcı Popup'a tıklamak zorunda kalmasın diye) ---

const SUN_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
const MOON_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

let currentInPageTheme = 'dark';

// Sayfa yüklendiğinde kayıtlı temayı hemen çek
try {
    if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['tracepoint_theme'], (res) => {
            if (res && res.tracepoint_theme) {
                applyInPageTheme(res.tracepoint_theme);
            }
        });
    }
} catch (e) {}

function applyInPageTheme(theme) {
    currentInPageTheme = theme || 'dark';
    const panel = document.getElementById('soc-ext-inpage-panel');
    const themeBtn = document.getElementById('soc-ext-theme-btn');
    if (panel) {
        if (currentInPageTheme === 'light') {
            panel.classList.add('light-theme');
        } else {
            panel.classList.remove('light-theme');
        }
    }
    if (themeBtn) {
        if (currentInPageTheme === 'light') {
            themeBtn.innerHTML = MOON_ICON;
            themeBtn.title = "Koyu Moda Geç";
        } else {
            themeBtn.innerHTML = SUN_ICON;
            themeBtn.title = "Açık Moda Geç";
        }
    }

    // CVE Modalı ile Senkronizasyon
    const cveModal = document.getElementById('soc-cve-modal');
    const cveThemeBtn = document.getElementById('soc-cve-theme-btn');
    if (cveModal) {
        if (currentInPageTheme === 'light') {
            cveModal.classList.add('light-theme');
        } else {
            cveModal.classList.remove('light-theme');
        }
    }
    if (cveThemeBtn) {
        if (currentInPageTheme === 'light') {
            cveThemeBtn.innerHTML = MOON_ICON;
            cveThemeBtn.title = "Koyu Moda Geç";
        } else {
            cveThemeBtn.innerHTML = SUN_ICON;
            cveThemeBtn.title = "Açık Moda Geç";
        }
    }

    // Açık olan düzenlenebilir XDR kod bloğu varsa arka planını güncelle
    const codeBlock = document.getElementById('soc-xdr-query-code');
    if (codeBlock && codeBlock.getAttribute('contenteditable') === 'true') {
        codeBlock.style.backgroundColor = currentInPageTheme === 'light' ? '#e2e8f0' : '#1e293b';
    }
}

function initPanelTheme(panel) {
    try {
        if (chrome.storage && chrome.storage.local) {
            chrome.storage.local.get(['tracepoint_theme'], (res) => {
                applyInPageTheme(res?.tracepoint_theme || 'dark');
            });
        } else {
            applyInPageTheme('dark');
        }
    } catch (e) {
        applyInPageTheme('dark');
    }

    const themeBtn = panel.querySelector('#soc-ext-theme-btn');
    if (themeBtn) {
        themeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const newTheme = currentInPageTheme === 'light' ? 'dark' : 'light';
            applyInPageTheme(newTheme);
            try {
                if (chrome.storage && chrome.storage.local) {
                    chrome.storage.local.set({ tracepoint_theme: newTheme });
                }
            } catch (err) {}
        });
    }
}

// Global olarak depolama değişikliklerini dinle (popup ile canlı senkronizasyon)
try {
    if (chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === 'local' && changes.tracepoint_theme) {
                applyInPageTheme(changes.tracepoint_theme.newValue);
            }
        });
    }
} catch (e) {}

function showInPagePanel(targetValue, type = '') {
    let existing = document.getElementById('soc-ext-inpage-panel');
    if (existing) { existing.remove(); }

    const panel = document.createElement('div');
    panel.id = 'soc-ext-inpage-panel';
    panel.className = 'soc-ext-overlay';

    let loadingText = type === 'powershell' ? 'Script Çözümleniyor...' : 'Derin Tarama Yapılıyor...';
    // Eğer powershell ise, çok uzun kodu göstermek yerine kısaltarak göster (HTML kirlenmesin)
    let displayValue = targetValue;
    if (type === 'powershell' && displayValue.length > 80) {
        displayValue = displayValue.substring(0, 80) + '...';
    }

    panel.innerHTML = `
        <div class="soc-ext-header">
            <div class="soc-ext-title" style="color: #c5a963;">
                <span class="soc-btn-logo" style="display:inline-block; width:16px; height:16px; background-image: url('${getExtIconUrl()}');"></span> TracePoint - Kuveyt Türk
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <button id="soc-ext-theme-btn" class="soc-ext-theme-btn" title="Koyu / Açık Mod" aria-label="Tema Değiştir"></button>
                <div class="soc-ext-close" id="soc-ext-close-btn">✕</div>
            </div>
        </div>
        <div class="soc-ext-body">
            <div id="soc-ext-inpage-results">
                <div class="soc-ext-loading">
                    <div class="soc-ext-spinner"></div>
                    <div style="margin-top: 10px; font-family: monospace; color: #3b82f6; word-break: break-all;">${displayValue}</div>
                    <div style="margin-top: 10px;">${loadingText}</div>
                </div>
            </div>
            <div id="soc-ext-inpage-splunk" class="splunk-panel" style="display: block; margin-top: 12px; border-radius:8px; overflow:hidden; border:1px solid rgba(99,102,241,0.25);">
                <div class="splunk-panel-header" id="inpage-splunk-header" style="display:flex; justify-content:space-between; align-items:center; cursor:pointer; user-select:none; padding:10px 14px; background:rgba(99,102,241,0.08);">
                    <span class="splunk-panel-title" style="font-size:12px; font-weight:700; color:#a5b4fc;">🔍 Splunk SPL Sorguları</span>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span id="inpage-splunk-status-badge" class="splunk-loading-badge" style="font-size:10px;">
                            <span class="splunk-spinner"></span> pending
                        </span>
                        <svg id="inpage-splunk-chevron" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transition:transform 0.2s; color:#94a3b8;">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                </div>
                <div id="inpage-splunk-queries-list" style="display:none; padding:10px; background:rgba(0,0,0,0.25);"></div>
            </div>
        </div>
    `;
    document.body.appendChild(panel);
    initPanelTheme(panel);
    document.getElementById('soc-ext-close-btn').addEventListener('click', () => panel.remove());

    const inpageSplunkHeader = document.getElementById('inpage-splunk-header');
    if (inpageSplunkHeader) {
        inpageSplunkHeader.addEventListener('click', () => {
            const list = document.getElementById('inpage-splunk-queries-list');
            const chev = document.getElementById('inpage-splunk-chevron');
            if (list) {
                const isOpen = list.style.display !== 'none';
                list.style.display = isOpen ? 'none' : 'block';
                if (chev) chev.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
            }
        });
    }
}

// URL Encode & Hex Decoder helpers
function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

// Yeni: Decoder Paneli
function showDecodedPanel(encodedText, type) {
    let existing = document.getElementById('soc-ext-inpage-panel');
    if (existing) { existing.remove(); }

    const panel = document.createElement('div');
    panel.id = 'soc-ext-inpage-panel';
    panel.className = 'soc-ext-overlay';

    let decodedText = "";
    try {
        if (type === 'base64') decodedText = atob(encodedText);
        else if (type === 'hex') decodedText = hexToString(encodedText);
        else if (type === 'urlencoded') decodedText = decodeURIComponent(encodedText);
        else decodedText = encodedText;
    } catch (e) { decodedText = "Decode Hatası"; }

    // Çözülen metnin içindeki IoC'leri (IP/URL/Email vb.) ayıkla
    let extractedIoCs = [];
    const words = decodedText.split(/\\s+|"|'|,|;|!/);
    words.forEach(w => {
        let t = determineType(w);
        if (t && t.type !== 'base64' && t.type !== 'hex' && t.type !== 'urlencoded') {
            if (!extractedIoCs.find(i => i.value === t.value)) extractedIoCs.push(t);
        }
    });

    let iocHtml = '';
    if (extractedIoCs.length > 0) {
        iocHtml = `<div style="margin-top:12px; font-size:12px; border-top:1px solid #334155; padding-top:8px;">
            <strong style="color:#6366f1;">Gizli IoC Bulundu:</strong>
            <ul style="padding-left:15px; margin-top:5px;">
                ${extractedIoCs.map(ioc => `<li><span style="color:#e2e8f0;">[${ioc.type.toUpperCase()}]</span> <span class="soc-ext-ioc-link" data-type="${ioc.type}" data-value="${ioc.value.replace(/"/g, '&quot;')}" style="font-family:monospace; color:#38bdf8; cursor:pointer; text-decoration:underline;">${ioc.value}</span> (Tıkla ve Tara)</li>`).join('')}
            </ul>
        </div>`;
    }

    panel.innerHTML = `
        <div class="soc-ext-header">
            <div class="soc-ext-title" style="color: #c5a963;">
                <span class="soc-btn-logo" style="display:inline-block; width:16px; height:16px; background-image: url('${getExtIconUrl()}');"></span> Akıllı Decoder (CyberChef)
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <button id="soc-ext-theme-btn" class="soc-ext-theme-btn" title="Koyu / Açık Mod" aria-label="Tema Değiştir"></button>
                <div class="soc-ext-close" id="soc-ext-close-btn">✕</div>
            </div>
        </div>
        <div class="soc-ext-body">
            <div style="margin-bottom:8px;">
                <span style="font-size:11px; color:#94a3b8;">ORİJİNAL VERİ (${type.toUpperCase()})</span>
                <div class="soc-ext-code-box" style="margin-top:4px; padding:6px; border-radius:4px; font-family:monospace; word-break:break-all; max-height:80px; overflow-y:auto; font-size:11px;">${encodedText}</div>
            </div>
            <div>
                <span style="font-size:11px; color:#10b981;">ÇÖZÜLMÜŞ METİN (PLAINTEXT)</span>
                <div class="soc-ext-decoded-box" style="margin-top:4px; padding:6px; border-radius:4px; font-family:monospace; word-break:break-all; max-height:120px; overflow-y:auto; font-size:13px; line-height:1.4;">
                    ${decodedText.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
                </div>
            </div>
            ${iocHtml}
        </div>
    `;
    document.body.appendChild(panel);
    initPanelTheme(panel);
    document.getElementById('soc-ext-close-btn').addEventListener('click', () => panel.remove());
    
    // Add event listeners for extracted IOCs
    const iocLinks = panel.querySelectorAll('.soc-ext-ioc-link');
    iocLinks.forEach(link => {
        link.addEventListener('click', function() {
            const type = this.getAttribute('data-type');
            const value = this.getAttribute('data-value');
            if (window.scanExtractedIoc) window.scanExtractedIoc(type, value);
        });
    });
}

// Panel içerisindeki IoC'ye tıklandığında In-Page analizi tetikleyen yardımcı fonksiyon (global scope)
window.scanExtractedIoc = function (type, value) {
    showInPagePanel(value, type);
    safeSendMessage({ action: "scan_threat", dataType: type, dataValue: value }, function (response) {
        if (response) updateInPagePanel(response);
    });
};

function sh(text, maxLen = 100) {
    const s = String(text !== undefined && text !== null ? text : '—');
    return escapeHtml(s.length > maxLen ? s.substring(0, maxLen) + '…' : s);
}

const SOURCE_LABELS = {
    'VirusTotal':                  'VirusTotal',
    'AlienVault OTX':              'OTX',
    'AlienVault':                  'OTX',
    'AbuseIPDB':                   'AbuseIPDB',
    'Shodan':                      'Shodan',
    'GreyNoise':                   'GreyNoise',
    'IPInfo.io':                   'IPInfo',
    'IPInfo':                      'IPInfo',
    'ipapi.co':                    'ipapi.co',
    'MalwareBazaar':               'MBazaar',
    'Hybrid Analysis':             'Hybrid',
    'Triage':                      'Triage',
    'Polyswarm':                   'Polyswarm',
    'Pulsedive':                   'Pulsedive',
    'URLhaus':                     'URLhaus',
    'Sucuri SiteCheck':            'Sucuri',
    'urlscan.io':                  'URLScan',
    'USOM':                        'USOM',
    'PhishTank':                   'PhishTank',
    'CIRCL Hashlookup':            'CIRCL',
    'AbstractAPI':                 'Abstract',
    'emailrep.io':                 'EmailRep',
    'HaveIBeenPwned':              'HIBP',
    'BreachDirectory':             'BreachDir',
    'Spamhaus':                    'Spamhaus',
    'SecurityTrails':              'SecTrails',
    'crt.sh':                      'crt.sh',
    'RDAP':                        'RDAP',
    'IntelX':                      'IntelX',
};

function classifySource(res, targetValue = '', iocType = '') {
    if (!res.success) {
        return {
            verdict: 'error',
            metric: 'Hata',
            detailHtml: `<div style="color:#94a3b8;">${sh(res.error || 'API isteği başarısız')}</div>`
        };
    }

    const src  = res.source || '';
    const data = (res.data && typeof res.data === 'object') ? res.data : {};
    const targetStr = encodeURIComponent(targetValue || '');

    // ── VirusTotal ────────────────────────────────────────────────
    if (src.includes('VirusTotal')) {
        const vtData = data.data;
        const attrs  = (vtData && typeof vtData === 'object') ? (vtData.attributes || {}) : {};
        const stats  = attrs.last_analysis_stats || {};
        const mal    = stats.malicious  || 0;
        const sus    = stats.suspicious || 0;
        const total  = Object.values(stats).reduce((a, b) => a + b, 0);
        const verdict = mal > 4 ? 'malicious' : (mal > 0 || sus > 0 ? 'suspicious' : 'clean');
        const rep = attrs.reputation;

        let vtLink = '';
        if (targetValue) {
            if (iocType === 'hash') vtLink = `https://www.virustotal.com/gui/file/${targetStr}/detection`;
            else if (iocType === 'ipv4' || iocType === 'ip') vtLink = `https://www.virustotal.com/gui/ip-address/${targetStr}/detection`;
            else vtLink = `https://www.virustotal.com/gui/search/${targetStr}`;
        }

        return {
            verdict,
            metric: total > 0 ? `${mal}/${total}` : '—',
            detailHtml: `
                <div>🔍 <b>${mal}</b> zararlı / <b>${sus}</b> şüpheli / <b>${total}</b> motor</div>
                ${rep !== undefined ? `<div>👥 İtibar: <b style="color:${rep < 0 ? '#ef4444' : rep > 0 ? '#10b981' : '#94a3b8'}">${rep > 0 ? '+' + rep : rep}</b></div>` : ''}
                ${attrs.tags?.length ? `<div>🏷️ ${attrs.tags.slice(0,5).map(t => sh(t)).join(', ')}</div>` : ''}
                ${vtLink ? `<div style="margin-top:4px;"><a href="${vtLink}" target="_blank" class="soc-ext-link">VT'de Gör →</a></div>` : ''}
            `
        };
    }

    // ── AbuseIPDB ─────────────────────────────────────────────────
    if (src.includes('AbuseIPDB')) {
        const d     = data.data || {};
        const score = d.abuseConfidenceScore || 0;
        const verdict = score > 70 ? 'malicious' : score > 20 ? 'suspicious' : 'clean';
        const scoreColor = verdict === 'malicious' ? '#ef4444' : verdict === 'suspicious' ? '#f59e0b' : '#10b981';
        return {
            verdict,
            metric: `${score}%`,
            detailHtml: `
                <div>📊 Güven skoru: <b style="color:${scoreColor}">${score}%</b></div>
                <div>📋 Rapor sayısı: <b>${d.totalReports || 0}</b></div>
                <div>🌐 ISP: ${sh(d.isp || '—')}</div>
                <div>🏳️ Ülke: ${sh(d.countryCode || '—')}</div>
                ${d.domain ? `<div>🔗 Domain: ${sh(d.domain)}</div>` : ''}
                ${targetValue ? `<div style="margin-top:4px;"><a href="https://www.abuseipdb.com/check/${targetStr}" target="_blank" class="soc-ext-link">AbuseIPDB'de Gör →</a></div>` : ''}
            `
        };
    }

    // ── Shodan ────────────────────────────────────────────────────
    if (src.includes('Shodan')) {
        const ports = data.open_ports || [];
        const vulns = data.vulns || [];
        const verdict = vulns.length > 0 ? 'suspicious' : ports.length > 0 ? 'clean' : 'unknown';
        return {
            verdict,
            metric: ports.length > 0 ? `${ports.slice(0,3).join(',')}` : '—',
            detailHtml: `
                ${ports.length > 0 ? `<div>🔓 Açık portlar: <b>${ports.join(', ')}</b></div>` : '<div>🔒 Açık port tespit edilmedi.</div>'}
                ${vulns.length > 0 ? `<div>⚠️ CVE: <span style="color:#f59e0b">${vulns.slice(0,5).join(', ')}</span></div>` : ''}
                ${data.org  ? `<div>🏢 Org: ${sh(data.org)}</div>`  : ''}
                ${data.os   ? `<div>💻 OS: ${sh(data.os)}</div>`    : ''}
                ${data.country ? `<div>🌐 Ülke: ${sh(data.country)}</div>` : ''}
                ${data.hostnames?.length ? `<div>🌍 Hostname: ${data.hostnames.slice(0,3).map(h => sh(h)).join(', ')}</div>` : ''}
            `
        };
    }

    // ── GreyNoise ─────────────────────────────────────────────────
    if (src.includes('GreyNoise')) {
        const cls   = data.classification || '';
        const noise = data.noise || false;
        const riot  = data.riot  || false;
        const verdict = cls === 'malicious' ? 'malicious' : (noise && !riot ? 'suspicious' : 'clean');
        return {
            verdict,
            metric: cls || (noise ? 'Noise' : 'Temiz'),
            detailHtml: `
                <div>📡 Noise: <b style="color:${noise ? '#f59e0b' : '#10b981'}">${noise ? 'Evet' : 'Hayır'}</b></div>
                <div>🏢 RIOT: <b>${riot ? 'Evet (Trusted)' : 'Hayır'}</b></div>
                ${data.name ? `<div>🔖 İsim: ${sh(data.name)}</div>` : ''}
                ${cls ? `<div>🎯 Sınıf: <b style="color:${cls === 'malicious' ? '#ef4444' : '#10b981'}">${cls}</b></div>` : ''}
            `
        };
    }

    // ── AlienVault OTX ────────────────────────────────────────────
    if (src.includes('AlienVault') || src.includes('OTX')) {
        const count = data.pulse_info?.count || 0;
        const verdict = count > 2 ? 'malicious' : count > 0 ? 'suspicious' : 'clean';
        const tags = data.pulse_info?.pulses?.[0]?.tags?.slice(0,4) || [];
        return {
            verdict,
            metric: `${count} pulse`,
            detailHtml: `
                <div>📡 Pulse sayısı: <b>${count}</b></div>
                ${tags.length > 0 ? `<div>🏷️ Etiketler: ${tags.map(t => sh(t)).join(', ')}</div>` : ''}
                ${targetValue ? `<div style="margin-top:4px;"><a href="https://otx.alienvault.com/indicator/ip/${targetStr}" target="_blank" class="soc-ext-link">OTX'de Gör →</a></div>` : ''}
            `
        };
    }

    // ── MalwareBazaar ─────────────────────────────────────────────
    if (src.includes('MalwareBazaar')) {
        const status = data.query_status;
        const verdict = status === 'ok' ? 'malicious' : 'clean';
        const item = data.data?.[0] || {};
        return {
            verdict,
            metric: verdict === 'malicious' ? 'Zararlı' : 'Bulunamadı',
            detailHtml: `
                <div>📊 Durum: <b style="color:${verdict === 'malicious' ? '#ef4444' : '#10b981'}">${status === 'ok' ? 'Zararlı olarak listelendi' : 'Listede yok'}</b></div>
                ${item.file_type ? `<div>📄 Tip: ${sh(item.file_type)}</div>` : ''}
                ${item.signature ? `<div>🔒 İmza: ${sh(item.signature)}</div>` : ''}
            `
        };
    }

    // ── Hybrid Analysis ───────────────────────────────────────────
    if (src.includes('Hybrid Analysis')) {
        const items = Array.isArray(data) ? data : [];
        const vv = items[0]?.verdict;
        const verdict = vv === 'malicious' ? 'malicious' : vv === 'suspicious' ? 'suspicious' : items.length > 0 ? 'clean' : 'unknown';
        return {
            verdict,
            metric: vv || (items.length > 0 ? `${items.length} örnek` : '—'),
            detailHtml: `
                <div>🔬 Örnek sayısı: <b>${items.length}</b></div>
                ${vv ? `<div>🎯 Karar: <b style="color:${verdict === 'malicious' ? '#ef4444' : '#10b981'}">${vv}</b></div>` : ''}
            `
        };
    }

    // ── Triage ────────────────────────────────────────────────────
    if (src.includes('Triage')) {
        const count = data.sample_count || 0;
        const verdict = count > 0 ? 'suspicious' : 'clean';
        return {
            verdict,
            metric: count > 0 ? `${count} sample` : 'Bulunamadı',
            detailHtml: `
                <div>🔬 Sandbox örneği: <b>${count}</b></div>
                ${count === 0 ? '<div>✅ Bu hash Triage sandbox\'ında görülmemiş.</div>' : ''}
            `
        };
    }

    // ── Polyswarm ─────────────────────────────────────────────────
    if (src.includes('Polyswarm')) {
        const results = data.result || [];
        const verdict = results.length > 0 ? 'suspicious' : 'clean';
        return {
            verdict,
            metric: `${results.length} sonuç`,
            detailHtml: `<div>🔬 Sonuç sayısı: <b>${results.length}</b></div>`
        };
    }

    // ── Pulsedive ─────────────────────────────────────────────────
    if (src.includes('Pulsedive')) {
        const risk = data.risk || 'unknown';
        const riskLower = risk.toLowerCase();
        const verdict = ['high', 'critical', 'very high'].includes(riskLower) ? 'malicious'
            : ['medium', 'low'].includes(riskLower) ? 'suspicious' : 'clean';
        const threats = (data.threats || []).slice(0,3).map(t => t.name || t).join(', ');
        const riskColor = verdict === 'malicious' ? '#ef4444' : verdict === 'suspicious' ? '#f59e0b' : '#10b981';
        return {
            verdict,
            metric: risk,
            detailHtml: `
                <div>⚠️ Risk: <b style="color:${riskColor}">${risk}</b></div>
                ${threats ? `<div>🎯 Tehditler: ${sh(threats)}</div>` : ''}
            `
        };
    }

    // ── URLhaus ───────────────────────────────────────────────────
    if (src.includes('URLhaus')) {
        const status = data.url_status;
        const verdict = status === 'online' ? 'malicious' : status === 'offline' ? 'suspicious' : 'clean';
        return {
            verdict,
            metric: status || 'Bulunamadı',
            detailHtml: `
                <div>🌐 URL durumu: <b style="color:${verdict === 'malicious' ? '#ef4444' : '#f59e0b'}">${status || 'Bilinmiyor'}</b></div>
                ${data.threat ? `<div>⚠️ Tehdit: ${sh(data.threat)}</div>` : ''}
                ${(data.tags || []).length > 0 ? `<div>🏷️ Etiket: ${data.tags.join(', ')}</div>` : ''}
            `
        };
    }

    // ── Sucuri SiteCheck ──────────────────────────────────────────
    if (src.includes('Sucuri')) {
        const bls = data.blacklists || [];
        const isBlacklisted = Array.isArray(bls) && bls.some(b => b.is_blacklisted);
        const warnings = data.warnings || [];
        const verdict = isBlacklisted ? 'malicious' : warnings.length > 0 ? 'suspicious' : 'clean';
        const si = data.site_info || {};
        return {
            verdict,
            metric: isBlacklisted ? 'Kara Listede' : `${warnings.length} uyarı`,
            detailHtml: `
                <div>🚫 Kara liste: <b>${isBlacklisted ? 'Evet' : 'Hayır'}</b></div>
                <div>⚠️ Uyarı: <b>${warnings.length}</b></div>
                ${si.ip     ? `<div>🌐 IP: ${sh(si.ip)}</div>`          : ''}
                ${si.server ? `<div>🖥️ Server: ${sh(si.server)}</div>` : ''}
                ${si.application ? `<div>📦 CMS: ${sh(si.application)}</div>` : ''}
                ${targetValue ? `<div style="margin-top:4px;"><a href="https://sitecheck.sucuri.net/results/${targetStr}" target="_blank" class="soc-ext-link">Sucuri'de İncele →</a></div>` : ''}
            `
        };
    }

    // ── urlscan.io ────────────────────────────────────────────────
    if (src.includes('urlscan')) {
        const total   = data.total || 0;
        const page    = data.results?.[0]?.page || {};
        return {
            verdict: total > 0 ? 'unknown' : 'clean',
            metric: `${total} tarama`,
            detailHtml: `
                <div>🔍 Geçmiş tarama sayısı: <b>${total}</b></div>
                ${page.ip     ? `<div>🌐 IP: ${sh(page.ip)}</div>`     : ''}
                ${page.server ? `<div>🖥️ Server: ${sh(page.server)}</div>` : ''}
                ${page.asn    ? `<div>📡 ASN: ${sh(page.asn)} (${sh(page.asnname || '')})</div>` : ''}
                ${total > 0 && targetValue ? `<div style="margin-top:4px;"><a href="https://urlscan.io/search/#domain:${targetStr}" target="_blank" class="soc-ext-link">urlscan'da Gör →</a></div>` : ''}
            `
        };
    }

    // ── USOM ──────────────────────────────────────────────────────
    if (src.includes('USOM')) {
        const count = data.totalCount || 0;
        const model = data.models?.[0] || {};
        const verdict = count > 0 ? 'malicious' : 'clean';
        return {
            verdict,
            metric: count > 0 ? `${count} eşleşme` : 'Temiz',
            detailHtml: `
                <div>🇹🇷 USOM kara liste: <b style="color:${count > 0 ? '#ef4444' : '#10b981'}">${count} eşleşme</b></div>
                ${model.desc   ? `<div>📋 Açıklama: ${sh(model.desc)}</div>`   : ''}
                ${model.source ? `<div>📌 Kaynak: ${sh(model.source)}</div>`   : ''}
                ${model.date   ? `<div>📅 Tarih: ${sh(model.date.split(' ')[0])}</div>` : ''}
                <div style="margin-top:4px;"><a href="https://www.usom.gov.tr/zararli-baglantilar" target="_blank" class="soc-ext-link">USOM'da Ara →</a></div>
            `
        };
    }

    // ── PhishTank ─────────────────────────────────────────────────
    if (src.includes('PhishTank')) {
        const inDb = data.in_database || false;
        const verdict = inDb ? 'malicious' : 'clean';
        return {
            verdict,
            metric: inDb ? 'Phishing!' : 'Temiz',
            detailHtml: `
                <div>🎣 PhishTank DB: <b style="color:${inDb ? '#ef4444' : '#10b981'}">${inDb ? 'Evet — Phishing sitesi!' : 'Hayır'}</b></div>
                ${data.verified !== undefined ? `<div>✅ Doğrulandı: <b>${data.verified ? 'Evet' : 'Hayır'}</b></div>` : ''}
            `
        };
    }

    // ── CIRCL Hashlookup ──────────────────────────────────────────
    if (src.includes('CIRCL')) {
        const found = !data.message || data.message !== 'Not found';
        return {
            verdict: found ? 'clean' : 'unknown',
            metric: found ? 'Bulundu' : 'Bulunamadı',
            detailHtml: `<div>🔍 CIRCL veritabanı: <b>${found ? 'Hash kaydı var (meşru yazılım olabilir)' : 'Kayıt yok'}</b></div>`
        };
    }

    // ── IPInfo.io ─────────────────────────────────────────────────
    if (src.includes('IPInfo')) {
        const orgShort = (data.org || '').split(' ').slice(0,2).join(' ');
        return {
            verdict: 'clean',
            metric: `${data.country || '?'} / ${orgShort}`,
            detailHtml: `
                <div>🌍 Şehir: ${sh(data.city || '—')}, ${sh(data.region || '—')}</div>
                <div>🌐 Ülke: ${sh(data.country || '—')}</div>
                <div>🏢 Org: ${sh(data.org || '—')}</div>
                <div>⏰ Timezone: ${sh(data.timezone || '—')}</div>
                ${data.loc ? `<div>📍 Konum: ${sh(data.loc)}</div>` : ''}
            `
        };
    }

    // ── ipapi.co ──────────────────────────────────────────────────
    if (src.includes('ipapi')) {
        return {
            verdict: 'clean',
            metric: sh(data.city || data.country_name || '—', 12),
            detailHtml: `
                <div>🌍 Şehir: ${sh(data.city || '—')}</div>
                <div>🌐 Ülke: ${sh(data.country_name || '—')}</div>
                <div>🏢 Org: ${sh(data.org || '—')}</div>
                <div>📡 ASN: ${sh(data.asn || '—')}</div>
                <div>⏰ Timezone: ${sh(data.timezone || '—')}</div>
            `
        };
    }

    // ── AbstractAPI ───────────────────────────────────────────────
    if (src.includes('AbstractAPI')) {
        const del = data.deliverability || 'UNKNOWN';
        const isDisposable = data.is_disposable_email?.value || false;
        const verdict = isDisposable ? 'suspicious' : del === 'DELIVERABLE' ? 'clean' : 'unknown';
        return {
            verdict,
            metric: del.substring(0, 12),
            detailHtml: `
                <div>📧 Teslim edilebilirlik: <b>${del}</b></div>
                <div>📊 Kalite skoru: <b>${Math.round((parseFloat(data.quality_score) || 0) * 100)}%</b></div>
                <div>🗑️ Tek kullanımlık: <b style="color:${isDisposable ? '#ef4444' : '#10b981'}">${isDisposable ? 'Evet' : 'Hayır'}</b></div>
                <div>📬 MX kaydı: <b>${data.mx_records ? 'Var' : 'Yok'}</b></div>
            `
        };
    }

    // ── emailrep.io ───────────────────────────────────────────────
    if (src.includes('emailrep')) {
        const rep = data.reputation || 'unknown';
        const sus = data.suspicious || false;
        const verdict = sus ? 'suspicious' : rep === 'none' ? 'unknown' : 'clean';
        const details = data.details || {};
        return {
            verdict,
            metric: rep,
            detailHtml: `
                <div>📊 İtibar: <b>${rep}</b></div>
                <div>⚠️ Şüpheli: <b style="color:${sus ? '#ef4444' : '#10b981'}">${sus ? 'Evet' : 'Hayır'}</b></div>
                ${details.blacklisted ? '<div>🚫 Kara listede</div>' : ''}
                ${details.malicious_activity ? '<div>🔴 Zararlı aktivite tespit edildi</div>' : ''}
                ${details.credentials_leaked ? '<div>💀 Parola sızmış</div>' : ''}
                ${details.days_since_domain_creation ? `<div>📅 Alan adı yaşı: ${details.days_since_domain_creation} gün</div>` : ''}
            `
        };
    }

    // ── HaveIBeenPwned ────────────────────────────────────────────
    if (src.includes('HaveIBeenPwned')) {
        const breached = res.breached || false;
        const breachList = Array.isArray(res.data) ? res.data : [];
        const verdict = breached ? 'malicious' : 'clean';
        return {
            verdict,
            metric: breached ? `${breachList.length} ihlal` : 'İhlal Yok',
            detailHtml: breached
                ? `<div>💀 <b>${breachList.length}</b> veri ihlalinde bulundu:</div>
                   <div style="margin-top:4px;">${breachList.slice(0,5).map(b => `• ${sh(b.Name || '')} (${sh(b.BreachDate || '')})`).join('<br>')}</div>
                   ${targetValue ? `<div style="margin-top:4px;"><a href="https://haveibeenpwned.com/account/${targetStr}" target="_blank" class="soc-ext-link">HIBP'de Gör →</a></div>` : ''}`
                : '<div>✅ Bu e-posta hiçbir veri ihlalinde görülmemiş.</div>'
        };
    }

    // ── BreachDirectory ───────────────────────────────────────────
    if (src.includes('BreachDirectory')) {
        const found = data.found || 0;
        const verdict = found > 0 ? 'suspicious' : 'clean';
        return {
            verdict,
            metric: found > 0 ? `${found} kayıt` : 'Temiz',
            detailHtml: `
                <div>🔍 Bulunan kayıt: <b style="color:${found > 0 ? '#f59e0b' : '#10b981'}">${found}</b></div>
                ${found > 0 ? '<div style="color:#f59e0b;font-size:10px;">⚠️ Sızdırılmış kimlik bilgisi olabilir.</div>' : ''}
            `
        };
    }

    // ── Spamhaus ──────────────────────────────────────────────────
    if (src.includes('Spamhaus')) {
        const bl = data.domain_blacklisted || false;
        const verdict = bl ? 'malicious' : 'clean';
        return {
            verdict,
            metric: bl ? 'Listede!' : 'Temiz',
            detailHtml: `
                <div>🚫 DBL kara liste: <b style="color:${data.dbl_listed ? '#ef4444' : '#10b981'}">${data.dbl_listed ? 'Evet' : 'Hayır'}</b></div>
                <div>🚫 Zen kara liste: <b style="color:${data.sbl_listed ? '#ef4444' : '#10b981'}">${data.sbl_listed ? 'Evet' : 'Hayır'}</b></div>
                <div style="margin-top:4px;"><a href="https://check.spamhaus.org/" target="_blank" class="soc-ext-link">Spamhaus'ta Kontrol Et →</a></div>
            `
        };
    }

    // ── MX / DNS ──────────────────────────────────────────────────
    if (src.includes('MX') || src.includes('DNS')) {
        const resolves = data.domain_resolves || false;
        return {
            verdict: resolves ? 'clean' : 'unknown',
            metric: resolves ? 'Geçerli' : 'Geçersiz',
            detailHtml: `
                <div>📡 DNS çözümleme: <b style="color:${resolves ? '#10b981' : '#ef4444'}">${resolves ? 'Başarılı' : 'Başarısız'}</b></div>
                <div>📬 MX kaydı: <b>${data.mx_valid ? 'Var' : 'Yok veya çözümlenemedi'}</b></div>
            `
        };
    }

    // ── SecurityTrails ────────────────────────────────────────────
    if (src.includes('SecurityTrails')) {
        const subCount  = data.subdomain_count || 0;
        const registrar = data.whois?.registrar || '—';
        return {
            verdict: 'unknown',
            metric: `${subCount} sub`,
            detailHtml: `
                <div>🌐 Subdomain sayısı: <b>${subCount}</b></div>
                <div>📋 Registrar: ${sh(registrar)}</div>
                ${data.whois?.created ? `<div>📅 Kayıt: ${sh(data.whois.created)}</div>` : ''}
                ${data.whois?.expires ? `<div>⏳ Bitiş: ${sh(data.whois.expires)}</div>` : ''}
                ${subCount > 0 ? `<div>🔍 İlk 5: ${(data.subdomains || []).slice(0,5).map(s => sh(s)).join(', ')}</div>` : ''}
            `
        };
    }

    // ── crt.sh ────────────────────────────────────────────────────
    if (src.includes('crt.sh')) {
        const certCount   = data.certificate_count || 0;
        const uniqueNames = data.unique_names || 0;
        return {
            verdict: 'unknown',
            metric: `${certCount} sertifika`,
            detailHtml: `
                <div>🔒 Sertifika sayısı: <b>${certCount}</b></div>
                <div>🌐 Benzersiz isim: <b>${uniqueNames}</b></div>
                ${data.certificates?.length ? `<div style="margin-top:4px;">${data.certificates.slice(0,3).map(c => `• ${sh(c.common_name || '')} (${c.not_before || ''})`).join('<br>')}</div>` : ''}
            `
        };
    }

    // ── RDAP ──────────────────────────────────────────────────────
    if (src.includes('RDAP')) {
        const registrar = data.registrar || '—';
        return {
            verdict: 'unknown',
            metric: sh(registrar, 12),
            detailHtml: `
                <div>📋 Registrar: ${sh(registrar)}</div>
                ${data.registration ? `<div>📅 Kayıt: ${sh(data.registration)}</div>` : ''}
                ${data.expiration   ? `<div>⏳ Bitiş: ${sh(data.expiration)}</div>`   : ''}
                ${data.status?.length ? `<div>📊 Durum: ${data.status.join(', ')}</div>` : ''}
                ${data.name_servers?.length ? `<div>🖥️ NS: ${data.name_servers.slice(0,3).join(', ')}</div>` : ''}
            `
        };
    }

    // ── IntelX ────────────────────────────────────────────────────
    if (src.includes('IntelX')) {
        const found = data.total_found || 0;
        const verdict = found > 0 ? 'suspicious' : 'clean';
        return {
            verdict,
            metric: `${found} kayıt`,
            detailHtml: `
                <div>🔍 Bulunan kayıt: <b style="color:${found > 0 ? '#f59e0b' : '#10b981'}">${found}</b></div>
                ${found > 0 ? (data.records || []).slice(0,3).map(r => `<div>• ${sh(r.name || '')} (${sh(r.date || '')})</div>`).join('') : ''}
            `
        };
    }

    // ── Pre-processor ─────────────────────────────────────────────
    if (src.includes('Pre-processor') || src.includes('De-Obfuscator')) {
        const isObf = data?.is_obfuscated || false;
        const count = data?.decoded_blocks || 0;
        return {
            verdict: isObf ? 'malicious' : 'clean',
            metric: isObf ? `${count} blok` : 'Temiz',
            detailHtml: `
                <div>🔍 Gizleme (Obfuscation): <b style="color:${isObf ? '#ef4444' : '#10b981'}">${isObf ? 'Tespit edildi' : 'Tespit edilmedi'}</b></div>
                ${isObf ? `<div>🔓 Çözülen blok: <b>${count}</b></div>` : ''}
            `
        };
    }

    // ── Fallback ──────────────────────────────────────────────────
    return {
        verdict: 'unknown',
        metric: '—',
        detailHtml: `<div style="color:#94a3b8;">Bu kaynak için detaylı parser henüz tanımlanmamış.</div>`
    };
}

function buildVerdictBarHtml(results, targetValue = '', iocType = '') {
    const counts = { malicious: 0, suspicious: 0, clean: 0 };
    results.forEach(res => {
        const { verdict } = classifySource(res, targetValue, iocType);
        if (verdict in counts) counts[verdict]++;
    });

    const total = results.length;
    let html = '';

    if (counts.malicious > 0) {
        html += `<span class="verdict-pill malicious"><span class="verdict-dot"></span>Zararlı <strong>${counts.malicious}</strong></span>`;
    }
    if (counts.suspicious > 0) {
        html += `<span class="verdict-pill suspicious"><span class="verdict-dot"></span>Şüpheli <strong>${counts.suspicious}</strong></span>`;
    }
    if (counts.clean > 0) {
        html += `<span class="verdict-pill clean"><span class="verdict-dot"></span>Temiz <strong>${counts.clean}</strong></span>`;
    }
    html += `<span class="verdict-count-label">${total} kaynak</span>`;
    return html;
}

function buildInPageSourcesAccordion(results, targetValue = '', iocType = '') {
    const wrapper = document.createElement('div');
    wrapper.className = 'sources-accordion-inner';

    // Header
    const header = document.createElement('div');
    header.className = 'accordion-header';
    header.innerHTML = `
        <span style="display:flex; align-items:center; gap:6px;">🛡️ İstihbarat Kaynakları (${results.length} Kaynak)</span>
        <svg class="accordion-chevron" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
    `;

    // Body (varsayılan kapalı)
    const body = document.createElement('div');
    body.className = 'accordion-body';
    body.style.display = 'none';

    // Chip Grid
    const grid = document.createElement('div');
    grid.className = 'chips-grid';

    // Kaynakları ikili grupla
    for (let i = 0; i < results.length; i += 2) {
        const rowEl = document.createElement('div');
        rowEl.className = 'chip-row';

        const rowResults  = results.slice(i, i + 2);
        const chipEls     = [];
        const detailInfos = [];

        rowResults.forEach((res) => {
            const { verdict, metric, detailHtml } = classifySource(res, targetValue, iocType);
            const srcName = res.source || 'Bilinmeyen';
            const label   = SOURCE_LABELS[srcName] || srcName.split(' ')[0];
            const isSolo  = rowResults.length === 1; // Tek sayıda kaynak (son satır)

            const chip = document.createElement('div');
            chip.className = `source-chip${verdict === 'error' ? ' chip-error' : ''}${isSolo ? ' chip-solo' : ''}`;
            chip.dataset.expanded = 'false';
            chip.title = srcName;
            chip.innerHTML = `
                <span class="chip-dot ${verdict}"></span>
                <span class="chip-name">${escapeHtml(label)}</span>
                <span class="chip-metric">${escapeHtml(String(metric).substring(0, 13))}</span>
            `;

            chipEls.push(chip);
            detailInfos.push({ detailHtml, srcName });
            rowEl.appendChild(chip);
        });

        // Paylaşılan detail panel (satır için tek panel)
        const detailPanel = document.createElement('div');
        detailPanel.className = 'chip-detail';
        detailPanel.style.display = 'none';
        rowEl.appendChild(detailPanel);

        // Click handler (her chip için)
        chipEls.forEach((chip, idx) => {
            chip.addEventListener('click', () => {
                const isThisExpanded = chip.dataset.expanded === 'true';

                // Tüm chip'leri resetle
                chipEls.forEach(c => {
                    c.classList.remove('expanded');
                    c.dataset.expanded = 'false';
                });

                if (!isThisExpanded) {
                    // Bu chip'i aç
                    chip.classList.add('expanded');
                    chip.dataset.expanded = 'true';
                    const { detailHtml, srcName } = detailInfos[idx];
                    detailPanel.innerHTML = `
                        <div class="chip-detail-source">📌 ${escapeHtml(srcName)}</div>
                        ${detailHtml || '<div style="color:#94a3b8;">Detay bilgisi yok.</div>'}
                    `;
                    detailPanel.style.display = 'block';
                } else {
                    // Aynı chip'e tekrar tıklandı → kapat
                    detailPanel.style.display = 'none';
                }
            });
        });

        grid.appendChild(rowEl);
    }

    body.appendChild(grid);

    // Accordion toggle
    header.addEventListener('click', () => {
        const isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : 'block';
        header.classList.toggle('is-open', !isOpen);
    });

    wrapper.appendChild(header);
    wrapper.appendChild(body);
    return wrapper;
}

function updateInPagePanel(result) {
    const body = document.getElementById('soc-ext-inpage-results');
    if (!body) return;

    if (result.status === "error") {
        body.innerHTML = `<div style="color:#ef4444; padding:10px;">⛔ Sunucu Hatası: ${result.error}</div>`;
        return;
    }

    if (result.status === "success") {
        let rawData = result.rawData;
        let html = '';

        if (result.type === 'report') {
            html += `
            <div class="soc-ext-card inpage-ai-card" id="inpage-report-ai-card" style="padding:0; margin-bottom:12px; overflow:hidden; border-radius:8px; border:1px solid rgba(99,102,241,0.25);">
                <div id="inpage-report-ai-header" style="display:flex; justify-content:space-between; align-items:center; cursor:pointer; user-select:none; padding:10px 14px; background:rgba(99,102,241,0.08);">
                    <span style="font-size:12px; font-weight:700; color:#a5b4fc; display:flex; align-items:center; gap:6px;">📄 Rapor Özeti</span>
                    <svg id="inpage-report-ai-chevron" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transition:transform 0.25s cubic-bezier(0.4, 0, 0.2, 1); color:#94a3b8; transform:rotate(180deg);">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div id="inpage-report-ai-body" class="soc-ext-ai-body" style="display:block; padding:12px 14px; font-size:12px; line-height:1.6; background:rgba(15,23,42,0.4);">
                    ${rawData.summary || "Özet çıkarılamadı."}
                </div>
            </div>`;
            html += `<div class="soc-ext-section-title" style="margin-bottom:8px;">Taranan IOC Kategorileri (${rawData.total_iocs_found || 0} Adet)</div>`;
            
            if (rawData.grouped_iocs && rawData.grouped_iocs.length > 0) {
                const reportGroupsMap = {}; // Global store for click listeners
                window._reportGroupsMap = reportGroupsMap; // Ensure it's accessible

                rawData.grouped_iocs.forEach((group, index) => {
                    const gId = `accordion-group-${index}`;
                    reportGroupsMap[gId] = group;
                    const t = group.type.toUpperCase();
                    const cnt = group.count;
                    
                    let valuesHtml = `<div class="report-values-grid">`;
                    group.values.forEach(v => {
                        valuesHtml += `<span class="report-ioc-pill" title="${escapeHtml(v)}">${escapeHtml(v)}</span>`;
                    });
                    valuesHtml += `</div>`;
                    
                    let splHtml = `<div id="spl-container-${gId}"></div>`;

                    html += `
                    <div class="soc-ext-card report-group-card" style="padding:0; margin-bottom:8px; overflow:hidden;">
                        <button class="accordion-header report-accordion-btn" data-target="${gId}">
                            <span style="display:flex; align-items:center; gap:8px;">
                                <span class="report-type-badge">${t}</span>
                                <span class="report-count-label">(${cnt} Adet)</span>
                            </span>
                            <span class="acc-chevron" style="color:#6366f1; transition:transform 0.2s; font-size:11px;">▼</span>
                        </button>
                        <div id="${gId}" class="report-accordion-body" style="display:none;">
                            ${valuesHtml}
                            ${splHtml}
                        </div>
                    </div>`;
                });
                
                // Action Buttons
                html += `
                <div style="margin-top:15px; width:100%; display:flex; gap:8px;">
                    <button id="inpageGraphBtn" style="flex:1; background:#8b5cf6; color:#fff; border:none; border-radius:6px; padding:8px; font-weight:bold; cursor:pointer; font-size:11px; transition:all 0.2s;">
                        🕸️ Tehdit Grafiği
                    </button>
                    <button id="inpagePdfBtn" style="flex:1; background:#10b981; color:#fff; border:none; border-radius:6px; padding:8px; font-weight:bold; cursor:pointer; font-size:11px; transition:all 0.2s;">
                        📄 PDF İndir
                    </button>
                </div>`;
            } else {
                html += `<div class="soc-ext-card">IOC bulunamadı.</div>`;
            }
            
            body.innerHTML = html;
            
            // Accordion dinleyicilerini ekle (CSP sebebiyle inline JS kullanamayız)
            const accBtns = body.querySelectorAll('.report-accordion-btn');
            accBtns.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const targetId = e.currentTarget.getAttribute('data-target');
                    const content = document.getElementById(targetId);
                    if (content) {
                        const isExpanded = content.style.display === 'block';
                        content.style.display = isExpanded ? 'none' : 'block';
                        btn.classList.toggle('is-expanded', !isExpanded);
                        const chevron = btn.querySelector('.acc-chevron');
                        if (chevron) chevron.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';
                        
                        // Lazy loading SPL requests
                        if (!isExpanded && !content.hasAttribute('data-spl-loaded')) {
                            content.setAttribute('data-spl-loaded', 'true');
                            
                            const groupData = window._reportGroupsMap[targetId];
                            const splContainer = document.getElementById(`spl-container-${targetId}`);
                            
                            if (splContainer && groupData) {
                                splContainer.innerHTML = `<div class="report-spl-loading"><span class="splunk-spinner"></span> SPL Sorguları üretiliyor...</div>`;
                                
                                safeSendMessage({
                                    action: "fetch_report_spl",
                                    iocType: groupData.type,
                                    values: groupData.values
                                }, (response) => {
                                    if (response && response.queries && response.queries.length > 0) {
                                        let splHtml = `<div class="report-spl-wrapper"><strong class="report-spl-header">Toplu Splunk Sorguları (${response.queries.length}):</strong><div class="report-spl-list">`;
                                        response.queries.forEach(q => {
                                            splHtml += `
                                                <div class="report-spl-item">
                                                    <div class="report-spl-label">[${escapeHtml(q.index || 'Index')}] ${escapeHtml(q.label || '')}</div>
                                                    <div class="report-spl-query">${escapeHtml(q.query)}</div>
                                                </div>`;
                                        });
                                        splHtml += `</div></div>`;
                                        splContainer.innerHTML = splHtml;
                                    } else {
                                        splContainer.innerHTML = `<div class="report-spl-empty">Bu kategori için özel SPL sorgusu bulunamadı.</div>`;
                                    }
                                });
                            }
                        }
                    }
                });
            });

            const repAiHeader = document.getElementById('inpage-report-ai-header');
            if (repAiHeader) {
                repAiHeader.addEventListener('click', () => {
                    const rBody = document.getElementById('inpage-report-ai-body');
                    const rChev = document.getElementById('inpage-report-ai-chevron');
                    if (rBody) {
                        const isOpen = rBody.style.display !== 'none';
                        rBody.style.display = isOpen ? 'none' : 'block';
                        if (rChev) rChev.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
                    }
                });
            }
            
            const pdfBtn = document.getElementById('inpagePdfBtn');
            if (pdfBtn) {
                pdfBtn.addEventListener('click', () => {
                    safeSendMessage({
                        action: "open_pdf",
                        reportData: rawData,
                        reportUrl: window.location.href
                    });
                });
            }

            const graphBtn = document.getElementById('inpageGraphBtn');
            if (graphBtn) {
                graphBtn.addEventListener('click', () => {
                    if (typeof openThreatGraph === 'function') {
                        openThreatGraph(rawData.grouped_iocs, "Sayfa Raporu");
                    } else {
                        console.error("TracePoint: openThreatGraph is not defined. Make sure threat_graph.js is loaded.");
                    }
                });
            }
            
            const inpageSplunk = document.getElementById('soc-ext-inpage-splunk');
            if (inpageSplunk) inpageSplunk.style.display = 'none';
            return;
        }

        if (rawData.ai_summary) {
            html += `
            <div class="soc-ext-card inpage-ai-card" id="inpage-ai-card" style="padding:0; margin-bottom:12px; overflow:hidden; border-radius:8px; border:1px solid rgba(99,102,241,0.25);">
                <div id="inpage-ai-header" style="display:flex; justify-content:space-between; align-items:center; cursor:pointer; user-select:none; padding:10px 14px; background:rgba(99,102,241,0.08);">
                    <span style="font-size:12px; font-weight:700; color:#a5b4fc; display:flex; align-items:center; gap:6px;">🧠 Yapay Zeka Özeti</span>
                    <svg id="inpage-ai-chevron" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transition:transform 0.25s cubic-bezier(0.4, 0, 0.2, 1); color:#94a3b8; transform:rotate(180deg);">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div id="inpage-ai-body" class="soc-ext-ai-body" style="display:block; padding:12px 14px; font-size:12px; line-height:1.6; background:rgba(15,23,42,0.4);">
                    ${rawData.ai_summary}
                </div>
            </div>`;
        }

        if (rawData.results && rawData.results.length > 0) {
            // 1. Verdict Summary Pill Bar (v2)
            html += `<div id="inpage-verdictBar" class="inpage-verdict-bar">${buildVerdictBarHtml(rawData.results, result.value, result.type)}</div>`;

            // 2. Sources Accordion Container (v2 Grid)
            html += `<div id="inpage-sources-container" style="margin-top:8px;"></div>`;
        } else {
            html += `<div class="soc-ext-card">Sonuç bulunamadı.</div>`;
        }

        body.innerHTML = html;

        // Yapay Zeka Özeti Akordiyon Dinleyicisi
        const inpageAiHeader = document.getElementById('inpage-ai-header');
        if (inpageAiHeader) {
            inpageAiHeader.addEventListener('click', () => {
                const aBody = document.getElementById('inpage-ai-body');
                const aChev = document.getElementById('inpage-ai-chevron');
                if (aBody) {
                    const isOpen = aBody.style.display !== 'none';
                    aBody.style.display = isOpen ? 'none' : 'block';
                    if (aChev) aChev.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
                }
            });
        }

        // İstihbarat Kaynakları Akordiyonunu Ekle (v2 Chip Grid)
        const sourcesContainer = document.getElementById('inpage-sources-container');
        if (sourcesContainer && rawData.results && rawData.results.length > 0) {
            sourcesContainer.appendChild(buildInPageSourcesAccordion(rawData.results, result.value, result.type));
        }

        if (result.splData) {
            renderInPageSplunkPanel(result.splData);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Sayfa İçi Panel İçin Splunk SPL İşlemleri ve Dinleyici
// ─────────────────────────────────────────────────────────────────

function renderInPageSplunkPanel(splData) {
    const statusBadge = document.getElementById('inpage-splunk-status-badge');
    const queriesList = document.getElementById('inpage-splunk-queries-list');
    if (!statusBadge || !queriesList) return;

    if (!splData || splData.status === "pending") {
        statusBadge.className = 'splunk-loading-badge';
        statusBadge.innerHTML = '<span class="splunk-spinner"></span> pending';
        queriesList.innerHTML = '';
        return;
    }

    if (splData.status === "error") {
        statusBadge.className = '';
        statusBadge.style.color = '#ef4444';
        statusBadge.innerHTML = 'error';
        queriesList.innerHTML = `<div class="spl-empty-msg" style="color:#ef4444; padding: 10px; font-size:12px;">⚠️ SPL üretilemedi: ${splData.error}</div>`;
        return;
    }

    if (splData.status === "completed") {
        statusBadge.className = 'splunk-ready-badge';
        const queries = splData.queries || [];
        statusBadge.innerHTML = `✓ Hazır (${queries.length})`;
        queriesList.innerHTML = '';

        if (queries.length === 0) {
            queriesList.innerHTML = '<div class="spl-empty-msg" style="padding: 10px; font-size:12px; color:#94a3b8;">Bu IOC tipi için Splunk sorgusu bulunamadı.</div>';
            return;
        }

        queries.forEach(q => {
            const card = buildInPageSplCard(q);
            if (card) queriesList.appendChild(card);
        });
    }
}

function buildInPageSplCard(q) {
    const div = document.createElement('div');
    div.className = 'spl-card';
    div.style.cssText = 'background:rgba(15,23,42,0.6); border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:10px 12px; margin-bottom:8px; transition:all 0.2s;';

    const color = q.color || '#6366f1';
    const label = q.label || q.index || 'Index';
    const description = q.description || '';
    let currentQuery = q.query || '';
    const note  = q.note || null;

    const uid = `inpage-spl-${q.index}-${Math.random().toString(36).substr(2, 9)}`;
    const copyBtnId = `${uid}-copy`;
    const runBtnId  = `${uid}-run`;
    const editBtnId = `${uid}-edit`;
    const queryPreId = `${uid}-pre`;
    const resultsId = `${uid}-results`;
    const bodyId    = `${uid}-body`;
    const chevronId = `${uid}-chev`;

    div.innerHTML = `
        <div class="spl-card-header" style="display:flex; justify-content:space-between; align-items:center; cursor:pointer; user-select:none; gap:6px;">
            <div style="display:flex; align-items:center; overflow:hidden; gap:6px; flex:1; min-width:0;">
                <span class="spl-index-title" style="font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex-shrink:0;">${escapeHtml(q.index || 'index')}</span>
                <span class="spl-status-badge" style="font-size:9.5px; font-weight:700; padding:2px 7px; border-radius:10px; border:1px solid ${color}; color:${color}; background:${color}15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:130px;" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
            </div>
            <div style="display:flex; gap:6px; align-items:center; flex-shrink:0;">
                <button class="spl-edit-btn" id="${editBtnId}" title="SPL sorgusunu düzenle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                </button>
                <button class="spl-run-btn" id="${runBtnId}" title="Splunk'ta çalıştır">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Çalıştır
                </button>
                <button class="spl-copy-btn" id="${copyBtnId}" title="SPL sorgusunu kopyala">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    Kopyala
                </button>
                <svg id="${chevronId}" class="spl-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-dim); transition:transform 0.2s; margin-left:2px;">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
        </div>
        <div id="${bodyId}" class="spl-card-body" style="display:none; margin-top:8px; padding-top:8px;">
            <div class="spl-description" style="font-size:10px; margin-bottom:6px; font-style:italic;">${label} — ${description}</div>
            <pre id="${queryPreId}" class="spl-query-code">${escapeHtml(currentQuery)}</pre>
            ${note ? `<div class="spl-note" style="font-size:10px; margin-bottom:6px;">⚠️ ${note}</div>` : ''}
            <div id="${resultsId}" style="display:none;"></div>
        </div>
    `;

    const cardHeader = div.querySelector('.spl-card-header');
    const cardBody   = div.querySelector(`#${bodyId}`);
    const cardChev   = div.querySelector(`#${chevronId}`);

    cardHeader.addEventListener('click', () => {
        const isOpen = cardBody.style.display !== 'none';
        cardBody.style.display = isOpen ? 'none' : 'block';
        if (cardChev) cardChev.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
    });

    const openBody = () => {
        if (cardBody.style.display === 'none') {
            cardBody.style.display = 'block';
            if (cardChev) cardChev.style.transform = 'rotate(180deg)';
        }
    };

    // ── Düzenle butonu ────────────────────────────────────────────
    const editBtn = div.querySelector(`#${editBtnId}`);
    if (editBtn) {
        const editHandler = (e) => {
            e.stopPropagation();
            openBody();

            const preEl = div.querySelector(`#${queryPreId}`);
            if (!preEl || preEl.tagName === 'TEXTAREA') return;

            const textarea = document.createElement('textarea');
            textarea.id = queryPreId;
            textarea.className = 'spl-query-editor';
            textarea.value = currentQuery;
            textarea.spellcheck = false;
            preEl.replaceWith(textarea);
            textarea.focus();

            editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Kaydet';
            editBtn.style.color = '#10b981';

            const saveHandler = (e2) => {
                e2.stopPropagation();
                currentQuery = textarea.value;
                const newPre = document.createElement('pre');
                newPre.id = queryPreId;
                newPre.className = 'spl-query-code';
                newPre.textContent = currentQuery;
                textarea.replaceWith(newPre);

                editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> Düzenle';
                editBtn.style.color = '';

                editBtn.removeEventListener('click', saveHandler);
                editBtn.addEventListener('click', editHandler);
            };

            editBtn.removeEventListener('click', editHandler);
            editBtn.addEventListener('click', saveHandler);
        };
        editBtn.addEventListener('click', editHandler);
    }

    // ── Kopyala butonu ────────────────────────────────────────────
    const copyBtn = div.querySelector(`#${copyBtnId}`);
    if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(currentQuery).then(() => {
                copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><polyline points="20 6 9 17 4 12"></polyline></svg> Kopyalandı';
                copyBtn.style.color = '#10b981';
                setTimeout(() => { 
                    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala';
                    copyBtn.style.color = '#94a3b8';
                }, 2000);
            }).catch(() => {
                copyBtn.innerHTML = '❌ Hata';
                setTimeout(() => { 
                    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:11px; height:11px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala'; 
                }, 2000);
            });
        });
    }

    // ── Çalıştır butonu ───────────────────────────────────────────
    const runBtn = div.querySelector(`#${runBtnId}`);
    if (runBtn) {
        runBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openBody();

            const resultsDiv = div.querySelector(`#${resultsId}`);
            if (!resultsDiv) return;

            runBtn.disabled = true;
            runBtn.style.opacity = '0.5';
            runBtn.style.cursor = 'wait';
            runBtn.textContent = '⏳...';
            runBtn.style.background = 'rgba(245,158,11,0.12)';
            runBtn.style.borderColor = 'rgba(245,158,11,0.4)';
            runBtn.style.color = '#fbbf24';

            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `
                <div style="margin-top:8px; border:1px solid rgba(99,102,241,0.15); border-radius:6px; overflow:hidden;">
                    <div style="text-align:center; padding:14px; color:#94a3b8; font-size:11px; display:flex; align-items:center; justify-content:center; gap:8px;">
                        <span class="splunk-spinner"></span> Splunk'ta sorgulanıyor...
                    </div>
                </div>`;

            safeSendMessage(
                { action: "execute_splunk", query: currentQuery },
                (response) => {
                    runBtn.disabled = false;
                    runBtn.style.opacity = '1';
                    runBtn.style.cursor = 'pointer';
                    runBtn.textContent = '⚡ Çalıştır';
                    runBtn.style.background = 'rgba(16,185,129,0.1)';
                    runBtn.style.borderColor = 'rgba(16,185,129,0.4)';
                    runBtn.style.color = '#6ee7b7';

                    if (!response) {
                        resultsDiv.innerHTML = `<div style="margin-top:8px; padding:10px 12px; font-size:11px; color:#f87171; background:rgba(239,68,68,0.06); border-left:3px solid #ef4444; border-radius:6px;">⛔ Yanıt alınamadı.</div>`;
                        return;
                    }

                    resultsDiv.innerHTML = buildInPageSplResultsHtml(response);
                }
            );
        });
    }

    return div;
}

/**
 * Sayfa içi panel için Splunk sonuçlarını HTML'e dönüştürür.
 */
function buildInPageSplResultsHtml(response) {
    const wrapStyle = 'margin-top:8px; border:1px solid rgba(99,102,241,0.15); border-radius:6px; overflow:hidden;';

    if (response.status === "not_configured") {
        return `<div style="${wrapStyle}">
            <div style="padding:10px 12px; font-size:11px; color:#fbbf24; background:rgba(245,158,11,0.08); border-left:3px solid #f59e0b; line-height:1.5;">⚠️ ${response.message}</div>
        </div>`;
    }

    if (response.status === "error") {
        return `<div style="${wrapStyle}">
            <div style="padding:10px 12px; font-size:11px; color:#f87171; background:rgba(239,68,68,0.06); border-left:3px solid #ef4444; line-height:1.5;">⛔ ${response.message}</div>
        </div>`;
    }

    if (response.status === "success") {
        const results = response.results || [];

        if (results.length === 0) {
            return `<div style="${wrapStyle}">
                <div style="text-align:center; padding:14px; font-size:11px; color:#94a3b8;">Sorgu başarıyla çalıştırıldı ancak sonuç bulunamadı.</div>
            </div>`;
        }

        const allKeys = new Set();
        results.forEach(row => {
            Object.keys(row).forEach(k => {
                if (!k.startsWith('_') || k === '_time' || k === '_raw') {
                    allKeys.add(k);
                }
            });
        });
        const columns = Array.from(allKeys);

        let headerHtml = columns.map(col => `<th style="background:rgba(99,102,241,0.12); padding:5px 8px; text-align:left; font-weight:700; color:#a5b4fc; white-space:nowrap; border-bottom:1px solid rgba(99,102,241,0.2); font-size:10px;">${escapeHtml(col)}</th>`).join('');
        let rowsHtml = results.map(row => {
            const cells = columns.map(col => `<td style="padding:4px 8px; border-bottom:1px solid rgba(255,255,255,0.04); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:10px;" title="${escapeHtml(String(row[col] || ''))}">${escapeHtml(String(row[col] || '-'))}</td>`).join('');
            return `<tr>${cells}</tr>`;
        }).join('');

        return `<div style="${wrapStyle}">
            <div style="padding:8px 12px; font-size:11px; font-weight:600; color:#6ee7b7; background:rgba(16,185,129,0.08); border-bottom:1px solid rgba(16,185,129,0.15);">✅ ${response.result_count} sonuç bulundu</div>
            <div style="overflow-x:auto; max-height:160px; overflow-y:auto;">
                <table style="width:100%; border-collapse:collapse; font-family:monospace; color:#cbd5e1;">
                    <thead><tr>${headerHtml}</tr></thead>
                    <tbody>${rowsHtml}</tbody>
                </table>
            </div>
        </div>`;
    }

    return `<div style="${wrapStyle}"><div style="padding:10px 12px; font-size:11px; color:#f87171;">Bilinmeyen yanıt formatı.</div></div>`;
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "spl_update_inpage") {
        if (request.splData) {
            renderInPageSplunkPanel(request.splData);
        }
    }
    
    if (request.action === "get_page_text") {
        let text = "";
        const article = document.querySelector('article');
        const main = document.querySelector('main');
        if (article) {
            text = article.innerText;
        } else if (main) {
            text = main.innerText;
        } else {
            text = document.body.innerText;
        }
        sendResponse({ text: text, url: window.location.href });
        return true;
    }

    if (request.action === "start_report_scan_from_page") {
        let text = "";
        const article = document.querySelector('article');
        const main = document.querySelector('main');
        if (article) text = article.innerText;
        else if (main) text = main.innerText;
        else text = document.body.innerText;

        showInPagePanel("Tüm Sayfa Raporu", "report");

        safeSendMessage({
            action: "scan_report",
            text: text,
            url: window.location.href
        }, function (response) {
            if (response) {
                updateInPagePanel(response);
            }
        });
        
        return true;
    }
});

// ─────────────────────────────────────────────────────────────────
// CVE DETAY ANALİZİ (NIST NVD) — Modal/Overlay Sistemi
// ─────────────────────────────────────────────────────────────────

// CVE cache: aynı CVE tekrar tıklandığında API'ye gitmez
const _cveCache = {};

/**
 * Sayfadaki tüm CVE numaralarını (CVE-YYYY-NNNNN) bulur ve
 * tıklanabilir link haline getirir.
 */
function highlightCVEsOnPage() {
    const CVE_REGEX = /\bCVE-\d{4}-\d{4,}\b/gi;
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode: function(node) {
                // Eklentimizin kendi elementlerini atla
                if (node.parentElement && (
                    node.parentElement.closest('#soc-ext-inpage-panel') ||
                    node.parentElement.closest('.soc-cve-modal') ||
                    node.parentElement.closest('.soc-cve-backdrop') ||
                    node.parentElement.closest('.soc-scanner-btn') ||
                    node.parentElement.tagName === 'SCRIPT' ||
                    node.parentElement.tagName === 'STYLE' ||
                    node.parentElement.tagName === 'TEXTAREA' ||
                    node.parentElement.tagName === 'INPUT' ||
                    node.parentElement.classList.contains('soc-cve-link')
                )) {
                    return NodeFilter.FILTER_REJECT;
                }
                return CVE_REGEX.test(node.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
            }
        }
    );

    const textNodes = [];
    let node;
    while (node = walker.nextNode()) {
        textNodes.push(node);
    }

    textNodes.forEach(textNode => {
        const text = textNode.nodeValue;
        // Reset regex lastIndex
        CVE_REGEX.lastIndex = 0;

        const fragment = document.createDocumentFragment();
        let lastIndex = 0;
        let match;

        while ((match = CVE_REGEX.exec(text)) !== null) {
            // Match öncesi düz metin
            if (match.index > lastIndex) {
                fragment.appendChild(document.createTextNode(text.substring(lastIndex, match.index)));
            }

            // CVE linkini oluştur
            const cveSpan = document.createElement('span');
            cveSpan.className = 'soc-cve-link';
            cveSpan.textContent = match[0];
            cveSpan.setAttribute('data-cve-id', match[0].toUpperCase());
            cveSpan.setAttribute('title', `${match[0]} detayları için tıkla`);
            cveSpan.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                openCveModal(this.getAttribute('data-cve-id'));
            });

            fragment.appendChild(cveSpan);
            lastIndex = match.index + match[0].length;
        }

        // Kalan metin
        if (lastIndex < text.length) {
            fragment.appendChild(document.createTextNode(text.substring(lastIndex)));
        }

        if (fragment.childNodes.length > 0) {
            textNode.parentNode.replaceChild(fragment, textNode);
        }
    });
}

/**
 * CVE Modal (Overlay) açar. Lazy loading ile API isteği atar.
 */
function openCveModal(cveId) {
    // Önceki modalı kapat
    closeCveModal();

    // Backdrop
    const backdrop = document.createElement('div');
    backdrop.className = 'soc-cve-backdrop';
    backdrop.id = 'soc-cve-backdrop';
    backdrop.addEventListener('click', closeCveModal);

    // Modal
    const modal = document.createElement('div');
    modal.className = 'soc-cve-modal';
    modal.id = 'soc-cve-modal';

    // Header
    modal.innerHTML = `
        <div class="soc-cve-modal-header">
            <div class="soc-cve-modal-header-left">
                <span class="soc-cve-modal-title">🛡️ ${escapeHtml(cveId)}</span>
                <span id="soc-cve-cvss-badge"></span>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
                <button id="soc-cve-theme-btn" class="soc-ext-theme-btn" title="Koyu / Açık Mod" aria-label="Tema Değiştir"></button>
                <span class="soc-cve-modal-close" id="soc-cve-modal-close">✕</span>
            </div>
        </div>
        <div class="soc-cve-modal-body" id="soc-cve-modal-body">
            <div class="soc-cve-loading">
                <div class="soc-ext-spinner"></div>
                <div class="soc-cve-loading-text">NIST NVD sorgulanıyor...</div>
            </div>
        </div>
    `;

    document.body.appendChild(backdrop);
    document.body.appendChild(modal);

    // Kapatma butonu
    document.getElementById('soc-cve-modal-close').addEventListener('click', closeCveModal);

    // Tema Değiştirme Butonu ve Senkronizasyon
    const cveThemeBtn = document.getElementById('soc-cve-theme-btn');
    if (cveThemeBtn) {
        cveThemeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const newTheme = currentInPageTheme === 'light' ? 'dark' : 'light';
            applyInPageTheme(newTheme);
            try {
                if (chrome.storage && chrome.storage.local) {
                    chrome.storage.local.set({ tracepoint_theme: newTheme });
                }
            } catch (err) {}
        });
    }

    // Modal açıldığında mevcut temayı uygula
    applyInPageTheme(currentInPageTheme);

    // ESC tuşu ile kapatma
    document.addEventListener('keydown', _cveEscHandler);

    // Cache kontrolü
    if (_cveCache[cveId]) {
        _renderCveData(_cveCache[cveId]);
        return;
    }

    // Backend'e istek at
    safeSendMessage({ action: "fetch_cve", cveId: cveId }, function(response) {
        if (!response) {
            _renderCveError(cveId, "Eklenti bağlantısı kopmuş olabilir. Sayfayı yenileyin.");
            return;
        }

        if (response.status === "success") {
            _cveCache[cveId] = response;
            _renderCveData(response);
        } else {
            _renderCveError(cveId, response.error || "CVE bilgisi alınamadı veya NIST sunucuları meşgul.");
        }
    });
}

function _cveEscHandler(e) {
    if (e.key === 'Escape') closeCveModal();
}

function closeCveModal() {
    const backdrop = document.getElementById('soc-cve-backdrop');
    const modal = document.getElementById('soc-cve-modal');
    if (backdrop) backdrop.remove();
    if (modal) modal.remove();
    document.removeEventListener('keydown', _cveEscHandler);
}

/**
 * CVSS skoruna göre renk sınıfı ve etiket döner.
 */
function _getCvssBadgeInfo(score, severity) {
    if (score === null || score === undefined) {
        return { cls: 'soc-cvss-none', label: 'N/A' };
    }
    const s = parseFloat(score);
    if (s >= 9.0) return { cls: 'soc-cvss-critical', label: `CRITICAL ${s.toFixed(1)}` };
    if (s >= 7.0) return { cls: 'soc-cvss-high', label: `HIGH ${s.toFixed(1)}` };
    if (s >= 4.0) return { cls: 'soc-cvss-medium', label: `MEDIUM ${s.toFixed(1)}` };
    if (s > 0) return { cls: 'soc-cvss-low', label: `LOW ${s.toFixed(1)}` };
    return { cls: 'soc-cvss-none', label: `NONE ${s.toFixed(1)}` };
}

/**
 * CVE verisi başarıyla geldiyse modal body'sini render eder.
 */
function _renderCveData(data) {
    const body = document.getElementById('soc-cve-modal-body');
    const badge = document.getElementById('soc-cve-cvss-badge');
    if (!body) return;

    // CVSS Badge
    const badgeInfo = _getCvssBadgeInfo(data.cvss_score, data.cvss_severity);
    if (badge) {
        badge.className = `soc-cvss-badge ${badgeInfo.cls}`;
        badge.textContent = badgeInfo.label;
    }

    let html = '';

    // Zafiyet Özeti
    html += `<div class="soc-cve-section-title">📋 Zafiyet Özeti</div>`;
    html += `<div class="soc-cve-description">${escapeHtml(data.description || 'Açıklama bulunamadı.')}</div>`;

    // Etkilenen Varlıklar
    if (data.affected_assets && data.affected_assets.length > 0) {
        html += `<div class="soc-cve-section-title">🎯 Etkilenen Varlıklar (${data.affected_assets.length})</div>`;
        html += `<div class="soc-cve-asset-cloud">`;
        data.affected_assets.forEach(asset => {
            html += `<span class="soc-cve-asset-tag">${escapeHtml(asset.vendor)} — ${escapeHtml(asset.product)}</span>`;
        });
        html += `</div>`;
    }

    // Referanslar
    if (data.references && data.references.length > 0) {
        html += `<div class="soc-cve-section-title">🔗 Referanslar</div>`;
        html += `<ul class="soc-cve-ref-list">`;
        data.references.forEach(ref => {
            html += `<li><a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer" class="soc-cve-ref-link">${escapeHtml(ref)}</a></li>`;
        });
        html += `</ul>`;
    }

    // Cortex XDR Entegrasyonu
    const cveId = escapeHtml(data.cve_id || '');
    const xqlQuery = `dataset = va_cves | filter name = "${cveId}" | fields affected_hosts_count`;
    
    html += `<div class="soc-cve-section-title" style="margin-top:20px; display:flex; align-items:center; gap:8px;">
        <svg viewBox="0 0 24 24" width="16" height="16" stroke="#00cec9" stroke-width="2" fill="none"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg>
        Cortex XDR Tehdit Avı
    </div>`;
    html += `
        <div class="soc-xdr-query-wrapper">
            <code id="soc-xdr-query-code">${xqlQuery}</code>
        </div>
        <div class="soc-xdr-actions">
            <button id="soc-xdr-run-btn">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                Çalıştır
            </button>
            <button id="soc-xdr-edit-btn">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                Düzenle
            </button>
        </div>
        <div id="soc-xdr-result"></div>
    `;

    // Meta Bilgi
    html += `<div class="soc-cve-meta">`;
    if (data.published) {
        html += `<span>📅 Yayınlanma: ${escapeHtml(data.published)}</span>`;
    }
    html += `<span>Kaynak: NIST NVD</span>`;
    html += `</div>`;

    body.innerHTML = html;

    // XDR Run Button Dinleyicisi
    const runBtn = document.getElementById('soc-xdr-run-btn');
    const editBtn = document.getElementById('soc-xdr-edit-btn');
    const codeBlock = document.getElementById('soc-xdr-query-code');
    const resultDiv = document.getElementById('soc-xdr-result');
    
    if (editBtn && codeBlock) {
        editBtn.addEventListener('click', () => {
            const isEditable = codeBlock.getAttribute('contenteditable') === 'true';
            if (isEditable) {
                // Kaydet modu
                codeBlock.setAttribute('contenteditable', 'false');
                codeBlock.style.backgroundColor = '';
                editBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                `;
            } else {
                // Düzenle modu
                codeBlock.setAttribute('contenteditable', 'true');
                codeBlock.style.backgroundColor = currentInPageTheme === 'light' ? '#e2e8f0' : '#1e293b';
                codeBlock.focus();
                editBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg>
                    Kaydet
                `;
            }
        });
    }

    if (runBtn) {
        runBtn.addEventListener('click', () => {
            const currentQuery = codeBlock ? codeBlock.innerText : xqlQuery;
            runBtn.innerHTML = `
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                XDR Sorgulanıyor...
            `;
            runBtn.disabled = true;
            runBtn.style.opacity = "0.7";
            resultDiv.innerHTML = "";

            safeSendMessage({ action: "execute_xdr", query: currentQuery }, function(response) {
                runBtn.disabled = false;
                runBtn.style.opacity = "1";
                runBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Çalıştır
                `;

                if (!response || response.status === "error") {
                    resultDiv.className = "soc-xdr-alert-danger";
                    resultDiv.innerHTML = `⚠️ Hata: ${escapeHtml(response?.error || 'XDR sunucusuna bağlanılamadı.')}`;
                } else {
                    const count = response.affected_hosts || 0;
                    if (count > 0) {
                        resultDiv.className = "soc-xdr-alert-danger";
                        resultDiv.innerHTML = `🚨 XDR Sonucu: Ortamınızda bu zafiyetten etkilenen <b>${count}</b> adet host (varlık) tespit edildi.`;
                    } else {
                        resultDiv.className = "soc-xdr-alert-success";
                        resultDiv.innerHTML = `✅ XDR Sonucu: Ortamınızda bu zafiyetten etkilenen host (varlık) bulunmamaktadır.`;
                    }
                }
            });
        });
    }
}

/**
 * Hata durumunda modal body'sine zarif hata mesajı yazar.
 */
function _renderCveError(cveId, errorMsg) {
    const body = document.getElementById('soc-cve-modal-body');
    if (!body) return;

    body.innerHTML = `
        <div style="text-align:center; padding:30px 20px;">
            <div style="font-size:36px; margin-bottom:12px;">⚠️</div>
            <div style="color:#f87171; font-size:14px; font-weight:600; margin-bottom:8px;">${escapeHtml(cveId)}</div>
            <div class="soc-cve-error-desc">${escapeHtml(errorMsg)}</div>
        </div>
    `;
}

// ── Sayfa yüklendiğinde CVE'leri otomatik olarak tıklanabilir yap ──
setTimeout(() => { highlightCVEsOnPage(); }, 1500);

// MutationObserver: Dinamik yüklenen içerikler için de CVE algıla
const _cveObserver = new MutationObserver((mutations) => {
    let hasNewContent = false;
    mutations.forEach(m => {
        if (m.addedNodes.length > 0) hasNewContent = true;
    });
    if (hasNewContent) {
        // Debounce: Çok fazla mutation olursa tek seferde çalışsın
        clearTimeout(window._cveObserverTimeout);
        window._cveObserverTimeout = setTimeout(() => { highlightCVEsOnPage(); }, 800);
    }
});
_cveObserver.observe(document.body, { childList: true, subtree: true });
