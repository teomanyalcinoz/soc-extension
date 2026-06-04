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
            <div class="soc-ext-close" id="soc-ext-close-btn">✕</div>
        </div>
        <div class="soc-ext-body">
            <div id="soc-ext-inpage-results">
                <div class="soc-ext-loading">
                    <div class="soc-ext-spinner"></div>
                    <div style="margin-top: 10px; font-family: monospace; color: #3b82f6; word-break: break-all;">${displayValue}</div>
                    <div style="margin-top: 10px;">${loadingText}</div>
                </div>
            </div>
            <div id="soc-ext-inpage-splunk" class="splunk-panel" style="display: block; margin-top: 15px;">
                <div class="splunk-panel-header">
                    <span class="splunk-panel-title">🔍 Splunk SPL Sorgusu</span>
                    <span id="inpage-splunk-status-badge" class="splunk-loading-badge">
                        <span class="splunk-spinner"></span> pending
                    </span>
                </div>
                <div id="inpage-splunk-queries-list"></div>
            </div>
        </div>
    `;
    document.body.appendChild(panel);
    document.getElementById('soc-ext-close-btn').addEventListener('click', () => panel.remove());
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
            <div class="soc-ext-close" id="soc-ext-close-btn">✕</div>
        </div>
        <div class="soc-ext-body">
            <div style="margin-bottom:8px;">
                <span style="font-size:11px; color:#94a3b8;">ORİJİNAL VERİ (${type.toUpperCase()})</span>
                <div style="background:#0f172a; border: 1px solid #334155; margin-top:4px; padding:6px; border-radius:4px; color:#64748b; font-family:monospace; word-break:break-all; max-height:80px; overflow-y:auto; font-size:11px;">${encodedText}</div>
            </div>
            <div>
                <span style="font-size:11px; color:#10b981;">ÇÖZÜLMÜŞ METİN (PLAINTEXT)</span>
                <div style="background:#0f172a; border: 1px solid #10b981; margin-top:4px; padding:6px; border-radius:4px; color:#e2e8f0; font-family:monospace; word-break:break-all; max-height:120px; overflow-y:auto; font-size:13px; line-height:1.4;">
                    ${decodedText.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
                </div>
            </div>
            ${iocHtml}
        </div>
    `;
    document.body.appendChild(panel);
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
            html += `<div class="soc-ext-ai" style="margin-bottom:12px;"><strong>Rapor Özeti:</strong><br><div style="margin-top:8px;">${rawData.summary || "Özet çıkarılamadı."}</div></div>`;
            html += `<div style="color:#cbd5e1; font-size:12px; margin-bottom:8px; font-weight:bold;">Taranan IOC Kategorileri (${rawData.total_iocs_found || 0} Adet)</div>`;
            
            if (rawData.grouped_iocs && rawData.grouped_iocs.length > 0) {
                const reportGroupsMap = {}; // Global store for click listeners
                window._reportGroupsMap = reportGroupsMap; // Ensure it's accessible

                rawData.grouped_iocs.forEach((group, index) => {
                    const gId = `accordion-group-${index}`;
                    reportGroupsMap[gId] = group;
                    const t = group.type.toUpperCase();
                    const cnt = group.count;
                    
                    let valuesHtml = `<div style="display:flex; flex-wrap:wrap; gap:4px; margin-top:6px;">`;
                    group.values.forEach(v => {
                        valuesHtml += `<span style="background:#1e293b; color:#cbd5e1; font-family:monospace; font-size:10px; padding:3px 6px; border-radius:4px; border:1px solid #334155;">${escapeHtml(v)}</span>`;
                    });
                    valuesHtml += `</div>`;
                    
                    let splHtml = `<div id="spl-container-${gId}"></div>`;

                    html += `
                    <div class="soc-ext-card" style="padding:0; margin-bottom:8px; overflow:hidden;">
                        <button class="accordion-header report-accordion-btn" data-target="${gId}" style="width:100%; display:flex; justify-content:space-between; align-items:center; background:#1e293b; color:#f8fafc; border:none; padding:10px; cursor:pointer; font-weight:bold; font-size:11px;">
                            <span>${t} (${cnt})</span>
                            <span style="color:#6366f1;">▼</span>
                        </button>
                        <div id="${gId}" style="display:none; padding:10px; background:#0f172a; border-top:1px solid #334155;">
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
                        
                        // Lazy loading SPL requests
                        if (!isExpanded && !content.hasAttribute('data-spl-loaded')) {
                            content.setAttribute('data-spl-loaded', 'true');
                            
                            const groupData = window._reportGroupsMap[targetId];
                            const splContainer = document.getElementById(`spl-container-${targetId}`);
                            
                            if (splContainer && groupData) {
                                splContainer.innerHTML = `<div style="color:#fbbf24; font-size:11px; margin-top:10px;"><span class="splunk-spinner"></span> SPL Sorguları üretiliyor...</div>`;
                                
                                safeSendMessage({
                                    action: "fetch_report_spl",
                                    iocType: groupData.type,
                                    values: groupData.values
                                }, (response) => {
                                    if (response && response.queries && response.queries.length > 0) {
                                        let splHtml = `<div style="margin-top:10px; width:100%;"><strong style="font-size:10px; color:#6366f1;">Toplu Splunk Sorguları:</strong><div style="display:flex; flex-direction:column; gap:4px; margin-top:4px;">`;
                                        response.queries.forEach(q => {
                                            splHtml += `<div style="background:#0f172a; padding:6px; border-radius:4px; font-family:monospace; font-size:10px; color:#a5b4fc; word-break:break-all;">[${q.index}] ${escapeHtml(q.query)}</div>`;
                                        });
                                        splHtml += `</div></div>`;
                                        splContainer.innerHTML = splHtml;
                                    } else {
                                        splContainer.innerHTML = `<div style="color:#ef4444; font-size:11px; margin-top:10px;">SPL üretilemedi veya bulunamadı.</div>`;
                                    }
                                });
                            }
                        }
                    }
                });
            });
            
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
            html += `<div class="soc-ext-ai"><strong>Yapay Zeka Özeti:</strong><br><div style="margin-top:8px;">${rawData.ai_summary}</div></div>`;
        }

        if (rawData.results && rawData.results.length > 0) {
            rawData.results.forEach(res => {
                let statusClass = 'soc-ext-unk';
                let statusText = 'Bilinmiyor';
                let detailText = res.error || 'Detay yok.';
                let srcName = res.source;
                let linksHtml = '';

                if (!res.success) {
                    statusText = 'Hata';
                } else if (srcName.includes('AbuseIPDB') && res.data && res.data.data) {
                    const score = res.data.data.abuseConfidenceScore || 0;
                    const country = res.data.data.countryCode || '';
                    const isp = res.data.data.isp || '';
                    const flag = country ? `<img src="https://flagcdn.com/16x12/${country.toLowerCase()}.png" style="vertical-align: middle; margin-right: 5px;" alt="${country}">` : '';
                    if (score > 70) { statusClass = 'soc-ext-mal'; statusText = 'Zararlı'; }
                    else if (score > 20) { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli'; }
                    else { statusClass = 'soc-ext-clean'; statusText = 'Temiz'; }
                    detailText = `${flag}<strong>${isp}</strong><br><br>Güven skoru: ${score}% Zararlı (Rapor: ${res.data.data.totalReports})`;
                    linksHtml = `<a href="https://www.abuseipdb.com/check/${result.value}" target="_blank" class="soc-ext-link">AbuseIPDB'de Gör</a>`;
                } else if (srcName.includes('VirusTotal') && res.data && res.data.data) {
                    const stats = res.data.data.attributes?.last_analysis_stats || {};
                    const mal = stats.malicious || 0;
                    if (mal > 4) { statusClass = 'soc-ext-mal'; statusText = 'Zararlı'; }
                    else if (mal > 0 || stats.suspicious > 0) { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli'; }
                    else { statusClass = 'soc-ext-clean'; statusText = 'Temiz'; }
                    detailText = `${mal} motor tarafından işaretlendi.`;

                    const rep = res.data.data.attributes?.reputation;
                    if (rep !== undefined) {
                        detailText += `<br><br><span style="font-size:10.5px; color:#94a3b8;">Topluluk İtibarı: <strong style="color:${rep < 0 ? '#ef4444' : (rep > 0 ? '#10b981' : '#f59e0b')}">${rep > 0 ? '+' + rep : rep}</strong></span>`;
                    }

                    let vtLink = '';
                    if (result.type === 'hash') vtLink = `https://www.virustotal.com/gui/file/${result.value}/detection`;
                    else if (result.type === 'ipv4') vtLink = `https://www.virustotal.com/gui/ip-address/${result.value}/detection`;
                    else if (result.type === 'url') vtLink = `https://www.virustotal.com/gui/search/${encodeURIComponent(result.value)}`;

                    if (vtLink) linksHtml = `<a href="${vtLink}" target="_blank" class="soc-ext-link">VT'de Gör</a>`;
                } else if (srcName.includes('AlienVault') && res.data && res.data.pulse_info) {
                    const count = res.data.pulse_info.count || 0;
                    if (count > 2) { statusClass = 'soc-ext-mal'; statusText = 'Zararlı'; }
                    else if (count > 0) { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli'; }
                    else { statusClass = 'soc-ext-clean'; statusText = 'Temiz'; }
                    detailText = `Topluluk tarafından ${count} pulse bulundu.`;
                    linksHtml = `<a href="https://otx.alienvault.com/indicator/${result.type === 'url' ? 'url/' : ''}${result.value}" target="_blank" class="soc-ext-link">OTX'de Gör</a>`;
                } else if (srcName.includes('MalwareBazaar')) {
                    if (res.data?.query_status === 'ok') {
                        statusClass = 'soc-ext-mal'; statusText = 'Zararlı';
                        detailText = 'MalwareBazaar ağında tehdit tespit edildi!';
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Bilinmiyor';
                        detailText = 'Kayıt bulunamadı / Temiz.';
                    }
                } else if (srcName.includes('Sucuri') && res.data) {
                    const blacklists = res.data.blacklists || [];
                    const warnings = res.data.warnings || [];
                    const siteInfo = res.data.site_info || {};
                    const isBlacklisted = Array.isArray(blacklists) ? blacklists.some(b => b.is_blacklisted) : false;

                    if (isBlacklisted) { statusClass = 'soc-ext-mal'; statusText = 'Zararlı'; }
                    else if (warnings.length > 0) { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli'; }
                    else { statusClass = 'soc-ext-clean'; statusText = 'Temiz'; }

                    detailText = isBlacklisted ? "Kara listede yer alıyor." : (warnings.length > 0 ? "Güvenlik uyarıları var." : "Temiz görünüyor.");

                    let extraInfo = [];
                    if (siteInfo.ip) extraInfo.push(`<b>IP:</b> ${siteInfo.ip}`);
                    if (siteInfo.server) extraInfo.push(`<b>Sunucu:</b> ${siteInfo.server}`);
                    if (siteInfo.application) extraInfo.push(`<b>CMS:</b> ${siteInfo.application}`);
                    if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;

                    linksHtml = `<a href="https://sitecheck.sucuri.net/results/${result.value}" target="_blank" class="soc-ext-link">Sucuri'de İncele</a>`;
                } else if (srcName.includes('URLhaus') && res.data) {
                    if (res.data.query_status === 'ok' && res.data.url_status !== 'offline') {
                        statusClass = 'soc-ext-mal'; statusText = 'Zararlı';
                        detailText = 'URLhaus ağında zararlı bağlantı olarak tespit edildi!';
                    } else if (res.data.query_status === 'ok' && res.data.url_status === 'offline') {
                        statusClass = 'soc-ext-susp'; statusText = 'Şüpheli';
                        detailText = 'Zararlı bağlantı (Şu an çevrimdışı).';
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Temiz';
                        detailText = 'Kayıt bulunamadı.';
                    }

                    const tags = res.data.tags || [];
                    if (tags.length > 0) {
                        detailText += `<br><br><span style="font-size:10.5px; color:#94a3b8;"><b>Etiketler:</b> ${tags.join(', ')}</span>`;
                    }
                } else if (srcName.includes('urlscan') && res.data) {
                    const total = res.data.total || 0;
                    const results = res.data.results || [];
                    if (total > 0) {
                        statusClass = 'soc-ext-susp'; statusText = 'İncelendi';
                        detailText = `Kayıtlarda ${total} kez analiz edilmiş.`;

                        if (results.length > 0 && results[0].page) {
                            const page = results[0].page;
                            let extraInfo = [];
                            if (page.ip) extraInfo.push(`<b>IP:</b> ${page.ip}`);
                            if (page.server) extraInfo.push(`<b>Sunucu:</b> ${page.server}`);
                            if (page.asn) extraInfo.push(`<b>ASN:</b> ${page.asn} (${page.asnname || ''})`);
                            if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
                        }

                        linksHtml = `<a href="https://urlscan.io/search/#domain:${result.value}" target="_blank" class="soc-ext-link">urlscan.io'da Gör</a>`;
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Bilinmiyor';
                        detailText = "Geçmiş analiz bulunamadı.";
                    }
                } else if (srcName.includes('USOM') && res.data) {
                    const count = res.data.totalCount || 0;
                    if (count > 0) {
                        statusClass = 'soc-ext-mal'; statusText = 'Zararlı';
                        const model = res.data.models[0];
                        const reason = model.desc || 'Zararlı Bağlantı';
                        detailText = `USOM Kara Listesinde Tehdit Algılandı: ${reason}`;

                        let extraInfo = [];
                        if (model.source) extraInfo.push(`<b>Kaynak:</b> ${model.source}`);
                        if (model.date) extraInfo.push(`<b>Eklenme Tarihi:</b> ${model.date.split(' ')[0]}`);
                        if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;

                        linksHtml = `<a href="https://www.usom.gov.tr/zararli-baglantilar" target="_blank" class="soc-ext-link">USOM'da Ara</a>`;
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Temiz';
                        detailText = "USOM kayıtlarında bulunamadı.";
                    }
                } else if (srcName.includes('HaveIBeenPwned')) {
                    if (res.breached) {
                        statusClass = 'soc-ext-mal'; statusText = 'Sızıntı Var';
                        let breachCount = Array.isArray(res.data) ? res.data.length : 0;
                        detailText = `E-Posta adresi <b>${breachCount}</b> farklı veri sızıntısında bulundu!`;
                        linksHtml = `<a href="https://haveibeenpwned.com/account/${result.value}" target="_blank" class="soc-ext-link">HIBP'de Analiz Et</a>`;
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Güvenli';
                        detailText = "Bilinen bir veri sızıntısı bulunamadı.";
                    }
                } else if (srcName.includes('Spamhaus') && res.data) {
                    const blacklisted = res.data.domain_blacklisted;
                    const dbl = res.data.dbl_listed;
                    if (blacklisted) {
                        statusClass = 'soc-ext-mal'; statusText = 'Kara Listede';
                        detailText = `Alan adı Spamhaus kara listesinde tespit edildi!`;
                        let extraInfo = [];
                        if (dbl) extraInfo.push('<b>DBL:</b> E-Posta spam kaynağı olarak işaretlendi');
                        if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
                        linksHtml = `<a href="https://check.spamhaus.org/" target="_blank" class="soc-ext-link">Spamhaus'ta Kontrol Et</a>`;
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Temiz';
                        detailText = 'Alan adı Spamhaus kara listesinde bulunamadı.';
                    }
                } else if ((srcName.includes('MX') || srcName.includes('DNS')) && res.data) {
                    const resolves = res.data.domain_resolves;
                    const mxValid = res.data.mx_valid;
                    if (!resolves) {
                        statusClass = 'soc-ext-mal'; statusText = 'Geçersiz Alan';
                        detailText = `<b>${res.data.domain}</b> alan adı DNS\'de çözümlenemiyor! Muhtemelen sahte veya geçersiz.`;
                    } else {
                        statusClass = 'soc-ext-clean'; statusText = 'Alan Adı Geçerli';
                        detailText = `<b>${res.data.domain}</b> alan adı geçerli ve DNS üzerinden ulaşılabilir.`;
                    }
                } else if (srcName.includes('emailrep.io') && res.data) {
                    const rep = res.data.reputation || 'unknown';
                    const susp = res.data.suspicious;
                    if (rep === 'high') { statusClass = 'soc-ext-clean'; statusText = 'Yüksek İtibar'; }
                    else if (rep === 'none' || susp) { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli İtibar'; }
                    else { statusClass = 'soc-ext-mal'; statusText = 'Kötü İtibar'; }

                    detailText = `E-Posta geçmişi ve itibar değerlendirmesi: ${rep}`;
                    let extraInfo = [];
                    if (res.data.details) {
                        if (res.data.details.blacklisted) extraInfo.push(`<b>Kara Liste:</b> Evet`);
                        if (res.data.details.malicious_activity) extraInfo.push(`<b>Zararlı Aktivite:</b> Tespit Edildi`);
                        if (res.data.details.credentials_leaked) extraInfo.push(`<b>Sızıntı:</b> Parola Çalınmış`);
                        if (res.data.details.days_since_domain_creation) extraInfo.push(`<b>Alan Adı Yaşı:</b> ${res.data.details.days_since_domain_creation} gün`);
                    }
                    if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
                } else if (srcName.includes('AbstractAPI') && res.data) {
                    const quality = res.data.quality_score || 0;
                    const deliverability = res.data.deliverability || 'UNKNOWN';

                    if (deliverability === 'DELIVERABLE' && quality > 0.5) { statusClass = 'soc-ext-clean'; statusText = 'Geçerli'; }
                    else if (deliverability === 'UNDELIVERABLE') { statusClass = 'soc-ext-mal'; statusText = 'Teslim Edilemez'; }
                    else { statusClass = 'soc-ext-susp'; statusText = 'Şüpheli / Riskli'; }

                    detailText = `Adres Kalite Skoru: %${Math.round(quality * 100)}`;

                    let extraInfo = [];
                    if (res.data.is_disposable_email && res.data.is_disposable_email.value) extraInfo.push('<b style="color:#ef4444;">10 Dakikalık/Tek Kullanımlık Posta</b>');
                    if (res.data.is_role_email && res.data.is_role_email.value) extraInfo.push('<b>Kurumsal/Rol (info/admin vb.)</b>');
                    if (res.data.is_free_email && res.data.is_free_email.value) extraInfo.push('<b>Ücretsiz Sağlayıcı</b>');
                    if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
                } else {
                    detailText = "Kayıt analiz edildi.";
                }

                html += `
                        <div class="soc-ext-card">
                    <div class="soc-ext-card-header">
                        <span class="soc-ext-src-name">${srcName}</span>
                        <span class="soc-ext-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="soc-ext-details">
                        ${detailText}
                        ${linksHtml ? `<div style="margin-top: 8px;">${linksHtml}</div>` : ''}
                    </div>
                </div>`;
            });
        } else {
            html += `<div class="soc-ext-card">Sonuç bulunamadı.</div>`;
        }

        body.innerHTML = html;
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
        statusBadge.innerHTML = 'completed';
        queriesList.innerHTML = '';

        const queries = splData.queries || [];
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

    div.innerHTML = `
        <div class="spl-card-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <div style="display:flex; align-items:center; overflow:hidden;">
                <span style="font-size:12px; font-weight:700; color:#f8fafc; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:120px;">${q.index || 'index'}</span>
                <span style="font-size:9px; font-weight:700; padding:2px 8px; border-radius:12px; margin-left:8px; border:1px solid ${color}; color:${color}; background:${color}15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:140px;">${q.label || 'Active'}</span>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-shrink:0;">
                <button id="${editBtnId}" title="SPL sorgusunu düzenle" style="font-size:11px; padding:4px 6px; cursor:pointer; background:transparent; border:none; color:#94a3b8; border-radius:4px; display:inline-flex; align-items:center; gap:4px; transition:color 0.2s;" onmouseover="this.style.color='#f8fafc'" onmouseout="this.style.color='#94a3b8'">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                </button>
                <button class="spl-run-btn" id="${runBtnId}" title="Splunk'ta çalıştır" style="font-size:11px; padding:4px 6px; cursor:pointer; background:transparent; border:none; color:#94a3b8; border-radius:4px; display:inline-flex; align-items:center; gap:4px; transition:color 0.2s;" onmouseover="this.style.color='#f8fafc'" onmouseout="this.style.color='#94a3b8'">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Çalıştır
                </button>
                <button class="spl-copy-btn" id="${copyBtnId}" title="SPL sorgusunu kopyala" style="font-size:11px; padding:4px 6px; cursor:pointer; background:transparent; border:none; color:#94a3b8; border-radius:4px; display:inline-flex; align-items:center; gap:4px; transition:color 0.2s;" onmouseover="this.style.color='#f8fafc'" onmouseout="this.style.color='#94a3b8'">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    Kopyala
                </button>
            </div>
        </div>
        <div class="spl-description" style="font-size:11px; color:#94a3b8; margin-bottom:8px; font-style:italic;">${label} — ${description}</div>
        <pre id="${queryPreId}" class="spl-query-code" style="font-family:monospace; font-size:10.5px; color:#c4b5fd; background:rgba(0,0,0,0.3); border:1px solid rgba(99,102,241,0.2); border-radius:5px; padding:8px 10px; white-space:pre-wrap; word-break:break-all; max-height:90px; overflow-y:auto; margin-bottom:8px;">${escapeHtml(currentQuery)}</pre>
        ${note ? `<div class="spl-note" style="font-size:10.5px; color:#f59e0b; background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.2); border-radius:4px; padding:5px 8px; margin-top:5px;">⚠️ ${note}</div>` : ''}
        <div id="${resultsId}" style="display:none;"></div>
    `;

    // ── Düzenle butonu ────────────────────────────────────────────
    const editBtn = div.querySelector(`#${editBtnId}`);
    if (editBtn) {
        const editHandler = () => {
            const preEl = div.querySelector(`#${queryPreId}`);
            if (!preEl || preEl.tagName === 'TEXTAREA') return;

            const textarea = document.createElement('textarea');
            textarea.id = queryPreId;
            textarea.value = currentQuery;
            textarea.spellcheck = false;
            textarea.style.cssText = 'font-family:monospace; font-size:10.5px; color:#c4b5fd; background:rgba(0,0,0,0.4); border:2px solid rgba(251,191,36,0.5); border-radius:5px; padding:8px 10px; white-space:pre-wrap; word-break:break-all; min-height:70px; max-height:140px; width:100%; box-sizing:border-box; resize:vertical; outline:none; margin-bottom:8px; line-height:1.5;';
            preEl.replaceWith(textarea);
            textarea.focus();

            editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Kaydet';
            editBtn.style.color = '#10b981';

            const saveHandler = () => {
                currentQuery = textarea.value;
                const newPre = document.createElement('pre');
                newPre.id = queryPreId;
                newPre.className = 'spl-query-code';
                newPre.style.cssText = 'font-family:monospace; font-size:10.5px; color:#c4b5fd; background:rgba(0,0,0,0.3); border:1px solid rgba(99,102,241,0.2); border-radius:5px; padding:8px 10px; white-space:pre-wrap; word-break:break-all; max-height:90px; overflow-y:auto; margin-bottom:8px;';
                newPre.textContent = currentQuery;
                textarea.replaceWith(newPre);

                editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> Düzenle';
                editBtn.style.color = '#94a3b8';

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
                copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><polyline points="20 6 9 17 4 12"></polyline></svg> Kopyalandı';
                copyBtn.style.color = '#10b981';
                setTimeout(() => { 
                    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala';
                    copyBtn.style.color = '#94a3b8';
                }, 2000);
            }).catch(() => {
                copyBtn.innerHTML = '❌ Hata';
                setTimeout(() => { 
                    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:12px; height:12px; stroke-width:1.5px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala'; 
                }, 2000);
            });
        });
    }

    // ── Çalıştır butonu ───────────────────────────────────────────
    const runBtn = div.querySelector(`#${runBtnId}`);
    if (runBtn) {
        runBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const resultsDiv = div.querySelector(`#${resultsId}`);
            if (!resultsDiv) return;

            runBtn.disabled = true;
            runBtn.style.opacity = '0.5';
            runBtn.style.cursor = 'wait';
            runBtn.textContent = '⏳ Çalışıyor...';
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
    return text
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
            <span class="soc-cve-modal-close" id="soc-cve-modal-close">✕</span>
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
        <div style="background:#0f172a; border:1px solid #334155; border-radius:8px; padding:12px; margin-bottom:12px;">
            <code id="soc-xdr-query-code" style="color:#00cec9; font-family:monospace; font-size:13px; word-break:break-all; outline:none;">${xqlQuery}</code>
        </div>
        <div style="display:flex; gap:10px; align-items:center; margin-bottom:16px;">
            <button id="soc-xdr-run-btn" style="background:#00cec9; color:#0f172a; border:none; border-radius:6px; padding:6px 14px; font-weight:600; font-size:13px; cursor:pointer; display:flex; align-items:center; gap:6px; transition:opacity 0.2s;">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                Çalıştır
            </button>
            <button id="soc-xdr-edit-btn" style="background:transparent; color:#94a3b8; border:1px solid #334155; border-radius:6px; padding:6px 14px; font-weight:500; font-size:13px; cursor:pointer; display:flex; align-items:center; gap:6px;">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                Düzenle
            </button>
        </div>
        <div id="soc-xdr-result" style="font-size:13px; font-weight:500; margin-bottom:16px;"></div>
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
                codeBlock.style.background = 'transparent';
                editBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                `;
            } else {
                // Düzenle modu
                codeBlock.setAttribute('contenteditable', 'true');
                codeBlock.style.background = '#1e293b'; // biraz daha açık bir ton
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
                    resultDiv.style.color = "#f87171"; // Red
                    resultDiv.innerHTML = `⚠️ Hata: ${escapeHtml(response?.error || 'XDR sunucusuna bağlanılamadı.')}`;
                } else {
                    const count = response.affected_hosts || 0;
                    if (count > 0) {
                        resultDiv.style.color = "#f87171"; // Red
                        resultDiv.innerHTML = `🚨 XDR Sonucu: Ortamınızda bu zafiyetten etkilenen <b>${count}</b> adet host (varlık) tespit edildi.`;
                    } else {
                        resultDiv.style.color = "#4ade80"; // Green
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
            <div style="color:#94a3b8; font-size:13px; line-height:1.5;">${escapeHtml(errorMsg)}</div>
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
