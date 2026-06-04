document.addEventListener('DOMContentLoaded', () => {
    fetchLatestResult();

    document.getElementById('refreshBtn').addEventListener('click', () => {
        fetchLatestResult();
    });

    const scanReportBtn = document.getElementById('scanReportBtn');
    if (scanReportBtn) {
        scanReportBtn.addEventListener('click', () => {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]) {
                    chrome.tabs.sendMessage(tabs[0].id, { action: "start_report_scan_from_page" });
                    window.close(); // Popup'ı kapatıp sayfa içi paneli görebilmek için
                }
            });
        });
    }
});

// Arka plandan (background.js) saklanan dinlenmiş son veriyi çeker
function fetchLatestResult() {
    chrome.runtime.sendMessage({ action: "get_latest_result" }, (response) => {
        renderUI(response);
    });
}

// Service worker canlı veri döndürdüğünde Popup'u günceller (Push Notification-like)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "update_popup") {
        renderUI(request.result);
    }
    // SPL sorguları hazır olunca paneli güncelle
    if (request.action === "spl_ready") {
        renderSplunkPanel(request.result ? request.result.splData : null);
    }
});


function renderUI(result) {
    const msgEmpty = document.getElementById('msgEmpty');
    const msgLoading = document.getElementById('msgLoading');
    const resultsWrapper = document.getElementById('resultsWrapper');

    // UI'ı Sıfırla
    if (!result) {
        msgEmpty.style.display = 'block';
        msgLoading.style.display = 'none';
        resultsWrapper.style.display = 'none';
        return;
    }

    // Hedef Paneli Güncelle
    document.getElementById('targetValue').textContent = result.value || "Bilinmiyor";
    const typeBadge = document.getElementById('typeBadge');
    typeBadge.textContent = (result.type || "TARGET").toUpperCase();

    if (result.status === "loading") {
        msgEmpty.style.display = 'none';
        msgLoading.style.display = 'block';
        resultsWrapper.style.display = 'none';
        return;
    }

    // Başarılı Analiz (API Yanıt Bitti)
    if (result.status === "success") {
        msgEmpty.style.display = 'none';
        msgLoading.style.display = 'none';
        resultsWrapper.style.display = 'block';

        const rawData = result.rawData; // Backend'den dönen data

        // RAPOR TARAMA (Yeni Özellik)
        if (result.type === 'report') {
            const aiSummaryBox = document.getElementById('aiSummaryBox');
            aiSummaryBox.innerHTML = rawData.summary || "Özet çıkarılamadı.";
            
            const sourcesList = document.getElementById('sourcesList');
            sourcesList.innerHTML = `<h4 style="margin-bottom:8px; color:#cbd5e1; font-size:12px;">Çıkarılan IOC'ler (${rawData.total_iocs_found || 0})</h4>`;
            
            if (rawData.iocs && rawData.iocs.length > 0) {
                rawData.iocs.forEach(ioc => {
                    const statusColor = ioc.status === "Malicious" ? "#ef4444" : (ioc.status === "Suspicious" ? "#f59e0b" : (ioc.status === "Error" ? "#94a3b8" : "#10b981"));
                    
                    const card = document.createElement('div');
                    card.className = 'src-card';
                    card.style.flexDirection = 'column';
                    card.style.alignItems = 'flex-start';
                    card.style.gap = '8px';
                    
                    let splHtml = '';
                    if (ioc.spl_queries && ioc.spl_queries.length > 0) {
                        splHtml = `<div style="margin-top:6px; width:100%;"><strong style="font-size:10px; color:#6366f1;">Splunk Sorguları:</strong><div style="display:flex; flex-direction:column; gap:4px; margin-top:4px;">`;
                        ioc.spl_queries.forEach(q => {
                            splHtml += `<div style="background:#0f172a; padding:4px 6px; border-radius:4px; font-family:monospace; font-size:10px; color:#a5b4fc; word-break:break-all;">[${q.index}] ${escapeHtml(q.query)}</div>`;
                        });
                        splHtml += `</div></div>`;
                    }
                    
                    card.innerHTML = `
                        <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                            <div>
                                <span class="badge" style="background:#334155;">${ioc.type.toUpperCase()}</span>
                                <span style="font-family:monospace; color:#e2e8f0; margin-left:6px; word-break:break-all; font-size:11px;">${escapeHtml(ioc.value)}</span>
                            </div>
                            <span style="font-size:10px; font-weight:bold; color:${statusColor};">${ioc.status}</span>
                        </div>
                        ${splHtml}
                    `;
                    sourcesList.appendChild(card);
                });
                
                // PDF İndir butonu
                const pdfBtn = document.createElement('button');
                pdfBtn.className = 'refresh-btn';
                pdfBtn.style.marginTop = '15px';
                pdfBtn.style.backgroundColor = '#10b981';
                pdfBtn.style.color = '#fff';
                pdfBtn.style.width = '100%';
                pdfBtn.innerText = '📄 PDF Raporu İndir';
                pdfBtn.addEventListener('click', () => {
                    chrome.storage.local.set({ reportData: rawData, reportUrl: document.getElementById('targetValue').textContent }, () => {
                        chrome.tabs.create({ url: chrome.runtime.getURL('report_export.html') });
                    });
                });
                sourcesList.appendChild(pdfBtn);
            } else {
                sourcesList.innerHTML += '<div class="src-card"><span class="src-text">IOC bulunamadı.</span></div>';
            }
            
            // Splunk panelini gizle (çünkü her IOC içinde gösteriyoruz)
            const splunkPanel = document.getElementById('splunkPanel');
            if (splunkPanel) splunkPanel.style.display = 'none';
            return;
        }

        // STANDART OSINT TARAMASI (Tekil)
        // 1. AI Summary
        const aiSummaryBox = document.getElementById('aiSummaryBox');
        if (rawData.ai_summary) {
            aiSummaryBox.innerHTML = rawData.ai_summary;
        } else {
            aiSummaryBox.innerHTML = "AI modeli şu anda bu hedefin özetini çıkartamadı.";
        }

        // 2. Çapraz Sorgu Kartları
        const sourcesList = document.getElementById('sourcesList');
        sourcesList.innerHTML = ''; // Temizle

        if (rawData.results && rawData.results.length > 0) {
            rawData.results.forEach(res => {
                const card = buildSourceCard(res);
                if (card) {
                    sourcesList.appendChild(card);
                }
            });
        } else {
            sourcesList.innerHTML = '<div class="src-card"><span class="src-text">Hiçbir entegrasyonda sonuç bulunamadı.</span></div>';
        }

        // 3. Splunk SPL Paneli
        const splunkPanel = document.getElementById('splunkPanel');
        if (splunkPanel) {
            splunkPanel.style.display = 'block';
            // SPL verisi hazırsa render et, yoksa loading göster
            renderSplunkPanel(result.splData || null);
        }

    } else if (result.status === "error") {
        msgEmpty.style.display = 'block';
        msgLoading.style.display = 'none';
        resultsWrapper.style.display = 'none';
        
        let errorMsg = result.error;
        if (!errorMsg && result.rawData && result.rawData.message) {
            errorMsg = result.rawData.message;
        }
        
        msgEmpty.innerHTML = `<span style="color:var(--accent-red)">⛔ Sunucu Hatası:</span><br><br>${errorMsg}`;
    }
}

// ─────────────────────────────────────────────────────────────────
// SPLUNK SPL PANELİ RENDER FONKSİYONLARI
// ─────────────────────────────────────────────────────────────────

/**
 * splData: { queries: [...], ioc_value, ioc_type } veya null (yükleniyor)
 */
function renderSplunkPanel(splData) {
    const loadingBadge = document.getElementById('splunkLoadingBadge');
    const readyBadge   = document.getElementById('splunkReadyBadge');
    const queriesList  = document.getElementById('splunkQueriesList');

    if (!loadingBadge || !readyBadge || !queriesList) return;

    // SPL henüz gelmedi → loading state
    if (!splData) {
        loadingBadge.style.display = 'flex';
        readyBadge.style.display   = 'none';
        queriesList.innerHTML = '';
        return;
    }

    // Hata durumu
    if (splData.error && (!splData.queries || splData.queries.length === 0)) {
        loadingBadge.style.display = 'none';
        readyBadge.style.display   = 'none';
        queriesList.innerHTML = `<div class="spl-empty-msg">⚠️ SPL üretilemedi: ${splData.error}</div>`;
        return;
    }

    // Sorgular hazır
    loadingBadge.style.display = 'none';
    readyBadge.style.display   = 'inline-block';
    queriesList.innerHTML = '';

    const queries = splData.queries || [];
    if (queries.length === 0) {
        queriesList.innerHTML = '<div class="spl-empty-msg">Bu IOC tipi için Splunk sorgusu bulunamadı.</div>';
        return;
    }

    queries.forEach(q => {
        const card = buildSplCard(q);
        if (card) queriesList.appendChild(card);
    });
}

function buildSplCard(q) {
    const div = document.createElement('div');
    div.className = 'spl-card';

    const color = q.color || '#6366f1';
    const label = q.label || q.index || 'Index';
    const description = q.description || '';
    let currentQuery = q.query || '';
    const note  = q.note || null;

    // Benzersiz ID'ler
    const uid = `spl-${q.index}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
    const copyBtnId = `${uid}-copy`;
    const runBtnId  = `${uid}-run`;
    const editBtnId = `${uid}-edit`;
    const queryPreId = `${uid}-pre`;
    const resultsId = `${uid}-results`;

    div.innerHTML = `
        <div class="spl-card-header">
            <div style="display:flex; align-items:center;">
                <span class="spl-index-title">${q.index || 'index'}</span>
                <span class="spl-status-badge" style="border: 1px solid ${color}; color: ${color}; background: ${color}15;">${q.label || 'Active'}</span>
            </div>
            <div style="display:flex; gap:12px; align-items:center;">
                <button class="spl-edit-btn" id="${editBtnId}" title="SPL sorgusunu düzenle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                </button>
                <button class="spl-run-btn" id="${runBtnId}" title="Splunk'ta çalıştır">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Çalıştır
                </button>
                <button class="spl-copy-btn" id="${copyBtnId}" title="SPL sorgusunu kopyala">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    Kopyala
                </button>
            </div>
        </div>
        <div class="spl-description">${label} — ${description}</div>
        <pre class="spl-query-code" id="${queryPreId}">${escapeHtml(currentQuery)}</pre>
        ${note ? `<div class="spl-note">⚠️ ${note}</div>` : ''}
        <div id="${resultsId}" style="display:none;"></div>
    `;

    // ── Düzenle butonu ────────────────────────────────────────────
    const editBtn = div.querySelector(`#${editBtnId}`);
    if (editBtn) {
        const editHandler = () => {
            const preEl = div.querySelector(`#${queryPreId}`);
            if (!preEl) return;

            // <pre> → <textarea> dönüşümü
            const textarea = document.createElement('textarea');
            textarea.id = queryPreId;
            textarea.className = 'spl-query-editor';
            textarea.value = currentQuery;
            textarea.spellcheck = false;
            preEl.replaceWith(textarea);
            textarea.focus();

            editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Kaydet';
            editBtn.classList.add('editing');

            // Kaydet handler
            const saveHandler = () => {
                currentQuery = textarea.value;
                const newPre = document.createElement('pre');
                newPre.id = queryPreId;
                newPre.className = 'spl-query-code';
                newPre.textContent = currentQuery;
                textarea.replaceWith(newPre);

                editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> Düzenle';
                editBtn.classList.remove('editing');
                
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
                copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="20 6 9 17 4 12"></polyline></svg> Kopyalandı';
                copyBtn.classList.add('copied');
                setTimeout(() => { 
                    copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala';
                    copyBtn.classList.remove('copied');
                }, 2000);
            }).catch(() => {
                copyBtn.textContent = '❌ Hata';
                setTimeout(() => { copyBtn.textContent = '📋 Kopyala'; }, 2000);
            });
        });
    }

    // ── Çalıştır butonu ───────────────────────────────────────────
    const runBtn = div.querySelector(`#${runBtnId}`);
    if (runBtn) {
        runBtn.addEventListener('click', () => {
            const resultsDiv = div.querySelector(`#${resultsId}`);
            if (!resultsDiv) return;

            runBtn.disabled = true;
            runBtn.classList.add('running');
            runBtn.textContent = '⏳ Çalışıyor...';

            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `
                <div class="spl-results-wrapper">
                    <div class="spl-results-loading">
                        <div class="splunk-spinner"></div> Splunk'ta sorgulanıyor...
                    </div>
                </div>`;

            chrome.runtime.sendMessage(
                { action: "execute_splunk", query: currentQuery },
                (response) => {
                    runBtn.disabled = false;
                    runBtn.classList.remove('running');
                    runBtn.textContent = '⚡ Çalıştır';

                    if (!response) {
                        resultsDiv.innerHTML = `<div class="spl-results-wrapper"><div class="spl-results-error">⛔ Yanıt alınamadı.</div></div>`;
                        return;
                    }

                    resultsDiv.innerHTML = buildSplResultsHtml(response);
                }
            );
        });
    }

    return div;
}

/**
 * Splunk sorgu sonuçlarını HTML'e dönüştüren yardımcı fonksiyon.
 * response = { status, message, results, result_count }
 */
function buildSplResultsHtml(response) {
    if (response.status === "not_configured") {
        return `<div class="spl-results-wrapper">
            <div class="spl-results-warn">⚠️ ${response.message}</div>
        </div>`;
    }

    if (response.status === "error") {
        return `<div class="spl-results-wrapper">
            <div class="spl-results-error">⛔ ${response.message}</div>
        </div>`;
    }

    if (response.status === "success") {
        const results = response.results || [];

        if (results.length === 0) {
            return `<div class="spl-results-wrapper">
                <div class="spl-results-empty">Sorgu başarıyla çalıştırıldı ancak sonuç bulunamadı.</div>
            </div>`;
        }

        // Dinamik olarak tüm sütun başlıklarını çıkar (iç alanlar "_" ile başlayanları filtreleme opsiyonel)
        const allKeys = new Set();
        results.forEach(row => {
            Object.keys(row).forEach(k => {
                // Splunk dahili alanlarını (_raw, _time hariç) gizle
                if (!k.startsWith('_') || k === '_time' || k === '_raw') {
                    allKeys.add(k);
                }
            });
        });
        const columns = Array.from(allKeys);

        // Tablo başlıkları
        let headerHtml = columns.map(col => `<th>${escapeHtml(col)}</th>`).join('');
        // Tablo satırları
        let rowsHtml = results.map(row => {
            const cells = columns.map(col => `<td title="${escapeHtml(String(row[col] || ''))}">${escapeHtml(String(row[col] || '-'))}</td>`).join('');
            return `<tr>${cells}</tr>`;
        }).join('');

        return `<div class="spl-results-wrapper">
            <div class="spl-results-success-header">✅ ${response.result_count} sonuç bulundu</div>
            <div class="spl-results-table-wrap">
                <table class="spl-results-table">
                    <thead><tr>${headerHtml}</tr></thead>
                    <tbody>${rowsHtml}</tbody>
                </table>
            </div>
        </div>`;
    }

    return `<div class="spl-results-wrapper"><div class="spl-results-error">Bilinmeyen yanıt formatı.</div></div>`;
}

/** HTML escape yardımcısı */
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Basit kart oluşturucu. (Ana UI'daki parse fonksiyonlarını özet olarak replika eder)
function buildSourceCard(res) {
    const div = document.createElement('div');
    div.className = 'src-card';

    const srcName = res.source; // VirusTotal, AbuseIPDB, vs..
    let statusClass = 'st-unknown';
    let statusText = 'Bilinmiyor';
    let detailText = '';
    let linksHtml = '';

    if (!res.success) {
        statusText = 'Hata / İzinsiz';
        detailText = res.error || 'API sorunu yaşandı.';
        statusClass = 'st-unknown'; // Gri kalsın
    } else if (srcName.includes('AbuseIPDB') && res.data && res.data.data) {
        const score = res.data.data.abuseConfidenceScore || 0;
        const country = res.data.data.countryCode || '';
        const isp = res.data.data.isp || '';
        const flag = country ? `<img src="https://flagcdn.com/16x12/${country.toLowerCase()}.png" style="vertical-align: middle; margin-right: 5px;" alt="${country}">` : '';

        if (score > 70) { statusClass = 'st-malicious'; statusText = 'Zararlı'; }
        else if (score > 20) { statusClass = 'st-suspicious'; statusText = 'Şüpheli'; }
        else { statusClass = 'st-clean'; statusText = 'Temiz'; }
        detailText = `${flag}<strong>${isp}</strong><br><br>Güven skoru: ${score}% Zararlı (Toplam: ${res.data.data.totalReports} rapor)`;
        linksHtml = `<a href="https://www.abuseipdb.com/check/${document.getElementById('targetValue').textContent}" target="_blank" class="soc-ext-link">AbuseIPDB'de Gör</a>`;
    } else if (srcName.includes('VirusTotal') && res.data && res.data.data) {
        const stats = res.data.data.attributes?.last_analysis_stats || {};
        const mal = stats.malicious || 0;
        if (mal > 4) { statusClass = 'st-malicious'; statusText = 'Zararlı'; }
        else if (mal > 0 || stats.suspicious > 0) { statusClass = 'st-suspicious'; statusText = 'Şüpheli'; }
        else { statusClass = 'st-clean'; statusText = 'Temiz'; }
        detailText = `${mal} güvenlik motoru tarafından işaretlendi.`;

        const rep = res.data.data.attributes?.reputation;
        if (rep !== undefined) {
            detailText += `<br><br><span style="font-size:10.5px; color:#94a3b8;">Topluluk İtibarı: <strong style="color:${rep < 0 ? '#ef4444' : (rep > 0 ? '#10b981' : '#f59e0b')}">${rep > 0 ? '+' + rep : rep}</strong></span>`;
        }

        let targetVal = document.getElementById('targetValue').textContent;
        let tCategory = document.getElementById('typeBadge').textContent;
        let vtLink = '';
        if (tCategory === 'HASH') vtLink = `https://www.virustotal.com/gui/file/${targetVal}/detection`;
        else if (tCategory === 'IPV4') vtLink = `https://www.virustotal.com/gui/ip-address/${targetVal}/detection`;
        else if (tCategory === 'URL') vtLink = `https://www.virustotal.com/gui/search/${encodeURIComponent(targetVal)}`;
        if (vtLink) linksHtml = `<a href="${vtLink}" target="_blank" class="soc-ext-link">VT'de Gör</a>`;

    } else if (srcName.includes('AlienVault') && res.data && res.data.pulse_info) {
        const count = res.data.pulse_info.count || 0;
        if (count > 2) { statusClass = 'st-malicious'; statusText = 'Zararlı'; }
        else if (count > 0) { statusClass = 'st-suspicious'; statusText = 'Şüpheli'; }
        else { statusClass = 'st-clean'; statusText = 'Temiz'; }
        detailText = `Topluluk tarafından ${count} pulse bulundu.`;
        linksHtml = `<a href="https://otx.alienvault.com/indicator/${document.getElementById('typeBadge').textContent.toLowerCase() === 'url' ? 'url/' : ''}${document.getElementById('targetValue').textContent}" target="_blank" class="soc-ext-link">OTX'de Gör</a>`;
    } else if (srcName.includes('MalwareBazaar')) {
        if (res.data?.query_status === 'ok') {
            statusClass = 'st-malicious'; statusText = 'Zararlı';
            detailText = 'MalwareBazaar tehdit ağında tespit edildi.';
        } else {
            statusClass = 'st-unknown'; statusText = 'Bilinmiyor';
            detailText = 'Kayıt bulunamadı.';
        }
    } else if (srcName.includes('Sucuri') && res.data) {
        const blacklists = res.data.blacklists || [];
        const warnings = res.data.warnings || [];
        const siteInfo = res.data.site_info || {};
        const isBlacklisted = Array.isArray(blacklists) ? blacklists.some(b => b.is_blacklisted) : false;

        if (isBlacklisted) { statusClass = 'st-malicious'; statusText = 'Zararlı'; }
        else if (warnings.length > 0) { statusClass = 'st-suspicious'; statusText = 'Şüpheli'; }
        else { statusClass = 'st-clean'; statusText = 'Temiz'; }

        detailText = isBlacklisted ? "Kara listede yer alıyor." : (warnings.length > 0 ? "Güvenlik uyarıları var." : "Temiz görünüyor.");

        let extraInfo = [];
        if (siteInfo.ip) extraInfo.push(`<b>IP:</b> ${siteInfo.ip}`);
        if (siteInfo.server) extraInfo.push(`<b>Sunucu:</b> ${siteInfo.server}`);
        if (siteInfo.application) extraInfo.push(`<b>CMS:</b> ${siteInfo.application}`);
        if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;

        linksHtml = `<a href="https://sitecheck.sucuri.net/results/${document.getElementById('targetValue').textContent}" target="_blank" class="soc-ext-link">Sucuri'de İncele</a>`;
    } else if (srcName.includes('URLhaus') && res.data) {
        if (res.data.query_status === 'ok' && res.data.url_status !== 'offline') {
            statusClass = 'st-malicious'; statusText = 'Zararlı';
            detailText = 'URLhaus ağında zararlı bağlantı olarak tespit edildi!';
        } else if (res.data.query_status === 'ok' && res.data.url_status === 'offline') {
            statusClass = 'st-suspicious'; statusText = 'Şüpheli';
            detailText = 'Zararlı bağlantı (Şu an çevrimdışı).';
        } else {
            statusClass = 'st-clean'; statusText = 'Temiz';
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
            statusClass = 'st-suspicious'; statusText = 'İncelendi';
            detailText = `Kayıtlarda ${total} kez analiz edilmiş.`;

            if (results.length > 0 && results[0].page) {
                const page = results[0].page;
                let extraInfo = [];
                if (page.ip) extraInfo.push(`<b>IP:</b> ${page.ip}`);
                if (page.server) extraInfo.push(`<b>Sunucu:</b> ${page.server}`);
                if (page.asn) extraInfo.push(`<b>ASN:</b> ${page.asn} (${page.asnname || ''})`);
                if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
            }
            linksHtml = `<a href="https://urlscan.io/search/#domain:${document.getElementById('targetValue').textContent}" target="_blank" class="soc-ext-link">urlscan.io'da Gör</a>`;
        } else {
            statusClass = 'st-clean'; statusText = 'Bilinmiyor';
            detailText = "Geçmiş analiz bulunamadı.";
        }
    } else if (srcName.includes('USOM') && res.data) {
        const count = res.data.totalCount || 0;
        if (count > 0) {
            statusClass = 'st-malicious'; statusText = 'Zararlı';
            const model = res.data.models[0];
            const reason = model.desc || 'Zararlı Bağlantı';
            detailText = `USOM (TR) Kara Listesinde Tehdit Algılandı: ${reason}`;
            let extraInfo = [];
            if (model.source) extraInfo.push(`<b>Kaynak:</b> ${model.source}`);
            if (model.date) extraInfo.push(`<b>Eklenme Tarihi:</b> ${model.date.split(' ')[0]}`);
            if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
            linksHtml = `<a href="https://www.usom.gov.tr/zararli-baglantilar" target="_blank" class="soc-ext-link">USOM'da Ara</a>`;
        } else {
            statusClass = 'st-clean'; statusText = 'Temiz';
            detailText = "USOM kayıtlarında bulunamadı.";
        }
    } else if (srcName.includes('HaveIBeenPwned')) {
        if (res.breached) {
            statusClass = 'st-malicious'; statusText = 'Sızıntı Var';
            let breachCount = Array.isArray(res.data) ? res.data.length : 0;
            detailText = `E-Posta adresi <b>${breachCount}</b> farklı veri sızıntısında bulundu!`;
            linksHtml = `<a href="https://haveibeenpwned.com/account/${document.getElementById('targetValue').textContent}" target="_blank" class="soc-ext-link">HIBP'de Analiz Et</a>`;
        } else {
            statusClass = 'st-clean'; statusText = 'Güvenli';
            detailText = "Bilinen bir veri sızıntısı bulunamadı.";
        }
    } else if (srcName.includes('Spamhaus') && res.data) {
        const blacklisted = res.data.domain_blacklisted;
        if (blacklisted) {
            statusClass = 'st-malicious'; statusText = 'Kara Listede';
            detailText = 'Alan adı Spamhaus kara listesinde tespit edildi!';
            let extraInfo = [];
            if (res.data.dbl_listed) extraInfo.push('<b>DBL:</b> Spam kaynağı olarak işaretlendi');
            if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
            linksHtml = `<a href="https://check.spamhaus.org/" target="_blank" class="soc-ext-link">Spamhaus'ta Kontrol Et</a>`;
        } else {
            statusClass = 'st-clean'; statusText = 'Temiz';
            detailText = 'Alan adı Spamhaus kara listesinde bulunamadı.';
        }
    } else if ((srcName.includes('MX') || srcName.includes('DNS')) && res.data) {
        const resolves = res.data.domain_resolves;
        if (!resolves) {
            statusClass = 'st-malicious'; statusText = 'Geçersiz Alan';
            detailText = `<b>${res.data.domain}</b> alan adı DNS\'de çözümlenemiyor. Muhtemelen sahte e-posta!`;
        } else {
            statusClass = 'st-clean'; statusText = 'Alan Adı Geçerli';
            detailText = `<b>${res.data.domain}</b> alan adı geçerli ve DNS erişilebilir.`;
        }
    } else if (srcName.includes('emailrep.io') && res.data) {
        const rep = res.data.reputation || 'unknown';
        const susp = res.data.suspicious;
        if (rep === 'high') { statusClass = 'st-clean'; statusText = 'Yüksek İtibar'; }
        else if (rep === 'none' || susp) { statusClass = 'st-suspicious'; statusText = 'Şüpheli İtibar'; }
        else { statusClass = 'st-malicious'; statusText = 'Kötü İtibar'; }

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

        if (deliverability === 'DELIVERABLE' && quality > 0.5) { statusClass = 'st-clean'; statusText = 'Geçerli'; }
        else if (deliverability === 'UNDELIVERABLE') { statusClass = 'st-malicious'; statusText = 'Teslim Edilemez'; }
        else { statusClass = 'st-suspicious'; statusText = 'Şüpheli / Riskli'; }

        detailText = `Adres Kalite Skoru: %${Math.round(quality * 100)}`;

        let extraInfo = [];
        if (res.data.is_disposable_email && res.data.is_disposable_email.value) extraInfo.push('<b style="color:#ef4444;">10 Dakikalık/Tek Kullanımlık Posta</b>');
        if (res.data.is_role_email && res.data.is_role_email.value) extraInfo.push('<b>Kurumsal/Rol (info/admin vb.)</b>');
        if (res.data.is_free_email && res.data.is_free_email.value) extraInfo.push('<b>Ücretsiz Sağlayıcı</b>');
        if (extraInfo.length > 0) detailText += `<br><br><span style="font-size:10.5px; color:#e2e8f0;">${extraInfo.join(' | ')}</span>`;
    } else if (srcName.includes('Pre-processor (De-Obfuscator)')) {
        const isObf = res.data?.is_obfuscated || false;
        const count = res.data?.decoded_blocks || 0;

        if (isObf) {
            statusClass = 'st-malicious'; statusText = 'Zararlı Özellik';
            detailText = `L3 İncelemesi yapıldı. Analiz öncesinde <b>${count} gizlenmiş (obfuscated) blok</b> tespit edildi ve çözüldü.`;
        } else {
            statusClass = 'st-clean'; statusText = 'Temiz';
            detailText = 'Script içerisinde bir gizleme/obfuscation tespit edilmedi.';
        }
    } else {
        // Fallback
        detailText = "Kayıt analiz edildi.";
    }

    div.innerHTML = `
        <div class="src-header">
            <span class="src-name">${srcName}</span>
            <span class="src-status ${statusClass}">${statusText}</span>
        </div>
        <div class="src-text">
            ${detailText}
            ${linksHtml ? `<div style="margin-top: 8px;">${linksHtml}</div>` : ''}
        </div>
    `;
    return div;
}
