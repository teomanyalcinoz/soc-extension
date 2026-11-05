// ══════════════════════════════════════════════════════════════════
// TracePoint v2.5 — Popup JS
// ══════════════════════════════════════════════════════════════════

const SUN_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
const MOON_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

function applyPopupTheme(theme) {
    const btn = document.getElementById('themeToggleBtn');
    if (theme === 'light') {
        document.body.classList.add('light-theme');
        if (btn) {
            btn.innerHTML = MOON_ICON;
            btn.title = "Koyu Moda Geç";
        }
    } else {
        document.body.classList.remove('light-theme');
        if (btn) {
            btn.innerHTML = SUN_ICON;
            btn.title = "Açık Moda Geç";
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Tema Tercihini Yükle
    chrome.storage.local.get(['tracepoint_theme'], (res) => {
        applyPopupTheme(res.tracepoint_theme || 'dark');
    });

    const themeBtn = document.getElementById('themeToggleBtn');
    if (themeBtn) {
        themeBtn.addEventListener('click', () => {
            const isCurrentlyLight = document.body.classList.contains('light-theme');
            const newTheme = isCurrentlyLight ? 'dark' : 'light';
            applyPopupTheme(newTheme);
            chrome.storage.local.set({ tracepoint_theme: newTheme });
        });
    }

    // Storage Değişikliklerini Dinle (diğer ekranda değişirse anında güncelle)
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.tracepoint_theme) {
            applyPopupTheme(changes.tracepoint_theme.newValue);
        }
    });

    fetchLatestResult();

    document.getElementById('refreshBtn').addEventListener('click', fetchLatestResult);

    const scanReportBtn = document.getElementById('scanReportBtn');
    if (scanReportBtn) {
        scanReportBtn.addEventListener('click', () => {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]) {
                    chrome.tabs.sendMessage(tabs[0].id, { action: "start_report_scan_from_page" });
                    window.close();
                }
            });
        });
    }
    // AI Summary Akordiyon Toggle
    const aiBoxHeader = document.getElementById('aiBoxHeader');
    if (aiBoxHeader) {
        aiBoxHeader.addEventListener('click', () => {
            const aiBox = document.getElementById('aiBox');
            const aiBoxBody = document.getElementById('aiBoxBody');
            if (aiBoxBody) {
                const isOpen = aiBoxBody.style.display !== 'none';
                aiBoxBody.style.display = isOpen ? 'none' : 'block';
                if (aiBox) aiBox.classList.toggle('is-collapsed', isOpen);
            }
        });
    }

    // Splunk Panel Akordiyon Toggle
    const splunkPanelHeader = document.getElementById('splunkPanelHeader');
    if (splunkPanelHeader) {
        splunkPanelHeader.addEventListener('click', () => {
            const queriesList = document.getElementById('splunkQueriesList');
            if (queriesList) {
                const isOpen = queriesList.style.display !== 'none';
                queriesList.style.display = isOpen ? 'none' : 'block';
                splunkPanelHeader.classList.toggle('is-open', !isOpen);
            }
        });
    }
});

function fetchLatestResult() {
    chrome.runtime.sendMessage({ action: "get_latest_result" }, (response) => {
        renderUI(response);
    });
}

// Background'dan gelen push güncellemelerini dinle
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "update_popup") renderUI(request.result);
    if (request.action === "spl_ready") renderSplunkPanel(request.result?.splData || null);
});


// ══════════════════════════════════════════════════════════════════
// ANA UI RENDER FONKSİYONU
// ══════════════════════════════════════════════════════════════════
function renderUI(result) {
    const msgEmpty      = document.getElementById('msgEmpty');
    const msgLoading    = document.getElementById('msgLoading');
    const resultsWrapper = document.getElementById('resultsWrapper');

    if (!result) {
        msgEmpty.style.display      = 'block';
        msgLoading.style.display    = 'none';
        resultsWrapper.style.display = 'none';
        return;
    }

    document.getElementById('targetValue').textContent = result.value || 'Bilinmiyor';
    document.getElementById('typeBadge').textContent   = (result.type || 'TARGET').toUpperCase();

    if (result.status === 'loading') {
        msgEmpty.style.display      = 'none';
        msgLoading.style.display    = 'block';
        resultsWrapper.style.display = 'none';
        return;
    }

    if (result.status === 'success') {
        msgEmpty.style.display      = 'none';
        msgLoading.style.display    = 'none';
        resultsWrapper.style.display = 'block';

        // AI özetini varsayılan olarak açık (okunur) getir
        const aiBox = document.getElementById('aiBox');
        const aiBoxBody = document.getElementById('aiBoxBody');
        if (aiBox) aiBox.classList.remove('is-collapsed');
        if (aiBoxBody) aiBoxBody.style.display = 'block';

        const rawData = result.rawData;

        // ── RAPOR TARAMA MODU ────────────────────────────────────
        if (result.type === 'report') {
            // v2 elemanlarını gizle
            document.getElementById('verdictBar').style.display        = 'none';
            const acc = document.getElementById('sourcesAccordion');
            acc.innerHTML = '';
            acc.style.display = 'none';

            document.getElementById('aiSummaryBox').innerHTML = rawData.summary || 'Özet çıkarılamadı.';

            const sourcesList = document.getElementById('sourcesList');
            sourcesList.style.display = 'block';
            sourcesList.innerHTML     = `<h4 class="report-section-title">Çıkarılan IOC Kategorileri (${rawData.total_iocs_found || 0} Adet)</h4>`;

            const hasGrouped = rawData.grouped_iocs && rawData.grouped_iocs.length > 0;
            const hasFlat    = rawData.iocs && rawData.iocs.length > 0;

            if (hasGrouped) {
                rawData.grouped_iocs.forEach((group, index) => {
                    const gId = `popup-report-group-${index}`;
                    const t   = (group.type || 'IOC').toUpperCase();
                    const cnt = group.count || (group.values ? group.values.length : 0);

                    const card = document.createElement('div');
                    card.className = 'src-card report-group-card';
                    card.style.cssText = 'padding:0; margin-bottom:8px; overflow:hidden; border-radius:8px; display:block;';

                    // Kategori Butonu
                    const btn = document.createElement('button');
                    btn.className = 'report-accordion-btn';
                    btn.innerHTML = `
                        <span style="display:flex; align-items:center; gap:8px;">
                            <span class="badge report-type-badge">${escapeHtml(t)}</span>
                            <span class="report-count-label">(${cnt} Adet)</span>
                        </span>
                        <span class="acc-chevron" style="color:#6366f1; transition:transform 0.2s; font-size:11px;">▼</span>
                    `;

                    // Kategori İçeriği (Varsayılan kapalı)
                    const body = document.createElement('div');
                    body.id = gId;
                    body.className = 'report-accordion-body';
                    body.style.display = 'none';

                    let valuesHtml = `<div class="report-values-grid">`;
                    (group.values || []).forEach(v => {
                        valuesHtml += `<span class="report-ioc-pill" title="${escapeHtml(v)}">${escapeHtml(v)}</span>`;
                    });
                    valuesHtml += `</div>`;

                    const splContainer = document.createElement('div');
                    splContainer.id = `spl-container-${gId}`;
                    splContainer.className = 'report-spl-container';

                    body.innerHTML = valuesHtml;
                    body.appendChild(splContainer);

                    let splLoaded = false;
                    btn.addEventListener('click', () => {
                        const isExpanded = body.style.display === 'block';
                        body.style.display = isExpanded ? 'none' : 'block';
                        btn.classList.toggle('is-expanded', !isExpanded);
                        const chevron = btn.querySelector('.acc-chevron');
                        if (chevron) chevron.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';

                        // SPL sorgularını lazy-load ile getir
                        if (!isExpanded && !splLoaded) {
                            splLoaded = true;
                            splContainer.innerHTML = `<div class="report-spl-loading"><span class="splunk-spinner"></span> SPL Sorguları üretiliyor...</div>`;
                            chrome.runtime.sendMessage({
                                action: "fetch_report_spl",
                                iocType: group.type,
                                values: group.values
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
                    });

                    card.appendChild(btn);
                    card.appendChild(body);
                    sourcesList.appendChild(card);
                });

                // PDF İndir Butonu
                const pdfBtn = document.createElement('button');
                pdfBtn.className = 'refresh-btn';
                pdfBtn.style.cssText = 'margin-top:15px;background:#10b981;color:#fff;width:100%;';
                pdfBtn.innerText = '📄 PDF Raporu İndir';
                pdfBtn.addEventListener('click', () => {
                    chrome.storage.local.set(
                        { reportData: rawData, reportUrl: document.getElementById('targetValue').textContent },
                        () => { chrome.tabs.create({ url: chrome.runtime.getURL('report_export.html') }); }
                    );
                });
                sourcesList.appendChild(pdfBtn);

            } else if (hasFlat) {
                // Flat iocs listesi (fallback)
                rawData.iocs.forEach(ioc => {
                    const statusColor = ioc.status === 'Malicious' ? '#ef4444'
                        : ioc.status === 'Suspicious' ? '#f59e0b'
                        : ioc.status === 'Error'      ? '#94a3b8'
                        : '#10b981';

                    const card = document.createElement('div');
                    card.className = 'src-card report-flat-card';
                    card.style.cssText = 'flex-direction:column;align-items:flex-start;gap:8px;';

                    card.innerHTML = `
                        <div style="display:flex;justify-content:space-between;width:100%;align-items:center;">
                            <div>
                                <span class="badge report-type-badge">${(ioc.type || 'IOC').toUpperCase()}</span>
                                <span class="report-ioc-flat-value">${escapeHtml(ioc.value)}</span>
                            </div>
                            <span style="font-size:10px;font-weight:bold;color:${statusColor};">${ioc.status || 'Clean'}</span>
                        </div>
                    `;
                    sourcesList.appendChild(card);
                });
            } else {
                sourcesList.innerHTML += '<div class="src-card"><span class="src-text">IOC bulunamadı.</span></div>';
            }

            const splunkPanel = document.getElementById('splunkPanel');
            if (splunkPanel) splunkPanel.style.display = 'none';
            return;
        }

        // ── STANDART OSINT MODU ───────────────────────────────────
        document.getElementById('sourcesList').innerHTML   = '';
        document.getElementById('sourcesList').style.display = 'none';

        // 1. AI Özeti
        document.getElementById('aiSummaryBox').innerHTML =
            rawData.ai_summary || 'AI modeli şu anda bu hedefin özetini çıkartamadı.';

        const verdictBar       = document.getElementById('verdictBar');
        const accordionContainer = document.getElementById('sourcesAccordion');

        if (rawData.results && rawData.results.length > 0) {
            // 2. Verdict Pill Bar
            verdictBar.innerHTML    = buildVerdictBarHtml(rawData.results);
            verdictBar.style.display = 'flex';

            // 3. Sources Accordion
            accordionContainer.innerHTML = '';
            accordionContainer.appendChild(buildSourcesAccordion(rawData.results));
            accordionContainer.style.display = 'block';
        } else {
            verdictBar.style.display = 'none';
            accordionContainer.innerHTML = '<div class="src-card"><span class="src-text">Hiçbir entegrasyonda sonuç bulunamadı.</span></div>';
            accordionContainer.style.display = 'block';
        }

        // 4. Splunk SPL Paneli
        const splunkPanel = document.getElementById('splunkPanel');
        if (splunkPanel) {
            splunkPanel.style.display = 'block';
            renderSplunkPanel(result.splData || null);
        }

    } else if (result.status === 'error') {
        msgEmpty.style.display      = 'block';
        msgLoading.style.display    = 'none';
        resultsWrapper.style.display = 'none';
        const errorMsg = result.error || result.rawData?.message || 'Bilinmeyen hata';
        msgEmpty.innerHTML = `<span style="color:var(--accent-red)">⛔ Sunucu Hatası:</span><br><br>${errorMsg}`;
    }
}


// ══════════════════════════════════════════════════════════════════
// SPLUNK PANELİ (Akordiyon & Kompakt Sorgu Kartları)
// ══════════════════════════════════════════════════════════════════
function renderSplunkPanel(splData) {
    const loadingBadge = document.getElementById('splunkLoadingBadge');
    const readyBadge   = document.getElementById('splunkReadyBadge');
    const queriesList  = document.getElementById('splunkQueriesList');
    if (!loadingBadge || !readyBadge || !queriesList) return;

    if (!splData) {
        loadingBadge.style.display = 'flex';
        readyBadge.style.display   = 'none';
        queriesList.innerHTML = '';
        return;
    }
    if (splData.error && (!splData.queries || splData.queries.length === 0)) {
        loadingBadge.style.display = 'none';
        readyBadge.style.display   = 'none';
        queriesList.innerHTML = `<div class="spl-empty-msg" style="padding:10px; color:#f87171; font-size:11px;">⚠️ SPL üretilemedi: ${splData.error}</div>`;
        return;
    }
    loadingBadge.style.display = 'none';
    readyBadge.style.display   = 'inline-block';
    queriesList.innerHTML = '';
    const queries = splData.queries || [];
    readyBadge.textContent = `✓ Hazır (${queries.length})`;

    if (queries.length === 0) {
        queriesList.innerHTML = '<div class="spl-empty-msg" style="padding:10px; color:#94a3b8; font-size:11px;">Bu IOC tipi için Splunk sorgusu bulunamadı.</div>';
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
    div.style.cssText = 'background:rgba(15,23,42,0.5); border:1px solid rgba(255,255,255,0.07); border-radius:8px; padding:10px 12px; margin-bottom:8px; transition:all 0.2s;';

    const color       = q.color || '#6366f1';
    const label       = q.label || q.index || 'Index';
    const description = q.description || '';
    let currentQuery  = q.query || '';
    const note        = q.note || null;

    const uid        = `spl-${q.index}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
    const copyBtnId  = `${uid}-copy`;
    const runBtnId   = `${uid}-run`;
    const editBtnId  = `${uid}-edit`;
    const queryPreId = `${uid}-pre`;
    const resultsId  = `${uid}-results`;
    const bodyId     = `${uid}-body`;
    const chevronId  = `${uid}-chevron`;

    div.innerHTML = `
        <div class="spl-card-header" style="display:flex; align-items:center; justify-content:space-between; cursor:pointer; user-select:none;">
            <div style="display:flex; align-items:center; gap:6px;">
                <span class="spl-index-title" style="font-size:12px; font-weight:700; text-transform:uppercase;">${escapeHtml(q.index || 'index')}</span>
                <span class="spl-status-badge" style="font-size:9.5px; border:1px solid ${color}; color:${color}; background:${color}15; padding:2px 7px; border-radius:10px; font-weight:700;">${escapeHtml(label)}</span>
            </div>
            <div style="display:flex; gap:6px; align-items:center;">
                <button class="spl-edit-btn" id="${editBtnId}" title="SPL sorgusunu düzenle" style="padding:3px 6px; font-size:10px;">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    Düzenle
                </button>
                <button class="spl-run-btn" id="${runBtnId}" title="Splunk'ta çalıştır" style="padding:3px 6px; font-size:10px;">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                    Çalıştır
                </button>
                <button class="spl-copy-btn" id="${copyBtnId}" title="SPL sorgusunu kopyala" style="padding:3px 6px; font-size:10px;">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    Kopyala
                </button>
                <svg id="${chevronId}" class="spl-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="transition:transform 0.2s; margin-left:4px;">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
        </div>
        <div id="${bodyId}" class="spl-card-body" style="display:none; margin-top:10px; padding-top:8px;">
            ${description ? `<div class="spl-description" style="display:block; font-size:10px; margin-bottom:6px;">${escapeHtml(description)}</div>` : ''}
            <pre class="spl-query-code" id="${queryPreId}" style="margin-bottom:6px; font-size:10px;">${escapeHtml(currentQuery)}</pre>
            ${note ? `<div class="spl-note" style="font-size:10px; color:#f59e0b; margin-bottom:6px;">⚠️ ${escapeHtml(note)}</div>` : ''}
            <div id="${resultsId}" style="display:none;"></div>
        </div>
    `;

    const cardHeader = div.querySelector('.spl-card-header');
    const cardBody   = div.querySelector(`#${bodyId}`);
    const cardChev   = div.querySelector(`#${chevronId}`);

    // Kart akordiyon açma/kapatma (header tıklanınca)
    cardHeader.addEventListener('click', () => {
        const isOpen = cardBody.style.display !== 'none';
        cardBody.style.display = isOpen ? 'none' : 'block';
        if (cardChev) cardChev.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
    });

    const openCardBody = () => {
        if (cardBody.style.display === 'none') {
            cardBody.style.display = 'block';
            if (cardChev) cardChev.style.transform = 'rotate(180deg)';
        }
    };

    // Düzenle
    const editBtn = div.querySelector(`#${editBtnId}`);
    if (editBtn) {
        const editHandler = (e) => {
            e.stopPropagation();
            openCardBody();

            const preEl = div.querySelector(`#${queryPreId}`);
            if (!preEl) return;
            const textarea = document.createElement('textarea');
            textarea.id = queryPreId;
            textarea.className = 'spl-query-editor';
            textarea.value = currentQuery;
            textarea.spellcheck = false;
            textarea.style.cssText = 'width: 100% !important; min-height: 85px !important; box-sizing: border-box !important; background: #0b132b !important; color: #00cec9 !important; border: 1.5px solid #00cec9 !important; border-radius: 6px !important; padding: 10px 12px !important; font-family: Consolas, monospace !important; font-size: 11px !important; line-height: 1.5 !important; resize: vertical !important; display: block !important; margin: 8px 0 !important; outline: none !important;';
            preEl.replaceWith(textarea);
            textarea.focus();
            editBtn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Kaydet';
            editBtn.classList.add('editing');
            const saveHandler = (e2) => {
                e2.stopPropagation();
                currentQuery = textarea.value;
                const newPre = document.createElement('pre');
                newPre.id = queryPreId;
                newPre.className = 'spl-query-code';
                newPre.style.fontSize = '10px';
                newPre.textContent = currentQuery;
                textarea.replaceWith(newPre);
                editBtn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg> Düzenle';
                editBtn.classList.remove('editing');
                editBtn.removeEventListener('click', saveHandler);
                editBtn.addEventListener('click', editHandler);
            };
            editBtn.removeEventListener('click', editHandler);
            editBtn.addEventListener('click', saveHandler);
        };
        editBtn.addEventListener('click', editHandler);
    }

    // Kopyala
    const copyBtn = div.querySelector(`#${copyBtnId}`);
    if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(currentQuery).then(() => {
                copyBtn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="20 6 9 17 4 12"></polyline></svg> Kopyalandı';
                copyBtn.classList.add('copied');
                setTimeout(() => {
                    copyBtn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Kopyala';
                    copyBtn.classList.remove('copied');
                }, 2000);
            }).catch(() => {
                copyBtn.textContent = '❌ Hata';
                setTimeout(() => { copyBtn.textContent = '📋 Kopyala'; }, 2000);
            });
        });
    }

    // Çalıştır
    const runBtn = div.querySelector(`#${runBtnId}`);
    if (runBtn) {
        runBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openCardBody();

            const resultsDiv = div.querySelector(`#${resultsId}`);
            if (!resultsDiv) return;
            runBtn.disabled = true;
            runBtn.classList.add('running');
            runBtn.textContent = '⏳...';
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `<div class="spl-results-wrapper"><div class="spl-results-loading"><div class="splunk-spinner"></div> Splunk'ta sorgulanıyor...</div></div>`;
            chrome.runtime.sendMessage({ action: "execute_splunk", query: currentQuery }, (response) => {
                runBtn.disabled = false;
                runBtn.classList.remove('running');
                runBtn.textContent = '⚡ Çalıştır';
                if (!response) {
                    resultsDiv.innerHTML = `<div class="spl-results-wrapper"><div class="spl-results-error">⛔ Yanıt alınamadı.</div></div>`;
                    return;
                }
                resultsDiv.innerHTML = buildSplResultsHtml(response, currentQuery);
                const toggleBtn = resultsDiv.querySelector('.spl-preview-toggle-btn');
                if (toggleBtn) {
                    toggleBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const targetId = toggleBtn.getAttribute('data-target');
                        const targetEl = resultsDiv.querySelector('#' + targetId);
                        const chevron = toggleBtn.querySelector('.chevron');
                        if (targetEl) {
                            const isHidden = targetEl.style.display === 'none';
                            targetEl.style.display = isHidden ? 'block' : 'none';
                            if (chevron) chevron.textContent = isHidden ? '▲' : '▼';
                        }
                    });
                }
            });
        });
    }
    return div;
}

function buildSplResultsHtml(response, query) {
    if (response.status === 'not_configured') {
        return `<div class="spl-results-wrapper"><div class="spl-results-warn">⚠️ ${response.message}</div></div>`;
    }
    if (response.status === 'error') {
        return `<div class="spl-results-wrapper"><div class="spl-results-error">⛔ ${response.message}</div></div>`;
    }
    if (response.status === 'success') {
        const results = response.results || [];
        const count = response.result_count !== undefined ? response.result_count : results.length;
        if (count === 0) {
            return `
            <div class="spl-results-wrapper" style="margin-top:8px;">
                <div style="display:flex; align-items:center; gap:8px; padding:10px 12px; background:rgba(30,41,59,0.5); border:1px solid rgba(148,163,184,0.15); border-radius:6px; color:#94a3b8; font-size:11px;">
                    <span style="font-size:14px;">🛡️</span>
                    <span>Sorgu çalıştırıldı, kurum loglarında eşleşen kayıt bulunamadı (Temiz).</span>
                </div>
            </div>`;
        }

        // Splunk Web linki oluştur
        const rawQ = query || response.query || "";
        const splunkQ = rawQ.startsWith('|') || rawQ.toLowerCase().startsWith('search ') ? rawQ : `search ${rawQ}`;
        const webBase = response.splunk_web_url || `https://splunk.kuveytturk.com.tr/en-US/app/search/search?q=${encodeURIComponent(splunkQ)}`;

        // ── Akıllı & Sade Kolon Seçimi (Gereksiz Splunk metadata alanlarını filtrele) ──
        const BLACKLIST = new Set([
            'splunk_server', 'sourcetype', 'source', 'host', 'index',
            'punct', 'linecount', 'timestartpos', 'timeendpos', 'eventtype',
            'tag', '_bkt', '_cd', '_indextime', '_serial', '_si', '_sourcetype',
            '_subsecond', '_raw', '_time'
        ]);

        const PRIORITY_COLS = [
            'src_ip', 'c-ip', 'dst_ip', 's-ip',
            'cs-username', 'User', 'user',
            'cs-host', 'app', 'action', 'sc-status',
            'ComputerName', 'Image', 'CommandLine',
            'attack_type', 'response_code', 'rule_name'
        ];

        const foundKeys = new Set();
        results.forEach(row => {
            Object.keys(row).forEach(k => {
                if (!k.startsWith('_') && !BLACKLIST.has(k)) {
                    foundKeys.add(k);
                }
            });
        });

        const chosenCols = [];
        PRIORITY_COLS.forEach(k => {
            if (foundKeys.has(k)) {
                chosenCols.push(k);
                foundKeys.delete(k);
            }
        });

        foundKeys.forEach(k => {
            if (chosenCols.length < 3) {
                chosenCols.push(k);
            }
        });

        const finalCols = chosenCols.length > 0 ? ['_time', ...chosenCols.slice(0, 3)] : ['_time', '_raw'];

        const headerHtml = finalCols.map(col => {
            let label = col;
            if (col === '_time') label = 'Zaman';
            else if (col === '_raw') label = 'Olay Özeti';
            return `<th style="padding:6px 8px; text-align:left; font-weight:700; color:#a5b4fc; white-space:nowrap; border-bottom:1px solid rgba(99,102,241,0.2); font-size:10px;">${escapeHtml(label)}</th>`;
        }).join('');

        const rowsHtml = results.map(row => {
            const cells = finalCols.map(col => {
                let val = row[col];
                if (col === '_time' && typeof val === 'string') {
                    val = val.split('.')[0].replace('T', ' ');
                } else if (col === '_raw' && typeof val === 'string') {
                    val = val.length > 100 ? val.substring(0, 100) + '…' : val;
                }
                val = (val === undefined || val === null || val === '') ? '—' : String(val);
                return `<td style="padding:5px 8px; border-bottom:1px solid rgba(255,255,255,0.05); max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:10px;" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
            }).join('');
            return `<tr>${cells}</tr>`;
        }).join('');

        const previewId = 'spl-prev-' + Math.random().toString(36).substring(2, 9);

        return `
        <div class="spl-results-wrapper" style="margin-top:8px;">
            <!-- 1. Sonuç Bildirim Kartı -->
            <div style="background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.3); border-radius:8px; padding:10px 12px; margin-bottom:8px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="font-size:20px; line-height:1;">🚨</span>
                    <div>
                        <div style="font-size:12px; font-weight:700; color:#34d399;">${count} Adet Eşleşen Log Bulundu</div>
                        <div style="font-size:10px; color:#94a3b8; margin-top:2px;">Kurum Splunk SIEM loglarında bu IOC ile ilgili aktivite tespit edildi.</div>
                    </div>
                </div>

                <!-- 2. Splunk Web'e Yönlendirme Butonu -->
                <div style="margin-top:10px;">
                    <a href="${webBase}" target="_blank" rel="noopener noreferrer" style="display:flex; align-items:center; justify-content:center; gap:6px; width:100%; padding:8px 12px; background:#0284c7; color:#ffffff; font-size:11px; font-weight:600; text-decoration:none; border-radius:6px; box-sizing:border-box; box-shadow:0 2px 6px rgba(2,132,199,0.3); transition:background 0.2s;">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                        Detaylı Log İncelemesi için Splunk'a Git ↗
                    </a>
                </div>
            </div>

            <!-- 3. Ham Log Önizlemesi (İsteğe Bağlı Akordiyon) -->
            <div style="border:1px solid rgba(148,163,184,0.15); border-radius:6px; overflow:hidden;">
                <button type="button" class="spl-preview-toggle-btn" data-target="${previewId}" style="width:100%; display:flex; align-items:center; justify-content:space-between; padding:7px 10px; background:rgba(30,41,59,0.6); border:none; color:#94a3b8; font-size:10px; cursor:pointer; font-weight:500;">
                    <span>📄 Ham Log Önizlemesini Göster / Gizle (${count} Kayıt)</span>
                    <span class="chevron">▼</span>
                </button>
                <div id="${previewId}" style="display:none; overflow-x:auto; max-height:160px; overflow-y:auto; background:#0b132b; border-top:1px solid rgba(148,163,184,0.1);">
                    <table class="spl-results-table" style="width:100%; font-size:10px;">
                        <thead><tr>${headerHtml}</tr></thead>
                        <tbody>${rowsHtml}</tbody>
                    </table>
                </div>
            </div>
        </div>`;
    }
    return `<div class="spl-results-wrapper"><div class="spl-results-error">Bilinmeyen yanıt formatı.</div></div>`;
}


// ══════════════════════════════════════════════════════════════════
// YARDIMCI FONKSİYONLAR
// ══════════════════════════════════════════════════════════════════
function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function sh(text, maxLen = 100) {
    // Safe truncated escapeHtml
    const s = String(text || '—');
    return escapeHtml(s.length > maxLen ? s.substring(0, maxLen) + '…' : s);
}


// ══════════════════════════════════════════════════════════════════
// v2 — KAYNAK ETİKETLERİ
// ══════════════════════════════════════════════════════════════════
const SOURCE_LABELS = {
    'VirusTotal':                  'VirusTotal',
    'AlienVault OTX':              'OTX',
    'AlienVault':                  'OTX',
    'AbuseIPDB':                   'AbuseIPDB',
    'Shodan':                      'Shodan',
    'GreyNoise':                   'GreyNoise',
    'IPInfo.io':                   'IPInfo',
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
    'AbstractAPI':                 'AbstractAPI',
    'emailrep.io':                 'emailrep',
    'HaveIBeenPwned':              'HIBP',
    'BreachDirectory':             'BreachDir',
    'Spamhaus':                    'Spamhaus',
    'MX / DNS Doğrulama':          'MX/DNS',
    'SecurityTrails':              'SecTrails',
    'crt.sh':                      'crt.sh',
    'RDAP':                        'RDAP',
    'IntelX':                      'IntelX',
};


// ══════════════════════════════════════════════════════════════════
// v2 — KAYNAK SINIFLANDIRMA
// verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'
// metric:  chip üzerinde gösterilecek kısa metin
// detailHtml: tıklanınca açılacak içerik
// ══════════════════════════════════════════════════════════════════
function classifySource(res) {
    if (!res.success) {
        return {
            verdict: 'error',
            metric: 'Hata',
            detailHtml: `<div style="color:#94a3b8;">${sh(res.error || 'API isteği başarısız')}</div>`
        };
    }

    const src  = res.source || '';
    const data = (res.data && typeof res.data === 'object') ? res.data : {};

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
        return {
            verdict,
            metric: total > 0 ? `${mal}/${total}` : '—',
            detailHtml: `
                <div>🔍 <b>${mal}</b> zararlı / <b>${sus}</b> şüpheli / <b>${total}</b> motor</div>
                ${rep !== undefined ? `<div>👥 İtibar: <b style="color:${rep < 0 ? '#ef4444' : rep > 0 ? '#10b981' : '#94a3b8'}">${rep > 0 ? '+' + rep : rep}</b></div>` : ''}
                ${attrs.tags?.length ? `<div>🏷️ ${attrs.tags.slice(0,5).map(t => sh(t)).join(', ')}</div>` : ''}
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
                <div style="margin-top:4px;"><a href="https://www.abuseipdb.com/check/${document.getElementById('targetValue').textContent}" target="_blank">AbuseIPDB'de Gör →</a></div>
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
                <div style="margin-top:4px;"><a href="https://otx.alienvault.com/indicator/ip/${document.getElementById('targetValue').textContent}" target="_blank">OTX'de Gör →</a></div>
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
                <div style="margin-top:4px;"><a href="https://sitecheck.sucuri.net/results/${document.getElementById('targetValue').textContent}" target="_blank">Sucuri'de İncele →</a></div>
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
                ${total > 0   ? `<div style="margin-top:4px;"><a href="https://urlscan.io/search/#domain:${document.getElementById('targetValue').textContent}" target="_blank">urlscan'da Gör →</a></div>` : ''}
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
                   <div style="margin-top:4px;"><a href="https://haveibeenpwned.com/account/${document.getElementById('targetValue').textContent}" target="_blank">HIBP'de Gör →</a></div>`
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
                <div style="margin-top:4px;"><a href="https://check.spamhaus.org/" target="_blank">Spamhaus'ta Kontrol Et →</a></div>
            `
        };
    }

    // ── MX / DNS ──────────────────────────────────────────────────
    if (src.includes('MX') || src.includes('DNS')) {
        const resolves = data.domain_resolves || false;
        return {
            verdict: 'unknown',
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

    // ── Pre-processor (PowerShell De-Obfuscator) ──────────────────
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


// ══════════════════════════════════════════════════════════════════
// v2 — VERDICT BAR HTML ÜRETİCİ
// ══════════════════════════════════════════════════════════════════
function buildVerdictBarHtml(results) {
    const counts = { malicious: 0, suspicious: 0, clean: 0 };
    results.forEach(res => {
        const { verdict } = classifySource(res);
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


// ══════════════════════════════════════════════════════════════════
// v2 — SOURCES ACCORDION (Kapalı başlar, tıklayınca açılır)
// ══════════════════════════════════════════════════════════════════
function buildSourcesAccordion(results) {
    const wrapper = document.createElement('div');
    wrapper.className = 'sources-accordion-inner';

    // Header
    const header = document.createElement('div');
    header.className = 'accordion-header';
    header.innerHTML = `
        <span>İstihbarat Kaynakları</span>
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

        rowResults.forEach((res, idx) => {
            const { verdict, metric, detailHtml } = classifySource(res);
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
