// Background Service Worker

// API Sunucu Adresi (Local test: 127.0.0.1:8000 | Canlı Sunucu: 10.14.7.20:8000)
let SERVER_HOST = "http://10.14.7.20:8000";
let API_BASE = `${SERVER_HOST}/api/analyze`;
let SPLUNK_SPL_URL = `${SERVER_HOST}/api/splunk/generate-spl`;
let SPLUNK_EXECUTE_URL = `${SERVER_HOST}/api/splunk/execute`;
let XDR_EXECUTE_URL = `${SERVER_HOST}/api/xdr/execute`;

function updateServerHost(host) {
    SERVER_HOST = host;
    API_BASE = `${SERVER_HOST}/api/analyze`;
    SPLUNK_SPL_URL = `${SERVER_HOST}/api/splunk/generate-spl`;
    SPLUNK_EXECUTE_URL = `${SERVER_HOST}/api/splunk/execute`;
    XDR_EXECUTE_URL = `${SERVER_HOST}/api/xdr/execute`;
}

// Storage'da özel sunucu adresi kayıtlıysa (ve eski localhost değilse) onu kullan
chrome.storage.local.get(["server_host"], (res) => {
    if (res.server_host && res.server_host !== "http://127.0.0.1:8000" && res.server_host !== "http://localhost:8000") {
        updateServerHost(res.server_host);
        console.log("TracePoint API Sunucusu (Storage):", res.server_host);
    } else {
        updateServerHost(SERVER_HOST);
        console.log("TracePoint API Sunucusu (Default):", SERVER_HOST);
    }
});

// Arama/Sorgu sonuçlarını hafızada tutmak için eklenti veritabanı değişkeni
let latestScanResult = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan_threat") {
        console.log("Tarama isteği alındı:", request);

        // İsteği atan sekmenin ID'sini kaydet (SPL güncelleme için gerekli)
        const senderTabId = sender.tab ? sender.tab.id : null;

        const type = request.dataType;
        const val = request.dataValue;

        let endpoint = "";
        let fetchOptions = { method: "GET" };

        if (type === "hash") endpoint = `${API_BASE}/hash/${val}`;
        else if (type === "ipv4") endpoint = `${API_BASE}/ip/${val}`;
        else if (type === "url") endpoint = `${API_BASE}/url/${encodeURIComponent(val)}`;
        else if (type === "email") endpoint = `${API_BASE}/email/${encodeURIComponent(val)}`;
        else if (type === "domain") endpoint = `${API_BASE}/domain/${encodeURIComponent(val)}`;
        else if (type === "powershell") {
            endpoint = `${API_BASE}/powershell/`;
            fetchOptions = {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ script_content: val })
            };
        }

        if (!endpoint) {
            console.error("Desteklenmeyen tarama tipi:", type);
            return;
        }

        // Popup arayüzüne (eğer açıksa) loading state'i gönderebiliriz
        latestScanResult = { status: "loading", type: type, value: val, splData: null };
        chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });

        // SPL sorgularını HEMEN arka planda üretmeye başla (OSINT'i bekleme!)
        // Bu sayede SPL paneli "pending" durumunda başlar
        _fetchSplQueries(val, type, [], senderTabId, true /* osint_pending */);

        // FastAPI (Backend) sunucumuza OSINT isteği
        fetch(endpoint, fetchOptions)
            .then(res => {
                if (!res.ok) throw new Error(`Sunucu Hatası: Gelen Kod ${res.status}`);
                return res.json();
            })
            .then(data => {
                latestScanResult = {
                    status: data.status === "error" ? "error" : "success",
                    type: type,
                    value: val,
                    rawData: data,
                    splData: latestScanResult ? latestScanResult.splData : null
                };
                chrome.action.setBadgeText({ text: "1" });
                chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });

                if (data.status === "error") {
                    _sendNotification("Tarama Hatası", `[${type.toUpperCase()}] ${val} taramasında sunucu hatası oluştu.`);
                } else {
                    _sendNotification("Tarama Tamamlandı", `[${type.toUpperCase()}] ${val} başarıyla incelendi.`);
                }

                sendResponse(latestScanResult);
                chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });
            })
            .catch(err => {
                latestScanResult = { status: "error", type: type, value: val, error: err.toString(), splData: null };
                _sendNotification("Tarama Hatası", `[${type.toUpperCase()}] ${val} incelenirken hata oluştu: ${err.message}`);
                sendResponse(latestScanResult);
                chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });
            });

        return true; // Asenkron response için gerekli
    }

    // Popup açıldığında arka plandaki son veriyi ister
    if (request.action === "get_latest_result") {
        sendResponse(latestScanResult);
        chrome.action.setBadgeText({ text: "" });
    }

    // SPL sorgusunu Splunk REST API üzerinden çalıştır
    if (request.action === "execute_splunk") {
        const query = request.query || "";
        fetch(SPLUNK_EXECUTE_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: query })
        })
            .then(res => {
                if (!res.ok) throw new Error(`Splunk Execute API Hatası: ${res.status}`);
                return res.json();
            })
            .then(data => {
                sendResponse(data);
            })
            .catch(err => {
                sendResponse({
                    status: "error",
                    message: `Bağlantı hatası: ${err.toString()}`,
                    results: [],
                    result_count: 0
                });
            });
        return true; // Asenkron response için gerekli
    }

    // Tüm sayfa raporu tarama isteği
    if (request.action === "scan_report") {
        console.log("Rapor tarama isteği alındı:", request.url);
        
        const endpoint = `${API_BASE}/report`;
        const fetchOptions = {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: request.text, url: request.url })
        };
        
        latestScanResult = { status: "loading", type: "report", value: "Sayfa Raporu", splData: null };
        chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });
        
        fetch(endpoint, fetchOptions)
            .then(res => {
                if (!res.ok) throw new Error(`Sunucu Hatası: Gelen Kod ${res.status}`);
                return res.json();
            })
            .then(data => {
                latestScanResult = {
                    status: data.status === "error" ? "error" : "success",
                    type: "report",
                    value: "Sayfa Raporu",
                    rawData: data,
                    splData: null
                };
                chrome.action.setBadgeText({ text: "R" });
                chrome.action.setBadgeBackgroundColor({ color: "#8b5cf6" });
                
                if (data.status === "error") {
                    _sendNotification("Rapor Hatası", "Sayfa raporu analiz edilirken bir sorun oluştu.");
                } else {
                    const count = data.total_iocs_found || 0;
                    _sendNotification("Rapor Tamamlandı", `Sayfada toplam ${count} IOC tespit edildi ve analiz edildi.`);
                }

                sendResponse(latestScanResult);
                chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });
            })
            .catch(err => {
                latestScanResult = { status: "error", type: "report", value: "Sayfa Raporu", error: err.toString(), splData: null };
                _sendNotification("Rapor Hatası", `Rapor analizinde bağlantı hatası: ${err.message}`);
                sendResponse(latestScanResult);
                chrome.runtime.sendMessage({ action: "update_popup", result: latestScanResult }).catch(() => { });
            });
            
        return true;
    }
    
    // Rapor taraması için SPL On-Demand Getirme
    if (request.action === "fetch_report_spl") {
        fetch(`${API_BASE}/report/spl`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ioc_type: request.iocType, values: request.values })
        })
        .then(res => res.json())
        .then(data => sendResponse(data))
        .catch(err => {
            sendResponse({ status: "error", error: err.toString() });
        });
        return true; // Asenkron için
    }

    // XDR Sorgusunu çalıştır
    if (request.action === "execute_xdr") {
        const query = request.query || "";
        fetch(XDR_EXECUTE_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: query })
        })
            .then(res => {
                if (!res.ok) throw new Error(`XDR Sunucu Hatası: ${res.status}`);
                return res.json();
            })
            .then(data => {
                sendResponse(data);
            })
            .catch(err => {
                sendResponse({ status: "error", error: err.toString() });
            });
        return true; // Asenkron için
    }
    
    // CVE Detay Analizi (NIST NVD)
    if (request.action === "fetch_cve") {
        const cveId = encodeURIComponent(request.cveId);
        fetch(`${API_BASE}/cve/${cveId}`)
            .then(res => {
                if (!res.ok) throw new Error(`CVE API Hatası: ${res.status}`);
                return res.json();
            })
            .then(data => sendResponse(data))
            .catch(err => sendResponse({ status: "error", cve_id: request.cveId, error: err.toString() }));
        return true;
    }

    // Content script üzerinden gelen PDF açma isteği
    if (request.action === "open_pdf") {
        chrome.storage.local.set({ reportData: request.reportData, reportUrl: request.reportUrl }, () => {
            chrome.tabs.create({ url: chrome.runtime.getURL('report_export.html') });
        });
        return true;
    }
});

// ─────────────────────────────────────────────────────────────────
// SPL Sorgu Üretimi
// ─────────────────────────────────────────────────────────────────
function _fetchSplQueries(iocValue, iocType, osintResults, tabId, isEarlyFetch = false) {
    // Eğer erken çağrıysa (OSINT henüz bitmedi) → sadece "pending" durumu bildir
    if (isEarlyFetch) {
        const pendingData = {
            status: "pending",
            ioc_value: iocValue,
            ioc_type: iocType,
            queries: []
        };

        // latestScanResult'a SPL pending durumunu ekle
        if (latestScanResult) {
            latestScanResult.splData = pendingData;
        }

        // Hem popup hem content script'e "SPL pending" bildir
        _broadcastSplUpdate(pendingData, tabId);

        // Gerçek SPL sorgusunu arka planda oluştur
        _doFetchSpl(iocValue, iocType, osintResults, tabId);
        return;
    }

    _doFetchSpl(iocValue, iocType, osintResults, tabId);
}

function _doFetchSpl(iocValue, iocType, osintResults, tabId) {
    fetch(SPLUNK_SPL_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            ioc_value: iocValue,
            ioc_type: iocType,
            osint_results: osintResults
        })
    })
        .then(res => {
            if (!res.ok) throw new Error(`SPL API Hatası: ${res.status}`);
            return res.json();
        })
        .then(splData => {
            splData.status = "completed";

            if (latestScanResult && latestScanResult.value === iocValue) {
                latestScanResult.splData = splData;
            }

            _broadcastSplUpdate(splData, tabId);
        })
        .catch(err => {
            console.warn("SPL sorgusu üretilemedi:", err);
            const errorData = {
                status: "error",
                ioc_value: iocValue,
                ioc_type: iocType,
                error: err.toString(),
                queries: []
            };

            if (latestScanResult && latestScanResult.value === iocValue) {
                latestScanResult.splData = errorData;
            }

            _broadcastSplUpdate(errorData, tabId);
        });
}

// Hem popup'a hem de sayfadaki in-page panele SPL güncellemesi gönder
function _broadcastSplUpdate(splData, tabId) {
    // Popup'a gönder
    chrome.runtime.sendMessage({
        action: "spl_ready",
        result: latestScanResult,
        splData: splData
    }).catch(() => { });

    // Content Script'e (in-page panel) gönder
    if (tabId) {
        chrome.tabs.sendMessage(tabId, {
            action: "spl_update_inpage",
            splData: splData
        }).catch(() => { });
    }
}

// ─────────────────────────────────────────────────────────────────
// Masaüstü Bildirimleri
// ─────────────────────────────────────────────────────────────────
function _sendNotification(title, message) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon.png',
        title: `TracePoint: ${title}`,
        message: message,
        priority: 1
    });
}
