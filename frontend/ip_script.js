const searchBtn = document.getElementById('searchBtn');
const ipInput = document.getElementById('ipInput');
const errorMsg = document.getElementById('errorMsg');
const loader = document.getElementById('loader');
const resultsSection = document.getElementById('resultsSection');
const analyzedIp = document.getElementById('analyzedIp');
const cardsContainer = document.getElementById('cardsContainer');
const aiSummaryText = document.getElementById('aiSummaryText');
const chartCard = document.getElementById('chartCard');

let threatChartInstance = null;
const API_BASE_URL = 'http://10.14.7.20:8000';

// IP Regex (IPv4)
const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

function getIconForSource(source) {
    if (source.includes('AlienVault')) return '<i class="fa-solid fa-satellite-dish"></i>';
    if (source.includes('VirusTotal')) return '<i class="fa-solid fa-virus"></i>';
    if (source.includes('AbuseIPDB')) return '<i class="fa-solid fa-user-ninja"></i>';
    return '<i class="fa-solid fa-database"></i>';
}

function drawChart(malicious, suspicious, clean) {
    chartCard.style.display = 'flex';
    const ctx = document.getElementById('threatChart').getContext('2d');

    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Zararlı', 'Şüpheli', 'Temiz/Bilinmeyen'],
            datasets: [{
                data: [malicious, suspicious, clean],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            plugins: {
                legend: { position: 'right', labels: { color: '#e2e8f0', font: { family: "'Inter', sans-serif" } } }
            },
            maintainAspectRatio: false,
            cutout: '70%'
        }
    });
}

function parseOTX(data) {
    if (!data || !data.pulse_info) return { status: 'unknown', text: 'Kayıt bulunamadı', details: null };
    const pulseCount = data.pulse_info.count || 0;
    if (pulseCount === 0) return { status: 'clean', text: 'Tehdit Bulunmadı (0 Pulse)', details: null };
    return {
        status: pulseCount > 2 ? 'malicious' : 'suspicious',
        text: `${pulseCount} Pulse İçinde Tespit Edildi`,
        details: [
            { label: 'Pulse Sayısı', value: pulseCount },
            { label: 'İlgili Ülkeler', value: (data.base_indicator?.country_name || 'Yok') }
        ]
    };
}

function parseVirusTotal(data) {
    if (!data || data.message === "Not found") return { status: 'unknown', text: 'Kayıt bulunamadı', details: null };

    if (data.data && data.data.attributes && data.data.attributes.last_analysis_stats) {
        const stats = data.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;

        let pStatus = 'clean';
        if (malicious > 4) pStatus = 'malicious';
        else if (malicious > 0 || suspicious > 1) pStatus = 'suspicious';

        // Grafiği çiz
        drawChart(malicious, suspicious, (stats.harmless || 0) + (stats.undetected || 0));

        return {
            status: pStatus,
            text: `${malicious} Motor Tarafından Zararlı Bulundu`,
            details: [
                { label: 'Zararlı', value: malicious },
                { label: 'Şüpheli', value: suspicious },
                { label: 'Temiz', value: stats.harmless || 0 },
                { label: 'IP Sahibi', value: data.data.attributes.as_owner || '-' }
            ]
        };
    }
    return { status: 'unknown', text: 'Analiz tamamlandı', details: null, raw: JSON.stringify(data, null, 2) };
}

function parseAbuseIPDB(data) {
    if (!data || !data.data) return { status: 'unknown', text: 'Kayıt bulunamadı', details: null };

    const d = data.data;
    const score = d.abuseConfidenceScore || 0;

    let pStatus = 'clean';
    if (score > 70) pStatus = 'malicious';
    else if (score > 20) pStatus = 'suspicious';

    return {
        status: pStatus,
        text: `Güven Skoru: ${score}% Zararlı`,
        details: [
            { label: 'Toplam Rapor', value: d.totalReports || 0 },
            { label: 'ISS (ISP)', value: d.isp || '-' },
            { label: 'Domain', value: d.domain || '-' },
            { label: 'Kullanım Tipi', value: d.usageType || '-' }
        ]
    };
}

function processSourceResult(result) {
    if (!result.success) {
        let errText = 'Hataya Düşüldü veya İstek Reddedildi';
        if (result.error && (result.error.includes('API Anahtarı') || result.error.includes('Unauthorized'))) {
            errText = '<i class="fa-solid fa-key" style="color:var(--accent-orange)"></i> ' + result.error;
        }
        return {
            status: 'error',
            text: errText,
            raw: result.error || result.data || 'Bilinmeyen Hata',
            details: null
        };
    }

    const { source, data } = result;

    if (source.includes('AlienVault')) return parseOTX(data);
    if (source.includes('VirusTotal')) return parseVirusTotal(data);
    if (source.includes('AbuseIPDB')) return parseAbuseIPDB(data);

    // Any other
    return { status: 'unknown', text: 'Analiz Tamamlandı', details: null, raw: JSON.stringify(data, null, 2) };
}

function renderCard(result) {
    const parsed = processSourceResult(result);

    let detailsHTML = '';
    if (parsed.details) {
        detailsHTML = parsed.details.map(d => `
            <div class="data-row">
                <span class="data-label">${d.label}:</span>
                <span class="data-value">${d.value}</span>
            </div>
        `).join('');
    }

    let rawHTML = '';
    if (parsed.raw) {
        rawHTML = `<div class="raw-json">${parsed.raw}</div>`;
    } else if (result.success && !parsed.details && result.data) {
        rawHTML = `<div class="raw-json">${JSON.stringify(result.data, null, 2)}</div>`;
    }

    return `
        <div class="source-card">
            <div class="card-header">
                <div class="source-name">
                    ${getIconForSource(result.source)} ${result.source}
                </div>
                <div class="status-badge status-${parsed.status}">
                    ${parsed.status === 'malicious' ? 'Tespİt Edİldİ' :
            parsed.status === 'clean' ? 'Temİz' :
                parsed.status === 'suspicious' ? 'Şüphelİ' :
                    parsed.status === 'error' ? 'Hata' : 'Bİlİnmİyor'}
                </div>
            </div>
            <div class="card-body">
                <div style="margin-bottom: ${parsed.details || rawHTML ? '1rem' : '0'}; font-weight: 600; color: #fff;">
                    ${parsed.text}
                </div>
                ${detailsHTML}
                ${rawHTML}
            </div>
        </div>
    `;
}

async function handleSearch() {
    const ip = ipInput.value.trim();
    errorMsg.textContent = '';

    if (!ip) {
        errorMsg.textContent = 'Lütfen bir IP adresi girin.';
        return;
    }

    if (!IP_REGEX.test(ip)) {
        errorMsg.textContent = 'Hatalı format. Lütfen geçerli bir IPv4 adresi girin.';
        return;
    }

    // UI Updates
    resultsSection.style.display = 'none';
    loader.style.display = 'flex';
    cardsContainer.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE_URL}/api/analyze/ip/${ip}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Sunucu hatası oluştu.');
        }

        // Render Results
        analyzedIp.textContent = data.ip;
        aiSummaryText.textContent = data.ai_summary || "Özet oluşturulamadı.";

        chartCard.style.display = 'none'; // reset
        if (threatChartInstance) threatChartInstance.destroy();

        let htmlCards = '';
        data.results.forEach(res => {
            htmlCards += renderCard(res);
        });

        cardsContainer.innerHTML = htmlCards;

        loader.style.display = 'none';
        resultsSection.style.display = 'block';

    } catch (err) {
        loader.style.display = 'none';
        errorMsg.textContent = `Ajan hatası: ${err.message}`;
    }
}

searchBtn.addEventListener('click', handleSearch);

ipInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleSearch();
    }
});
