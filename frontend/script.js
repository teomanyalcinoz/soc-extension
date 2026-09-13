const searchBtn = document.getElementById('searchBtn');
const hashInput = document.getElementById('hashInput');
const errorMsg = document.getElementById('errorMsg');
const loader = document.getElementById('loader');
const resultsSection = document.getElementById('resultsSection');
const analyzedHash = document.getElementById('analyzedHash');
const cardsContainer = document.getElementById('cardsContainer');
const aiSummaryText = document.getElementById('aiSummaryText');
const chartCard = document.getElementById('chartCard');

let threatChartInstance = null;

// Backend sunucu adresi
const API_BASE_URL = 'http://10.14.7.20:8000';

// Sabitler
const MD5_REGEX = /^[a-fA-F0-9]{32}$/;
const SHA1_REGEX = /^[a-fA-F0-9]{40}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;

function getIconForSource(source) {
    if (source.includes('MalwareBazaar')) return '<i class="fa-solid fa-bug"></i>';
    if (source.includes('AlienVault')) return '<i class="fa-solid fa-satellite-dish"></i>';
    if (source.includes('CIRCL')) return '<i class="fa-solid fa-check-double"></i>';
    if (source.includes('Hybrid')) return '<i class="fa-solid fa-flask"></i>';
    if (source.includes('VirusTotal')) return '<i class="fa-solid fa-virus"></i>';
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

function parseMalwareBazaar(data) {
    if (!data || data.query_status !== 'ok') return { status: 'unknown', text: 'Zararlı kaydı bulunamadı', details: null };
    return {
        status: 'malicious',
        text: 'Zararlı Bulundu!',
        details: [
            { label: 'Dosya Adı', value: data.data[0].file_name || 'Bilinmiyor' },
            { label: 'İmza', value: data.data[0].signature || 'Bilinmiyor' },
            { label: 'İlk Görülme', value: data.data[0].first_seen || '-' }
        ]
    };
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
            { label: 'İlgili Etiketler', value: (data.pulse_info.pulses[0]?.tags?.slice(0, 3).join(', ') || 'Yok') }
        ]
    };
}

function parseCIRCL(data) {
    if (!data || !data.FileName) return { status: 'unknown', text: 'Kayıt bulunamadı', details: null };
    // CIRCL genellikle whitelisting için kullanılır (NSRL)
    return {
        status: 'clean',
        text: 'Bilinen/Güvenli Dosya (NSRL)',
        details: [
            { label: 'Dosya Adı', value: data.FileName || '-' },
            { label: 'Boyut', value: data.FileSize || '-' }
        ]
    };
}

function parseHybrid(data) {
    // Hybrid analysis JSON array return edebilir.
    if (Array.isArray(data) && data.length > 0) {
        let threatLevel = data[0].threat_score || 0;
        let pStatus = 'unknown';
        if (threatLevel > 70) pStatus = 'malicious';
        else if (threatLevel > 30) pStatus = 'suspicious';
        else pStatus = 'clean';

        return {
            status: pStatus,
            text: `Tehdit Skoru: ${threatLevel}/100`,
            details: [
                { label: 'Uygulama', value: data[0].submit_name || '-' },
                { label: 'Durum', value: data[0].verdict || '-' }
            ]
        };
    }
    return { status: 'unknown', text: 'Kayıt bulunamadı', details: null };
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
                { label: 'Dosya Tipi', value: data.data.attributes.type_description || '-' }
            ]
        };
    }
    return { status: 'unknown', text: 'Analiz tamamlandı', details: null, raw: JSON.stringify(data, null, 2) };
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

    if (source.includes('MalwareBazaar')) return parseMalwareBazaar(data);
    if (source.includes('AlienVault')) return parseOTX(data);
    if (source.includes('CIRCL')) return parseCIRCL(data);
    if (source.includes('Hybrid')) return parseHybrid(data);
    if (source.includes('VirusTotal')) return parseVirusTotal(data);

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
    const hash = hashInput.value.trim().toLowerCase();
    errorMsg.textContent = '';

    if (!hash) {
        errorMsg.textContent = 'Lütfen bir hash değeri girin.';
        return;
    }

    if (!MD5_REGEX.test(hash) && !SHA1_REGEX.test(hash) && !SHA256_REGEX.test(hash)) {
        errorMsg.textContent = 'Hatalı format. Lütfen geçerli bir MD5, SHA1 veya SHA256 girin.';
        return;
    }

    // UI Updates
    resultsSection.style.display = 'none';
    loader.style.display = 'flex';
    cardsContainer.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE_URL}/api/analyze/hash/${hash}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Sunucu hatası oluştu.');
        }

        // Render Results
        analyzedHash.textContent = data.hash;
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

hashInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleSearch();
    }
});
