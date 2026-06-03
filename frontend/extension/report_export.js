document.addEventListener('DOMContentLoaded', () => {
    // Tarihi yazdır
    const dateStr = new Date().toLocaleString('tr-TR');
    document.getElementById('reportDate').textContent = "Tarih: " + dateStr;

    // Yazdırma butonunu bağla
    const printBtn = document.getElementById('printBtn');
    if (printBtn) {
        printBtn.addEventListener('click', () => {
            window.print();
        });
    }

    chrome.storage.local.get(['reportData', 'reportUrl'], (result) => {
        const data = result.reportData;
        const url = result.reportUrl || "Bilinmeyen Kaynak";
        
        document.getElementById('reportUrl').textContent = "Kaynak: " + url;
        document.getElementById('reportUrl').title = url;

        if (!data) {
            document.getElementById('summaryBox').innerHTML = "Rapor verisi bulunamadı.";
            return;
        }

        document.getElementById('summaryBox').innerHTML = data.summary || "Özet çıkarılamadı.";

        const tbody = document.getElementById('iocTableBody');
        const splSection = document.getElementById('splSection');
        
        if (data.grouped_iocs && data.grouped_iocs.length > 0) {
            data.grouped_iocs.forEach(group => {
                const tr = document.createElement('tr');
                
                let valuesHtml = group.values.map(v => `<span class="ioc-val" style="display:inline-block; margin-right:8px; margin-bottom:4px; padding:2px 4px; background:#f1f5f9; border-radius:3px;">${v}</span>`).join('');
                
                tr.innerHTML = `
                    <td style="vertical-align:top;"><span class="type-badge">${group.type}</span> <br><small style="color:#64748b;">${group.count} Adet</small></td>
                    <td>${valuesHtml}</td>
                `;
                tbody.appendChild(tr);

                if (group.spl_queries && group.spl_queries.length > 0) {
                    const splContainer = document.createElement('div');
                    splContainer.className = 'spl-item';
                    
                    let queriesHtml = '';
                    group.spl_queries.forEach(q => {
                        // escape HTML function
                        const escapeHtml = (unsafe) => {
                            return (unsafe || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
                        };
                        
                        queriesHtml += `
                            <div style="font-size:12px; color:#64748b; margin-top:10px;">Hedef Index: <strong>${escapeHtml(q.index)}</strong></div>
                            <div class="spl-query">${escapeHtml(q.query)}</div>
                        `;
                    });

                    splContainer.innerHTML = `
                        <div class="spl-ioc">[${group.type.toUpperCase()}] Toplu Splunk Avcılık Sorgusu</div>
                        ${queriesHtml}
                    `;
                    splSection.appendChild(splContainer);
                }
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;">IOC bulunamadı.</td></tr>`;
            splSection.innerHTML = `<p style="color:#64748b;">Üretilmiş sorgu bulunamadı.</p>`;
        }

        setTimeout(() => {
            window.print();
        }, 500);
    });
});
