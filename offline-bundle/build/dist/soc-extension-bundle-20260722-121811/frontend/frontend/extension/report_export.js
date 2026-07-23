document.addEventListener('DOMContentLoaded', () => {
    // Tarihi yazdır
    const now = new Date();
    const dateStr = now.toLocaleDateString('tr-TR') + ' ' + now.toLocaleTimeString('tr-TR');
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
            document.getElementById('summaryBox').innerHTML = "<p>Rapor verisi bulunamadı.</p>";
            return;
        }

        // Summary'i bullet list formatına çevir (Eğer noktalarla ayrılmış cümleler varsa)
        let summaryText = data.summary || "Özet çıkarılamadı.";
        let summaryLines = summaryText.split(/(?<=\.)\s+/).filter(line => line.trim().length > 0);
        let summaryHtml = '<ul class="summary-list">';
        if (summaryLines.length > 1) {
            summaryLines.forEach(line => {
                summaryHtml += `<li>${line}</li>`;
            });
        } else {
            summaryHtml += `<li>${summaryText}</li>`;
        }
        summaryHtml += '</ul>';
        document.getElementById('summaryBox').innerHTML = summaryHtml;

        const iocGrid = document.getElementById('iocGrid');
        const splSection = document.getElementById('splSection');
        
        if (data.grouped_iocs && data.grouped_iocs.length > 0) {
            // IOC Tabloları
            data.grouped_iocs.forEach(group => {
                const tableWrapper = document.createElement('div');
                tableWrapper.className = 'ioc-table-wrapper';
                
                let tbodyHtml = '';
                group.values.forEach(val => {
                    tbodyHtml += `
                        <tr>
                            <td>${val}</td>
                            <td style="width: 50px;"><span class="badge">${group.type.toUpperCase()}</span></td>
                        </tr>
                    `;
                });
                
                tableWrapper.innerHTML = `
                    <h3>${group.type.toUpperCase()}: <span>${group.count} Adet</span></h3>
                    <table>
                        <thead>
                            <tr>
                                <th colspan="2">${group.type.toUpperCase()}</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${tbodyHtml}
                        </tbody>
                    </table>
                `;
                iocGrid.appendChild(tableWrapper);

                // SPL Sorguları
                if (group.spl_queries && group.spl_queries.length > 0) {
                    group.spl_queries.forEach(q => {
                        const escapeHtml = (unsafe) => {
                            return (unsafe || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
                        };
                        
                        const splBox = document.createElement('div');
                        splBox.className = 'spl-box';
                        
                        // [cite: Hedef Index: xxx] formatında başlık
                        let titleText = `[cite: Hedef Index: ${escapeHtml(q.index)}]`;
                        // Eger URL vs sorgusu ise tip ekleyebiliriz
                        if (group.type === 'url' || group.type === 'hash') {
                            titleText = `[cite: ${group.type.toUpperCase()}] Toplu Splunk Avcılık Sorgusu - ${escapeHtml(q.index)}`;
                        }
                        
                        splBox.innerHTML = `
                            <div class="spl-header">${titleText}</div>
                            <div class="spl-body">${escapeHtml(q.query)}</div>
                        `;
                        splSection.appendChild(splBox);
                    });
                }
            });
        } else {
            iocGrid.innerHTML = `<p>IOC bulunamadı.</p>`;
            splSection.innerHTML = `<p>Üretilmiş sorgu bulunamadı.</p>`;
        }

        setTimeout(() => {
            window.print();
        }, 800);
    });
});
