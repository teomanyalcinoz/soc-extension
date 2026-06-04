// ─────────────────────────────────────────────────────────────────
// TracePoint — Grafiksel Tehdit Ağı (D3.js Force-Directed Graph)
// ─────────────────────────────────────────────────────────────────

/**
 * IOC gruplarından graph verisi oluşturur ve tam ekran modal açar.
 * @param {Array} groupedIocs - [{type, count, values}, ...]
 * @param {string} reportTitle - Rapor başlığı
 */
function openThreatGraph(groupedIocs, reportTitle) {
    // Önceki grafiği temizle
    closeThreatGraph();

    if (!groupedIocs || groupedIocs.length === 0) return;

    // ── Graph verisi oluştur ──────────────────────────────
    const nodes = [];
    const links = [];

    // Renk ve ikon haritası
    const typeConfig = {
        'ip':      { color: '#3b82f6', icon: '🌐', label: 'IP Adresi' },
        'ipv4':    { color: '#3b82f6', icon: '🌐', label: 'IP Adresi' },
        'domain':  { color: '#8b5cf6', icon: '🔗', label: 'Domain' },
        'url':     { color: '#8b5cf6', icon: '🔗', label: 'URL' },
        'hash':    { color: '#ef4444', icon: '#️⃣', label: 'Hash' },
        'md5':     { color: '#ef4444', icon: '#️⃣', label: 'MD5' },
        'sha1':    { color: '#f97316', icon: '#️⃣', label: 'SHA1' },
        'sha256':  { color: '#dc2626', icon: '#️⃣', label: 'SHA256' },
        'email':   { color: '#f59e0b', icon: '✉️', label: 'Email' },
        'cve':     { color: '#dc2626', icon: '🛡️', label: 'CVE' },
        'default': { color: '#64748b', icon: '📌', label: 'Diğer' }
    };

    // Merkez düğümü
    const centerNode = {
        id: 'center',
        label: reportTitle || 'Rapor',
        icon: '📄',
        type: 'center',
        color: '#c5a963',
        radius: 28,
        fx: null, // Simülasyon tarafından konumlandırılacak
        fy: null
    };
    nodes.push(centerNode);

    // Grup düğümleri (her IOC tipi bir grup)
    groupedIocs.forEach((group, gIdx) => {
        const typeLower = (group.type || 'default').toLowerCase();
        const config = typeConfig[typeLower] || typeConfig['default'];

        const groupNodeId = `group-${gIdx}`;
        const groupNode = {
            id: groupNodeId,
            label: `${config.label} (${group.count || group.values.length})`,
            icon: config.icon,
            type: 'group',
            color: config.color,
            radius: 18 + Math.min(group.values.length * 2, 14),
            iocType: typeLower
        };
        nodes.push(groupNode);
        links.push({ source: 'center', target: groupNodeId, strength: 0.7 });

        // Bireysel IOC düğümleri (en fazla 15 göster)
        const maxItems = Math.min(group.values.length, 15);
        for (let i = 0; i < maxItems; i++) {
            const val = group.values[i];
            const nodeId = `ioc-${gIdx}-${i}`;
            const displayVal = val.length > 24 ? val.substring(0, 22) + '…' : val;
            nodes.push({
                id: nodeId,
                label: displayVal,
                fullValue: val,
                icon: '',
                type: 'ioc',
                color: config.color,
                radius: 6,
                iocType: typeLower
            });
            links.push({ source: groupNodeId, target: nodeId, strength: 0.4 });
        }

        // Fazla IOC varsa "+X daha" düğümü
        if (group.values.length > maxItems) {
            const moreId = `more-${gIdx}`;
            nodes.push({
                id: moreId,
                label: `+${group.values.length - maxItems} daha`,
                icon: '',
                type: 'more',
                color: config.color,
                radius: 8,
                iocType: typeLower
            });
            links.push({ source: groupNodeId, target: moreId, strength: 0.3 });
        }
    });

    // ── Modal HTML ──────────────────────────────────────
    const backdrop = document.createElement('div');
    backdrop.className = 'soc-threat-graph-backdrop';
    backdrop.id = 'soc-threat-graph-backdrop';
    backdrop.addEventListener('click', closeThreatGraph);

    const modal = document.createElement('div');
    modal.className = 'soc-threat-graph-modal';
    modal.id = 'soc-threat-graph-modal';
    modal.innerHTML = `
        <div class="soc-threat-graph-header">
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:18px;">🕸️</span>
                <span class="soc-threat-graph-title">Tehdit Ağı Grafiği</span>
                <span class="soc-threat-graph-count">${nodes.length} düğüm · ${links.length} bağlantı</span>
            </div>
            <span class="soc-threat-graph-close" id="soc-threat-graph-close">✕</span>
        </div>
        <div class="soc-threat-graph-body" id="soc-threat-graph-body">
            <div class="soc-threat-graph-legend" id="soc-threat-graph-legend"></div>
            <div id="soc-threat-graph-svg-container" style="width:100%; height:100%; position:relative;"></div>
        </div>
    `;

    document.body.appendChild(backdrop);
    document.body.appendChild(modal);

    document.getElementById('soc-threat-graph-close').addEventListener('click', closeThreatGraph);
    document.addEventListener('keydown', _threatGraphEscHandler);

    // Legend oluştur
    const legendEl = document.getElementById('soc-threat-graph-legend');
    const usedTypes = new Set(groupedIocs.map(g => (g.type || 'default').toLowerCase()));
    usedTypes.forEach(t => {
        const cfg = typeConfig[t] || typeConfig['default'];
        const chip = document.createElement('span');
        chip.className = 'soc-threat-legend-chip';
        chip.innerHTML = `<span style="background:${cfg.color}; width:8px; height:8px; border-radius:50%; display:inline-block;"></span> ${cfg.icon} ${cfg.label}`;
        legendEl.appendChild(chip);
    });

    // ── D3.js Graph Render ──────────────────────────────
    _renderD3Graph(nodes, links);
}

function _threatGraphEscHandler(e) {
    if (e.key === 'Escape') closeThreatGraph();
}

function closeThreatGraph() {
    const b = document.getElementById('soc-threat-graph-backdrop');
    const m = document.getElementById('soc-threat-graph-modal');
    if (b) b.remove();
    if (m) m.remove();
    document.removeEventListener('keydown', _threatGraphEscHandler);
}

function _renderD3Graph(nodes, links) {
    const container = document.getElementById('soc-threat-graph-svg-container');
    if (!container || typeof d3 === 'undefined') {
        container.innerHTML = '<div style="text-align:center; color:#f87171; padding:40px;">D3.js yüklenemedi.</div>';
        return;
    }

    const width = container.clientWidth || 700;
    const height = container.clientHeight || 460;

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', [0, 0, width, height])
        .style('border-radius', '10px');

    // Zoom
    const zoomGroup = svg.append('g');
    const zoom = d3.zoom()
        .scaleExtent([0.3, 4])
        .on('zoom', (event) => {
            zoomGroup.attr('transform', event.transform);
        });
    svg.call(zoom);

    // Gradient definitions
    const defs = svg.append('defs');
    const radGrad = defs.append('radialGradient')
        .attr('id', 'centerGlow')
        .attr('cx', '50%').attr('cy', '50%').attr('r', '50%');
    radGrad.append('stop').attr('offset', '0%').attr('stop-color', '#c5a963').attr('stop-opacity', '0.3');
    radGrad.append('stop').attr('offset', '100%').attr('stop-color', '#c5a963').attr('stop-opacity', '0');

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(d => {
            if (d.source.type === 'center') return 120;
            if (d.source.type === 'group') return 60;
            return 40;
        }).strength(d => d.strength || 0.5))
        .force('charge', d3.forceManyBody().strength(d => {
            if (d.type === 'center') return -300;
            if (d.type === 'group') return -180;
            return -50;
        }))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.radius + 4));

    // Links
    const link = zoomGroup.append('g')
        .selectAll('line')
        .data(links)
        .join('line')
        .attr('stroke', 'rgba(148, 163, 184, 0.15)')
        .attr('stroke-width', d => d.strength > 0.5 ? 1.5 : 0.8);

    // Node groups
    const nodeGroup = zoomGroup.append('g')
        .selectAll('g')
        .data(nodes)
        .join('g')
        .call(d3.drag()
            .on('start', (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on('drag', (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on('end', (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            })
        )
        .style('cursor', 'grab');

    // Center glow
    nodeGroup.filter(d => d.type === 'center')
        .append('circle')
        .attr('r', d => d.radius + 15)
        .attr('fill', 'url(#centerGlow)');

    // Node circles
    nodeGroup.append('circle')
        .attr('r', d => d.radius)
        .attr('fill', d => {
            if (d.type === 'center') return '#c5a963';
            if (d.type === 'group') return d.color;
            return d.color;
        })
        .attr('fill-opacity', d => {
            if (d.type === 'center') return 1;
            if (d.type === 'group') return 0.85;
            return 0.5;
        })
        .attr('stroke', d => d.color)
        .attr('stroke-width', d => d.type === 'ioc' ? 1 : 2)
        .attr('stroke-opacity', d => d.type === 'ioc' ? 0.6 : 0.8);

    // Icons for center and groups
    nodeGroup.filter(d => d.type === 'center' || d.type === 'group')
        .append('text')
        .text(d => d.icon)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .attr('font-size', d => d.type === 'center' ? '18px' : '14px')
        .style('pointer-events', 'none');

    // Labels
    nodeGroup.append('text')
        .text(d => d.label)
        .attr('x', d => d.radius + 6)
        .attr('y', 3)
        .attr('font-size', d => {
            if (d.type === 'center') return '12px';
            if (d.type === 'group') return '11px';
            return '9px';
        })
        .attr('fill', d => {
            if (d.type === 'center') return '#c5a963';
            if (d.type === 'group') return '#e2e8f0';
            return '#94a3b8';
        })
        .attr('font-family', "'Inter', sans-serif")
        .attr('font-weight', d => d.type !== 'ioc' ? '600' : '400')
        .style('pointer-events', 'none');

    // Tooltip
    const tooltip = d3.select(container)
        .append('div')
        .attr('class', 'soc-threat-tooltip')
        .style('opacity', 0);

    nodeGroup
        .on('mouseenter', (event, d) => {
            if (d.type === 'ioc' && d.fullValue) {
                tooltip.html(`<strong>${d.iocType.toUpperCase()}</strong><br>${d.fullValue}`)
                    .style('opacity', 1)
                    .style('left', (event.offsetX + 12) + 'px')
                    .style('top', (event.offsetY - 10) + 'px');
            }
        })
        .on('mouseleave', () => {
            tooltip.style('opacity', 0);
        });

    // Tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
    });
}
