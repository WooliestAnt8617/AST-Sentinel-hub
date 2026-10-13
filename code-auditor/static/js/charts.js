/**
 * Chart.js initialization and configuration for the analytics dashboard.
 * Fetches data from /api/analytics and renders all charts.
 */

// Chart.js global defaults for dark theme
function setChartDefaults() {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.color = '#f4f4f5';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.08)';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.plugins.legend.labels.color = '#f4f4f5';
    Chart.defaults.plugins.legend.labels.font = { family: "'Inter', sans-serif", size: 12, weight: '500' };
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
    Chart.defaults.plugins.legend.labels.padding = 16;
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(24, 24, 27, 0.95)';
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.08)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.titleFont = { weight: '600' };
}

// Severity color mapping
const SEVERITY_COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280',
};

const SEVERITY_BG_COLORS = {
    critical: 'rgba(239, 68, 68, 0.15)',
    high: 'rgba(249, 115, 22, 0.15)',
    medium: 'rgba(234, 179, 8, 0.15)',
    low: 'rgba(59, 130, 246, 0.15)',
    info: 'rgba(107, 114, 128, 0.15)',
};

const CATEGORY_COLORS = [
    '#818cf8', '#c084fc', '#f472b6', '#fb923c',
    '#34d399', '#38bdf8', '#a78bfa', '#fbbf24',
];

// ── Fetch Analytics Data ─────────────────────────────────────────────────────

async function fetchAnalytics() {
    try {
        const response = await fetch('/api/analytics');
        if (!response.ok) throw new Error('Failed to fetch analytics');
        return await response.json();
    } catch (error) {
        console.error('Analytics fetch error:', error);
        return null;
    }
}

// ── Render Charts ────────────────────────────────────────────────────────────

function renderTopLanguagesChart(data) {
    const canvas = document.getElementById('chart-languages');
    if (!canvas || !data || data.length === 0) return;

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: data.map((d) => d.language),
            datasets: [
                {
                    label: 'Audits',
                    data: data.map((d) => d.count),
                    backgroundColor: data.map((_, i) => {
                        const colors = [
                            'rgba(129, 140, 248, 0.7)',
                            'rgba(167, 139, 250, 0.7)',
                            'rgba(192, 132, 252, 0.7)',
                            'rgba(244, 114, 182, 0.7)',
                            'rgba(251, 146, 60, 0.7)',
                            'rgba(52, 211, 153, 0.7)',
                            'rgba(56, 189, 248, 0.7)',
                            'rgba(251, 191, 36, 0.7)',
                        ];
                        return colors[i % colors.length];
                    }),
                    borderRadius: 6,
                    borderSkipped: false,
                    barThickness: 28,
                },
            ],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { precision: 0 },
                },
                y: {
                    grid: { display: false },
                },
            },
        },
    });
}

function renderSeverityChart(data) {
    const canvas = document.getElementById('chart-severity');
    if (!canvas || !data || data.length === 0) return;

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: data.map((d) => d.severity.charAt(0).toUpperCase() + d.severity.slice(1)),
            datasets: [
                {
                    data: data.map((d) => d.count),
                    backgroundColor: data.map((d) => SEVERITY_COLORS[d.severity] || '#6b7280'),
                    borderColor: 'rgba(9, 9, 11, 0.8)',
                    borderWidth: 3,
                    hoverOffset: 8,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#f4f4f5',
                        font: { size: 13, weight: '500' },
                        generateLabels: function(chart) {
                            const dataset = chart.data.datasets[0];
                            return chart.data.labels.map((label, i) => ({
                                text: `${label} (${dataset.data[i]})`,
                                fillStyle: dataset.backgroundColor[i],
                                strokeStyle: 'transparent',
                                fontColor: '#f4f4f5',
                                pointStyle: 'circle',
                                index: i,
                            }));
                        },
                    },
                },
            },
        },
    });
}

function renderCategoryChart(data) {
    const canvas = document.getElementById('chart-categories');
    if (!canvas || !data || data.length === 0) return;

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: data.map((d) => d.category),
            datasets: [
                {
                    label: 'Findings',
                    data: data.map((d) => d.count),
                    backgroundColor: data.map((_, i) => CATEGORY_COLORS[i % CATEGORY_COLORS.length]),
                    borderRadius: 6,
                    borderSkipped: false,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { precision: 0 },
                    beginAtZero: true,
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        maxRotation: 45,
                        font: { size: 11 },
                    },
                },
            },
        },
    });
}

function renderScoresOverTimeChart(data) {
    const canvas = document.getElementById('chart-scores-time');
    if (!canvas || !data || data.length === 0) return;

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: data.map((d) => d.date),
            datasets: [
                {
                    label: 'Overall',
                    data: data.map((d) => d.avg_overall),
                    borderColor: '#818cf8',
                    backgroundColor: 'rgba(129, 140, 248, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    borderWidth: 2,
                },
                {
                    label: 'Security',
                    data: data.map((d) => d.avg_security),
                    borderColor: '#ef4444',
                    backgroundColor: 'transparent',
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                    borderDash: [4, 4],
                },
                {
                    label: 'Performance',
                    data: data.map((d) => d.avg_performance),
                    borderColor: '#22c55e',
                    backgroundColor: 'transparent',
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                    borderDash: [4, 4],
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: {
                    position: 'top',
                },
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    min: 0,
                    max: 100,
                    ticks: { stepSize: 20 },
                },
                x: {
                    grid: { display: false },
                },
            },
        },
    });
}

// ── Render Heatmap ───────────────────────────────────────────────────────────

function renderHeatmap(data) {
    const container = document.getElementById('heatmap-container');
    if (!container || !data || !data.topics || data.topics.length === 0) {
        if (container) {
            container.innerHTML = '<div class="empty-state"><p class="text-sm">No topic data available yet.</p></div>';
        }
        return;
    }

    let html = '<table class="heatmap-table"><thead><tr><th>Topic</th>';
    data.severities.forEach((s) => {
        html += `<th>${s.charAt(0).toUpperCase() + s.slice(1)}</th>`;
    });
    html += '</tr></thead><tbody>';

    data.topics.forEach((topic) => {
        html += `<tr><td>${topic.name}</td>`;
        const maxCount = Math.max(...topic.counts, 1);
        topic.counts.forEach((count, i) => {
            const severity = data.severities[i];
            const intensity = count / maxCount;
            const color = SEVERITY_COLORS[severity] || '#6b7280';
            const bg = intensity > 0
                ? `rgba(${hexToRgb(color)}, ${0.08 + intensity * 0.35})`
                : 'transparent';
            html += `<td class="heatmap-cell" style="background: ${bg}; color: ${count > 0 ? color : 'var(--text-muted)'}">${count || '—'}</td>`;
        });
        html += '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function hexToRgb(hex) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `${r}, ${g}, ${b}`;
}

// ── Render Platform Health ───────────────────────────────────────────────────

function renderPlatformHealth(health) {
    const container = document.getElementById('health-container');
    if (!container || !health) return;

    const trendEmoji = {
        improving: '📈',
        declining: '📉',
        neutral: '➡️',
    };

    const trendLabel = {
        improving: 'Improving',
        declining: 'Declining',
        neutral: 'Stable',
    };

    let worstLangsHtml = '';
    if (health.worst_languages && health.worst_languages.length > 0) {
        worstLangsHtml = health.worst_languages
            .map((l) => `${l.language} (${l.avg_score})`)
            .join(', ');
    } else {
        worstLangsHtml = 'N/A';
    }

    container.innerHTML = `
        <div class="health-item glass-card">
            <div class="health-item__label">Average Overall Score</div>
            <div class="health-item__value gradient-text">${health.avg_score || 0}/100</div>
        </div>
        <div class="health-item glass-card">
            <div class="health-item__label">Most Common Issue</div>
            <div class="health-item__value">${health.most_common_category || 'N/A'}</div>
        </div>
        <div class="health-item glass-card">
            <div class="health-item__label">Needs Improvement</div>
            <div class="health-item__value">${worstLangsHtml}</div>
            <div class="health-item__sub">Languages with lowest scores</div>
        </div>
        <div class="health-item glass-card">
            <div class="health-item__label">Score Trend</div>
            <div class="health-item__value">
                <span class="trend-badge trend-badge--${health.trend}">
                    ${trendEmoji[health.trend] || '➡️'} ${trendLabel[health.trend] || 'Stable'}
                </span>
            </div>
        </div>
    `;
}

// ── Update Counters ──────────────────────────────────────────────────────────

function updateCounters(counters) {
    const mapping = {
        'counter-audits': counters.total_audits,
        'counter-languages': counters.unique_languages,
        'counter-critical': counters.critical_issues,
        'counter-files': counters.total_files,
    };

    for (const [id, value] of Object.entries(mapping)) {
        const el = document.getElementById(id);
        if (el) {
            el.dataset.countTarget = value;
            el.textContent = '0';
        }
    }
}

// ── Initialize Dashboard ─────────────────────────────────────────────────────

async function initDashboard() {
    setChartDefaults();

    const data = await fetchAnalytics();
    if (!data) {
        document.getElementById('dashboard-loading')?.remove();
        return;
    }

    // Update counters
    updateCounters(data.counters);

    // Render charts
    renderTopLanguagesChart(data.top_languages);
    renderSeverityChart(data.severity_distribution);
    renderCategoryChart(data.category_breakdown);
    renderScoresOverTimeChart(data.scores_over_time);

    // Render heatmap
    renderHeatmap(data.heatmap);

    // Render platform health
    renderPlatformHealth(data.platform_health);

    // Remove loading state
    document.getElementById('dashboard-loading')?.remove();

    // Re-trigger scroll animations for counters
    if (typeof initScrollAnimations === 'function') {
        initScrollAnimations();
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('analytics-page')) {
        initDashboard();
    }
});
