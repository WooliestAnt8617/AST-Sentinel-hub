/**
 * Audit form handling — tab switching, file upload preview, form submission.
 */

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initFileUpload();
    initFormSubmission();
    initFindingCards();
    initExportButton();
});

// ── Tab Switching ────────────────────────────────────────────────────────────

function initTabs() {
    const tabs = document.querySelectorAll('[data-tab]');
    const panels = document.querySelectorAll('[data-tab-panel]');

    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;

            tabs.forEach((t) => t.classList.remove('tab-btn--active'));
            tab.classList.add('tab-btn--active');

            panels.forEach((p) => {
                p.classList.toggle('tab-panel--active', p.dataset.tabPanel === target);
            });
        });
    });
}

// ── File Upload Preview ──────────────────────────────────────────────────────

function initFileUpload() {
    const zone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const preview = document.getElementById('file-preview');

    if (!zone || !fileInput) return;

    // Drag and drop effects
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('file-upload-zone--dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('file-upload-zone--dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('file-upload-zone--dragover');
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            showFilePreview(fileInput.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            showFilePreview(fileInput.files[0]);
        }
    });

    function showFilePreview(file) {
        if (!preview) return;

        const sizeKB = (file.size / 1024).toFixed(1);
        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        const displaySize = file.size > 1024 * 1024 ? `${sizeMB} MB` : `${sizeKB} KB`;

        preview.innerHTML = `
            <div class="file-selected">
                <span style="font-size: 1.25rem">📦</span>
                <span class="file-selected__name">${file.name}</span>
                <span class="file-selected__size">${displaySize}</span>
                <button type="button" class="file-selected__remove" onclick="clearFileInput()" title="Remove file">&times;</button>
            </div>
        `;
        preview.style.display = 'block';
    }
}

function clearFileInput() {
    const fileInput = document.getElementById('file-input');
    const preview = document.getElementById('file-preview');
    if (fileInput) fileInput.value = '';
    if (preview) {
        preview.innerHTML = '';
        preview.style.display = 'none';
    }
}

// ── Form Submission ──────────────────────────────────────────────────────────

function initFormSubmission() {
    const pasteForm = document.getElementById('paste-form');
    const uploadForm = document.getElementById('upload-form');

    if (pasteForm) {
        pasteForm.addEventListener('submit', (e) => {
            const code = document.getElementById('code-input')?.value?.trim();
            if (!code) {
                e.preventDefault();
                showToast('Please paste some code before submitting.', 'error');
                return;
            }
            showLoading('Analyzing your code with AI...');
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            const fileInput = document.getElementById('file-input');
            if (!fileInput?.files?.length) {
                e.preventDefault();
                showToast('Please select a ZIP file to upload.', 'error');
                return;
            }

            const file = fileInput.files[0];
            if (file.size > 10 * 1024 * 1024) {
                e.preventDefault();
                showToast('File exceeds 10MB limit.', 'error');
                return;
            }

            if (!file.name.toLowerCase().endsWith('.zip')) {
                e.preventDefault();
                showToast('Only .zip files are accepted.', 'error');
                return;
            }

            showLoading('Extracting and analyzing files...');
        });
    }
}

// ── Loading Overlay ──────────────────────────────────────────────────────────

function showLoading(message) {
    const overlay = document.getElementById('loading-overlay');
    const text = document.getElementById('loading-text');
    if (overlay) {
        overlay.classList.add('loading-overlay--visible');
        if (text) text.textContent = message || 'Processing...';
    }
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.classList.remove('loading-overlay--visible');
    }
}

// ── Toast Notifications ──────────────────────────────────────────────────────

function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        toast.style.transition = 'all 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── Expandable Finding Cards ─────────────────────────────────────────────────

function initFindingCards() {
    document.querySelectorAll('.finding-card').forEach((card) => {
        const header = card.querySelector('.finding-card__header');
        if (header) {
            header.addEventListener('click', () => {
                card.classList.toggle('finding-card--expanded');
            });
        }
    });
}

// ── Export Button ─────────────────────────────────────────────────────────────

function initExportButton() {
    const jsonBtn = document.getElementById('export-json');
    const mdBtn = document.getElementById('export-md');

    if (jsonBtn) {
        jsonBtn.addEventListener('click', async () => {
            const auditId = jsonBtn.dataset.auditId;
            try {
                const response = await fetch(`/api/audit/${auditId}/export?format=json`);
                const data = await response.json();
                downloadFile(
                    JSON.stringify(data, null, 2),
                    `audit-${auditId.slice(0, 8)}.json`,
                    'application/json'
                );
                showToast('JSON report downloaded!', 'success');
            } catch (error) {
                showToast('Failed to export report.', 'error');
            }
        });
    }

    if (mdBtn) {
        mdBtn.addEventListener('click', async () => {
            const auditId = mdBtn.dataset.auditId;
            try {
                const response = await fetch(`/api/audit/${auditId}/export?format=markdown`);
                const data = await response.json();
                downloadFile(data.markdown, data.filename, 'text/markdown');
                showToast('Markdown report downloaded!', 'success');
            } catch (error) {
                showToast('Failed to export report.', 'error');
            }
        });
    }
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
