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

// ── Form Submission with Live Loading Screen ──────────────────────────────────

async function submitFormWithLoading(form, opts = {}) {
    showLoading(opts.title || 'Analyzing your code with AI…', opts);

    try {
        const formData = new FormData(form);
        const response = await fetch(form.action, {
            method: 'POST',
            body: formData,
        });

        if (response.redirected) {
            window.location.href = response.url;
            return;
        }

        if (response.ok) {
            window.location.href = response.url;
            return;
        }

        // If not OK, handle error
        hideLoading();
        let errorMsg = 'Audit request failed. Please try again.';
        try {
            const errData = await response.json();
            if (errData && errData.detail) errorMsg = errData.detail;
        } catch (_) {
            try {
                const text = await response.text();
                if (text && text.length < 200) errorMsg = text;
            } catch (_) {}
        }
        showToast(errorMsg, 'error');

    } catch (err) {
        hideLoading();
        showToast('Network error: ' + (err.message || 'Unable to connect to auditor service'), 'error');
    }
}

function initFormSubmission() {
    const pasteForm = document.getElementById('paste-form');
    const uploadForm = document.getElementById('upload-form');
    const githubForm = document.getElementById('github-form');

    if (pasteForm) {
        pasteForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const code = document.getElementById('code-input')?.value?.trim();
            if (!code) {
                showToast('Please paste some code before submitting.', 'error');
                return;
            }
            submitFormWithLoading(pasteForm, {
                title: 'Analyzing your code with AI…',
                steps: [
                    'Preparing code snippet',
                    'Sending to Gemini AI',
                    'Deep analysis in progress',
                    'Building audit report',
                ],
            });
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('file-input');
            if (!fileInput?.files?.length) {
                showToast('Please select a ZIP file to upload.', 'error');
                return;
            }

            const file = fileInput.files[0];
            if (file.size > 10 * 1024 * 1024) {
                showToast('File exceeds 10MB limit.', 'error');
                return;
            }

            if (!file.name.toLowerCase().endsWith('.zip')) {
                showToast('Only .zip files are accepted.', 'error');
                return;
            }

            submitFormWithLoading(uploadForm, {
                title: 'Extracting and analyzing ZIP files…',
                steps: [
                    'Uploading ZIP archive',
                    'Extracting source files',
                    'Auditing each file with AI',
                    'Aggregating results',
                ],
                thoughts: [
                    'Uploading archive to server…',
                    'Extracting files from ZIP…',
                    'Detecting file languages…',
                    'Scanning file 1 for vulnerabilities…',
                    'Evaluating code complexity…',
                    'Checking for hardcoded secrets…',
                    'Reviewing error handling patterns…',
                    'Scanning next file…',
                    'Analyzing dependency imports…',
                    'Cross-referencing security best practices…',
                    'Computing per-file quality scores…',
                    'Aggregating findings across all files…',
                    'Ranking issues by severity…',
                    'Building comprehensive report…',
                    'Finalizing multi-file audit…',
                ],
            });
        });
    }

    if (githubForm) {
        githubForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const url = document.getElementById('github-url-input')?.value?.trim();
            if (!url) {
                showToast('Please enter a GitHub URL.', 'error');
                return;
            }
            const isRepo = !url.includes('/blob/') && !url.includes('/raw/') && !url.includes('raw.githubusercontent.com');

            if (isRepo) {
                submitFormWithLoading(githubForm, {
                    title: 'Fetching repository from GitHub…',
                    steps: [
                        'Downloading repository archive',
                        'Extracting source files',
                        'Auditing each file with AI',
                        'Compiling project report',
                    ],
                    thoughts: [
                        'Connecting to GitHub…',
                        'Downloading repository archive…',
                        'Extracting project structure…',
                        'Identifying key source files…',
                        'Scanning for security issues…',
                        'Evaluating code architecture…',
                        'Checking authentication patterns…',
                        'Reviewing API security…',
                        'Analyzing error propagation…',
                        'Inspecting data validation logic…',
                        'Computing code quality metrics…',
                        'Generating per-file summaries…',
                        'Ranking findings by impact…',
                        'Assembling project-wide report…',
                        'Finalizing repository audit…',
                    ],
                });
            } else {
                submitFormWithLoading(githubForm, {
                    title: 'Fetching file from GitHub…',
                    steps: [
                        'Fetching raw file content',
                        'Sending to Gemini AI',
                        'Deep analysis in progress',
                        'Building audit report',
                    ],
                    thoughts: [
                        'Connecting to GitHub…',
                        'Downloading raw file content…',
                        'Detecting programming language…',
                        'Parsing abstract syntax tree…',
                        'Scanning for vulnerabilities…',
                        'Evaluating complexity metrics…',
                        'Checking naming conventions…',
                        'Reviewing error handling…',
                        'Assessing performance patterns…',
                        'Scoring code quality…',
                        'Compiling recommendations…',
                        'Finalizing audit report…',
                    ],
                });
            }
        });
    }
}

// ── Loading Overlay — Dynamic Status Engine ──────────────────────────────────

let _loadingState = null;

/**
 * Show the loading overlay with rotating thinking messages, step timeline,
 * progress bar, elapsed timer, and helpful tips.
 *
 * @param {string} message - Primary title text
 * @param {object} [opts] - Optional overrides
 * @param {string[]} [opts.thoughts] - Custom array of thinking messages
 * @param {string[]} [opts.steps] - Custom array of step labels (4 items)
 * @param {string[]} [opts.tips] - Custom array of tip messages
 */
function showLoading(message, opts = {}) {
    // Clean up any previous loading state
    if (_loadingState) hideLoading();

    const overlay = document.getElementById('loading-overlay');
    const titleEl = document.getElementById('loading-text');
    const thinkingEl = document.getElementById('loading-thinking');
    const timerEl = document.getElementById('loading-timer');
    const progressBar = document.getElementById('loading-progress-bar');
    const tipEl = document.getElementById('loading-tip');
    const stepsContainer = document.getElementById('loading-steps');

    if (!overlay) return;

    // ── Default thought sequences ────────────────────────────────────────
    const defaultThoughts = [
        'Initializing AI engine…',
        'Parsing abstract syntax tree…',
        'Scanning for security vulnerabilities…',
        'Evaluating code complexity metrics…',
        'Checking error handling patterns…',
        'Analyzing naming conventions…',
        'Reviewing dependency usage…',
        'Detecting potential memory leaks…',
        'Inspecting authentication flows…',
        'Assessing API endpoint security…',
        'Evaluating input validation logic…',
        'Checking for hardcoded secrets…',
        'Analyzing exception handling depth…',
        'Reviewing concurrency patterns…',
        'Measuring cyclomatic complexity…',
        'Cross-referencing best practices…',
        'Building detailed findings report…',
        'Scoring code quality dimensions…',
        'Compiling recommendations…',
        'Finalizing audit results…',
    ];

    const defaultSteps = [
        'Preparing request',
        'Sending to AI engine',
        'Analyzing code patterns',
        'Generating report',
    ];

    const defaultTips = [
        '💡 Larger files take longer to analyze',
        '🔒 We check for OWASP Top 10 vulnerabilities',
        '⚡ Performance anti-patterns are flagged automatically',
        '🧮 Cyclomatic complexity is measured per function',
        '📋 Each finding includes a suggested fix',
        '🛡️ Powered by Google Gemini AI',
        '🔍 We analyze 50+ programming languages',
        '📊 Scores range from 0 (critical) to 100 (excellent)',
    ];

    const thoughts = opts.thoughts || defaultThoughts;
    const steps    = opts.steps    || defaultSteps;
    const tips     = opts.tips     || defaultTips;

    // Set title
    if (titleEl) titleEl.textContent = message || 'Analyzing your code…';

    // Update step labels
    if (stepsContainer) {
        const stepEls = stepsContainer.querySelectorAll('.loading-step');
        stepEls.forEach((el, i) => {
            const span = el.querySelector('span');
            if (span && steps[i]) span.textContent = steps[i];
            el.classList.remove('loading-step--active', 'loading-step--done');
        });
        if (stepEls[0]) stepEls[0].classList.add('loading-step--active');
    }

    // Reset progress
    if (progressBar) progressBar.style.width = '0%';

    // Show overlay
    overlay.classList.add('loading-overlay--visible');

    // ── State ────────────────────────────────────────────────────────────
    const startTime = Date.now();
    let thoughtIdx = 0;
    let tipIdx = 0;
    let currentStep = 0;

    // Step timing (seconds): when each step becomes active
    const stepTimings = [0, 3, 8, 18];

    // ── Timer — update every second ──────────────────────────────────────
    const timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        if (timerEl) {
            if (elapsed < 60) {
                timerEl.textContent = `${elapsed}s`;
            } else {
                const m = Math.floor(elapsed / 60);
                const s = elapsed % 60;
                timerEl.textContent = `${m}m ${s.toString().padStart(2, '0')}s`;
            }
        }

        // Progress bar — eases up to ~92% and plateaus
        if (progressBar) {
            const pct = Math.min(92, 10 + elapsed * 2.5 - elapsed * elapsed * 0.015);
            progressBar.style.width = `${Math.max(0, pct)}%`;
        }

        // Step advancement
        for (let i = stepTimings.length - 1; i >= 0; i--) {
            if (elapsed >= stepTimings[i] && currentStep < i) {
                currentStep = i;
                _advanceStep(stepsContainer, currentStep);
                break;
            }
        }
    }, 1000);

    // ── Thought rotation — every 3s ──────────────────────────────────────
    const thoughtInterval = setInterval(() => {
        thoughtIdx = (thoughtIdx + 1) % thoughts.length;
        if (thinkingEl) {
            thinkingEl.classList.add('fade-out');
            setTimeout(() => {
                thinkingEl.textContent = thoughts[thoughtIdx];
                thinkingEl.classList.remove('fade-out');
            }, 250);
        }
    }, 3000);

    // ── Tip rotation — every 6s ──────────────────────────────────────────
    const tipInterval = setInterval(() => {
        tipIdx = (tipIdx + 1) % tips.length;
        if (tipEl) {
            tipEl.classList.add('fade-out');
            setTimeout(() => {
                tipEl.textContent = tips[tipIdx];
                tipEl.classList.remove('fade-out');
            }, 300);
        }
    }, 6000);

    _loadingState = { timerInterval, thoughtInterval, tipInterval };
}

function _advanceStep(container, stepIdx) {
    if (!container) return;
    const steps = container.querySelectorAll('.loading-step');
    steps.forEach((el, i) => {
        el.classList.remove('loading-step--active', 'loading-step--done');
        if (i < stepIdx) {
            el.classList.add('loading-step--done');
        } else if (i === stepIdx) {
            el.classList.add('loading-step--active');
        }
    });
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    const progressBar = document.getElementById('loading-progress-bar');

    if (_loadingState) {
        clearInterval(_loadingState.timerInterval);
        clearInterval(_loadingState.thoughtInterval);
        clearInterval(_loadingState.tipInterval);
        _loadingState = null;
    }

    if (progressBar) progressBar.style.width = '100%';

    if (overlay) {
        setTimeout(() => {
            overlay.classList.remove('loading-overlay--visible');
            if (progressBar) progressBar.style.width = '0%';
        }, 300);
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
