// ClawGuard Dashboard JavaScript

const API_URL = 'http://127.0.0.1:19820';

// State
let panicMode = false;
let approvalQueue = [];

// DOM Elements
const statusBadge = document.getElementById('status-badge');
const panicBanner = document.getElementById('panic-banner');
const panicReason = document.getElementById('panic-reason');
const btnPanic = document.getElementById('btn-panic');
const btnResume = document.getElementById('btn-resume');
const panicReasonInput = document.getElementById('panic-reason-input');
const queueCount = document.getElementById('queue-count');
const approvalList = document.getElementById('approval-list');
const auditLogBody = document.getElementById('audit-log-body');
const statTotal = document.getElementById('stat-total');
const statBlocked = document.getElementById('stat-blocked');
const statApproved = document.getElementById('stat-approved');
const statDenied = document.getElementById('stat-denied');
const sanitizeInput = document.getElementById('sanitize-input');
const btnSanitize = document.getElementById('btn-sanitize');
const sanitizeResult = document.getElementById('sanitize-result');
const sanitizeOutput = document.getElementById('sanitize-output');
const commandInput = document.getElementById('command-input');
const btnCheckCommand = document.getElementById('btn-check-command');
const checkResult = document.getElementById('check-result');
const resultBadge = document.getElementById('result-badge');
const checkReason = document.getElementById('check-reason');
const btnRefreshLog = document.getElementById('btn-refresh-log');

// API Functions
async function apiGet(endpoint) {
    try {
        const response = await fetch(`${API_URL}${endpoint}`);
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        return null;
    }
}

async function apiPost(endpoint, data) {
    try {
        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        return null;
    }
}

// Update Status
async function updateStatus() {
    const data = await apiGet('/status');
    if (!data) {
        statusBadge.querySelector('.status-text').textContent = 'Offline';
        statusBadge.classList.add('panic');
        return;
    }

    // Panic status
    panicMode = data.panic?.state === 'panic';
    
    if (panicMode) {
        statusBadge.classList.add('panic');
        statusBadge.querySelector('.status-text').textContent = 'PANIC';
        panicBanner.classList.remove('hidden');
        if (data.panic?.current_panic?.reason) {
            panicReason.textContent = data.panic.current_panic.reason;
        }
    } else {
        statusBadge.classList.remove('panic');
        statusBadge.querySelector('.status-text').textContent = 'Normal';
        panicBanner.classList.add('hidden');
    }

    // Audit stats
    const audit = data.audit || {};
    statTotal.textContent = audit.total_operations || 0;
    statBlocked.textContent = audit.denied_count || 0;
    
    // Approval stats
    const approval = data.approval || {};
    statApproved.textContent = approval.approved || 0;
    statDenied.textContent = approval.denied || 0;
}

// Load Approval Queue
async function loadApprovalQueue() {
    const data = await apiGet('/approval/pending');
    if (!data) return;

    approvalQueue = data.requests || [];
    queueCount.textContent = approvalQueue.length;

    if (approvalQueue.length === 0) {
        approvalList.innerHTML = '<p class="empty-message">No pending approvals</p>';
        return;
    }

    approvalList.innerHTML = approvalQueue.map(item => `
        <div class="approval-item" data-id="${item.id}">
            <div class="approval-info">
                <div class="approval-type">${item.approval_type.toUpperCase()}</div>
                <div class="approval-operation">${escapeHtml(item.operation)}</div>
                <div class="approval-reason">${escapeHtml(item.reason)}</div>
            </div>
            <div class="approval-actions">
                <button class="btn btn-success btn-small" onclick="approveRequest('${item.id}')">Approve</button>
                <button class="btn btn-danger btn-small" onclick="denyRequest('${item.id}')">Deny</button>
            </div>
        </div>
    `).join('');
}

// Load Audit Log
async function loadAuditLog() {
    const data = await apiGet('/audit/logs?limit=50');
    if (!data || !data.logs) return;

    auditLogBody.innerHTML = data.logs.map(log => `
        <tr>
            <td>${formatTime(log.timestamp)}</td>
            <td>${log.action}</td>
            <td class="result-${log.result}">${log.result}</td>
            <td>${escapeHtml(truncate(log.operation, 40))}</td>
            <td>${escapeHtml(truncate(log.reason || '', 30))}</td>
        </tr>
    `).join('');
}

// Panic
async function triggerPanic() {
    const reason = panicReasonInput.value || 'Dashboard trigger';
    const result = await apiPost('/panic', { reason, trigger: 'dashboard', triggered_by: 'dashboard_user' });
    if (result) {
        panicReasonInput.value = '';
        await updateStatus();
    }
}

// Resume
async function triggerResume() {
    const result = await apiPost('/resume', { resolved_by: 'dashboard_user', reason: 'Dashboard resume' });
    if (result) {
        await updateStatus();
    }
}

// Approve Request
async function approveRequest(id) {
    const result = await apiPost('/approval/approve', { request_id: id, resolved_by: 'dashboard_user' });
    if (result) {
        await loadApprovalQueue();
    }
}

// Deny Request
async function denyRequest(id) {
    const result = await apiPost('/approval/deny', { request_id: id, resolved_by: 'dashboard_user' });
    if (result) {
        await loadApprovalQueue();
    }
}

// Sanitize Text
async function sanitizeText() {
    const text = sanitizeInput.value;
    if (!text) return;

    const result = await apiPost('/sanitize', { text });
    if (result) {
        sanitizeOutput.textContent = result.sanitized;
        sanitizeResult.classList.remove('hidden');
    }
}

// Check Command
async function checkCommand() {
    const command = commandInput.value;
    if (!command) return;

    const result = await apiPost('/check/command', { command });
    if (result) {
        resultBadge.textContent = result.allowed ? 'ALLOWED' : 'DENIED';
        resultBadge.className = 'result-badge ' + (result.allowed ? 'allowed' : 'denied');
        checkReason.textContent = result.reason;
        checkResult.classList.remove('hidden');
    }
}

// Helpers
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function truncate(text, length) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString();
}

// SSE Connection
function connectSSE() {
    // Approval SSE
    const approvalSource = new EventSource(`${API_URL}/approval/sse`);
    approvalSource.onmessage = (event) => {
        loadApprovalQueue();
    };
    approvalSource.onerror = () => {
        setTimeout(connectSSE, 5000);
    };

    // Panic SSE
    const panicSource = new EventSource(`${API_URL}/panic/sse`);
    panicSource.onmessage = (event) => {
        updateStatus();
    };
}

// Event Listeners
btnPanic.addEventListener('click', triggerPanic);
btnResume.addEventListener('click', triggerResume);
btnSanitize.addEventListener('click', sanitizeText);
btnCheckCommand.addEventListener('click', checkCommand);
btnRefreshLog.addEventListener('click', loadAuditLog);

commandInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') checkCommand();
});

sanitizeInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) sanitizeText();
});

// Initialize
async function init() {
    await updateStatus();
    await loadApprovalQueue();
    await loadAuditLog();
    connectSSE();

    // Refresh periodically
    setInterval(updateStatus, 30000);
    setInterval(loadAuditLog, 60000);
}

init();