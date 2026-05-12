// ClawGuard Dashboard - Enhanced Edition
// Handles: Stats, Panic, Approvals, Audit Log, Rule Management, Testing

const API_BASE = '';
let refreshInterval = null;

// =====================================
// Tab Switching
// =====================================

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Update tabs
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Update content
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(`${targetTab}-tab`).classList.add('active');
        
        // Load tab-specific data
        if (targetTab === 'rules') {
            loadRules();
        }
    });
});

// =====================================
// Initialize
// =====================================

async function init() {
    await refreshStatus();
    await refreshAuditLog();
    connectApprovalSSE();
    
    // Auto-refresh every 2 seconds (tightened for 60s approval window)
    refreshInterval = setInterval(refreshStatus, 2000);
    
    setupEventListeners();
}

function setupEventListeners() {
    // Panic button
    document.getElementById('btn-panic').addEventListener('click', triggerPanic);
    document.getElementById('btn-resume').addEventListener('click', resumeFromPanic);
    
    // Testing
    document.getElementById('btn-sanitize').addEventListener('click', testSanitize);
    document.getElementById('btn-detect-secrets').addEventListener('click', testDetectSecrets);
    document.getElementById('btn-check-command').addEventListener('click', testCommand);
    document.getElementById('btn-check-file').addEventListener('click', testFilePath);
    document.getElementById('btn-check-url').addEventListener('click', testURL);
    
    // Audit log refresh
    document.getElementById('btn-refresh-log').addEventListener('click', refreshAuditLog);
    
    // Rule management
    document.getElementById('btn-add-network-allow').addEventListener('click', () => addRule('network', 'allow'));
    document.getElementById('btn-add-network-deny').addEventListener('click', () => addRule('network', 'deny'));
    document.getElementById('btn-add-file-allow').addEventListener('click', () => addRule('file', 'allow'));
    document.getElementById('btn-add-file-deny').addEventListener('click', () => addRule('file', 'deny'));
}

// =====================================
// Status & Stats
// =====================================

async function refreshStatus() {
    try {
        const res = await fetch(`${API_BASE}/status`);
        const data = await res.json();
        
        // Update status badge
        updateStatusBadge(data.panic.state);
        
        // Update panic banner
        updatePanicBanner(data.panic);
        
        // Update stats
        updateStats(data.audit);
        
        // Update approval queue
        await refreshApprovalQueue();
        
    } catch (err) {
        console.error('Failed to fetch status:', err);
        document.getElementById('status-badge').innerHTML = `
            <span class="status-dot" style="background: #e0245e;"></span>
            <span class="status-text">Offline</span>
        `;
    }
}

function updateStatusBadge(state) {
    const badge = document.getElementById('status-badge');
    const dotColor = state === 'panicking' ? '#e0245e' : '#17bf63';
    const text = state === 'panicking' ? 'PANIC MODE' : 'Running';
    
    badge.innerHTML = `
        <span class="status-dot" style="background: ${dotColor};"></span>
        <span class="status-text">${text}</span>
    `;
}

function updatePanicBanner(panicData) {
    const banner = document.getElementById('panic-banner');
    
    if (panicData.is_panicking) {
        banner.classList.remove('hidden');
        const current = panicData.current_panic;
        document.getElementById('panic-reason').textContent = 
            current?.reason || 'All agent operations are blocked';
    } else {
        banner.classList.add('hidden');
    }
}

function updateStats(auditData) {
    document.getElementById('stat-total').textContent = auditData.total_operations || 0;
    document.getElementById('stat-blocked').textContent = auditData.denied_count || 0;
    
    // Calculate approved/denied from by_result
    const byResult = auditData.by_result || {};
    document.getElementById('stat-approved').textContent = byResult.allowed || 0;
    document.getElementById('stat-denied').textContent = byResult.denied || 0;
}

// =====================================
// Panic Control
// =====================================

async function triggerPanic() {
    const reason = document.getElementById('panic-reason-input').value || 'Manual trigger from dashboard';
    
    try {
        const res = await fetch(`${API_BASE}/panic`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                reason,
                trigger: 'dashboard',
                triggered_by: 'admin'
            })
        });
        
        if (res.ok) {
            await refreshStatus();
            document.getElementById('panic-reason-input').value = '';
        } else {
            alert('Failed to trigger panic');
        }
    } catch (err) {
        console.error(err);
        alert('Error triggering panic');
    }
}

async function resumeFromPanic() {
    try {
        const res = await fetch(`${API_BASE}/resume`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                resolved_by: 'admin',
                reason: 'Resumed from dashboard'
            })
        });
        
        if (res.ok) {
            await refreshStatus();
        } else {
            alert('Failed to resume');
        }
    } catch (err) {
        console.error(err);
        alert('Error resuming');
    }
}

// =====================================
// Approval Queue — SSE + countdown timers
// =====================================

let _approvalCountdownTimers = {};

function _clearApprovalTimers() {
    Object.values(_approvalCountdownTimers).forEach(t => clearInterval(t));
    _approvalCountdownTimers = {};
}

function _startCountdown(id, createdAt) {
    const TIMEOUT_MS = 60000;
    const el = document.getElementById(`countdown-${id}`);
    if (!el) return;
    const tick = () => {
        const elapsed = Date.now() - createdAt * 1000;
        const remaining = Math.max(0, Math.ceil((TIMEOUT_MS - elapsed) / 1000));
        if (el) el.textContent = `${remaining}s`;
        if (remaining <= 10 && el) el.style.color = '#e0245e';
        if (remaining === 0) clearInterval(_approvalCountdownTimers[id]);
    };
    tick();
    _approvalCountdownTimers[id] = setInterval(tick, 1000);
}

function _renderApprovalList(requests) {
    _clearApprovalTimers();
    const list = document.getElementById('approval-list');
    const count = requests.length;
    document.getElementById('queue-count').textContent = count;

    if (count === 0) {
        list.innerHTML = '<p class="empty-message">No pending approvals</p>';
        return;
    }

    list.innerHTML = requests.map(req => `
        <div class="approval-item" id="approval-item-${req.id}">
            <div class="approval-header">
                <span class="approval-type">${req.approval_type || req.type || ''}</span>
                <span class="approval-time">${new Date(req.created_at * 1000).toLocaleTimeString()}</span>
                <span class="approval-countdown" id="countdown-${req.id}">60s</span>
            </div>
            <div class="approval-operation" onclick="this.classList.toggle('expanded')" title="Click to expand/collapse">${req.operation}</div>
            <div class="approval-reason">${req.reason}</div>
            <div class="approval-actions">
                <button onclick="approveRequest('${req.id}')" class="btn btn-success btn-small">✓ Approve</button>
                <button onclick="denyRequest('${req.id}')" class="btn btn-danger btn-small">✗ Deny</button>
            </div>
        </div>
    `).join('');

    requests.forEach(req => _startCountdown(req.id, req.created_at));
}

async function refreshApprovalQueue() {
    try {
        const res = await fetch(`${API_BASE}/approval/pending`);
        const data = await res.json();
        _renderApprovalList(data.requests || []);
    } catch (err) {
        console.error('Failed to fetch approvals:', err);
    }
}

function connectApprovalSSE() {
    const es = new EventSource(`${API_BASE}/approval/sse`);

    es.addEventListener('initial', e => {
        const requests = JSON.parse(e.data);
        _renderApprovalList(requests);
    });

    es.addEventListener('new_request', e => {
        // New request arrived — re-render immediately
        refreshApprovalQueue();
    });

    es.addEventListener('approved', e => {
        const req = JSON.parse(e.data);
        const item = document.getElementById(`approval-item-${req.id}`);
        if (item) item.remove();
        clearInterval(_approvalCountdownTimers[req.id]);
        delete _approvalCountdownTimers[req.id];
        document.getElementById('queue-count').textContent =
            document.querySelectorAll('.approval-item').length;
    });

    es.addEventListener('denied', e => {
        const req = JSON.parse(e.data);
        const item = document.getElementById(`approval-item-${req.id}`);
        if (item) item.remove();
        clearInterval(_approvalCountdownTimers[req.id]);
        delete _approvalCountdownTimers[req.id];
        document.getElementById('queue-count').textContent =
            document.querySelectorAll('.approval-item').length;
    });

    es.addEventListener('timeout', e => {
        const req = JSON.parse(e.data);
        const item = document.getElementById(`approval-item-${req.id}`);
        if (item) item.remove();
        clearInterval(_approvalCountdownTimers[req.id]);
        delete _approvalCountdownTimers[req.id];
        document.getElementById('queue-count').textContent =
            document.querySelectorAll('.approval-item').length;
    });

    es.onerror = () => {
        // SSE dropped — fall back to polling until reconnect
        setTimeout(connectApprovalSSE, 3000);
        es.close();
    };
}

async function approveRequest(id) {
    try {
        await fetch(`${API_BASE}/approval/approve`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                request_id: id,
                resolved_by: 'admin'
            })
        });
        await refreshApprovalQueue();
    } catch (err) {
        alert('Failed to approve');
    }
}

async function denyRequest(id) {
    try {
        await fetch(`${API_BASE}/approval/deny`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                request_id: id,
                resolved_by: 'admin',
                reason: 'Denied from dashboard'
            })
        });
        await refreshApprovalQueue();
    } catch (err) {
        alert('Failed to deny');
    }
}

// =====================================
// Audit Log
// =====================================

async function refreshAuditLog() {
    try {
        const res = await fetch(`${API_BASE}/audit/logs?limit=20`);
        const data = await res.json();
        
        const tbody = document.getElementById('audit-log-body');
        
        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No logs</td></tr>';
            return;
        }
        
        tbody.innerHTML = data.logs.map(log => `
            <tr>
                <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
                <td>${log.action}</td>
                <td><span class="badge badge-${log.result}">${log.result}</span></td>
                <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis;">${log.operation}</td>
                <td>${log.reason || '-'}</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to fetch audit log:', err);
    }
}

// =====================================
// Testing Tools
// =====================================

async function testSanitize() {
    const input = document.getElementById('sanitize-input').value;
    if (!input) {
        alert('Please enter text to sanitize');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/sanitize`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: input})
        });
        
        const data = await res.json();
        
        document.getElementById('sanitize-result').classList.remove('hidden');
        document.getElementById('sanitize-output').textContent = data.sanitized || data.sanitized_text || 'No result';
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function testDetectSecrets() {
    const input = document.getElementById('sanitize-input').value;
    if (!input) {
        alert('Please enter text to check for secrets');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/detect-secrets`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: input})
        });
        
        const data = await res.json();
        
        document.getElementById('sanitize-result').classList.remove('hidden');
        
        if (data.count === 0) {
            document.getElementById('sanitize-output').textContent = '✅ No secrets detected';
        } else {
            document.getElementById('sanitize-output').textContent = 
                `🚨 ${data.count} secret(s) detected:\n\n` +
                data.secrets.map((s, i) => `${i+1}. Type: ${s.type}\n   Value: ${s.value}`).join('\n\n');
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function testCommand() {
    const cmd = document.getElementById('command-input').value;
    if (!cmd) {
        alert('Please enter a command');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/check/command`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({command: cmd})
        });
        
        const data = await res.json();
        
        const result = document.getElementById('check-result');
        const badge = document.getElementById('result-badge');
        const reason = document.getElementById('check-reason');
        
        result.classList.remove('hidden');
        
        if (data.allowed) {
            badge.textContent = '✅ ALLOWED';
            badge.style.background = '#17bf63';
        } else if (data.action === 'approve') {
            badge.textContent = '⏸️ REQUIRES APPROVAL';
            badge.style.background = '#ffad1f';
        } else {
            badge.textContent = '🛑 BLOCKED';
            badge.style.background = '#e0245e';
        }
        
        reason.textContent = data.reason || 'No reason provided';
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function testFilePath() {
    const path = document.getElementById('file-path-input').value;
    if (!path) {
        alert('Please enter a file path');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/check/file`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({path, operation: 'read'})
        });
        
        const data = await res.json();
        
        const result = document.getElementById('file-check-result');
        const badge = document.getElementById('file-result-badge');
        const reason = document.getElementById('file-check-reason');
        
        result.classList.remove('hidden');
        
        if (data.allowed) {
            badge.textContent = '✅ ALLOWED';
            badge.style.background = '#17bf63';
        } else if (data.action === 'approve') {
            badge.textContent = '⏸️ REQUIRES APPROVAL';
            badge.style.background = '#ffad1f';
        } else {
            badge.textContent = '🛑 BLOCKED';
            badge.style.background = '#e0245e';
        }
        
        reason.textContent = data.reason || 'No reason provided';
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

async function testURL() {
    const url = document.getElementById('url-input').value;
    if (!url) {
        alert('Please enter a URL');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/check/network`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        
        const data = await res.json();
        
        const result = document.getElementById('url-check-result');
        const badge = document.getElementById('url-result-badge');
        const reason = document.getElementById('url-check-reason');
        
        result.classList.remove('hidden');
        
        if (data.allowed) {
            badge.textContent = '✅ ALLOWED';
            badge.style.background = '#17bf63';
        } else if (data.action === 'approve') {
            badge.textContent = '⏸️ REQUIRES APPROVAL';
            badge.style.background = '#ffad1f';
        } else {
            badge.textContent = '🛑 BLOCKED';
            badge.style.background = '#e0245e';
        }
        
        reason.textContent = data.reason || 'No reason provided';
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// =====================================
// Rule Management
// =====================================

async function loadRules() {
    try {
        const res = await fetch(`${API_BASE}/rules/list`);
        const data = await res.json();
        
        // Task scope (top of page)
        renderTaskScope(data.task_scope);
        
        // Network allowed
        renderRuleList('network-allow-list', data.network.allowed_domains, 'network', 'allow');
        
        // Network denied
        renderRuleList('network-deny-list', data.network.denied_domains, 'network', 'deny');
        
        // File allowed
        renderRuleList('file-allow-list', data.file.allowed_paths, 'file', 'allow');
        
        // File denied
        renderRuleList('file-deny-list', data.file.denied_paths, 'file', 'deny');
        
    } catch (err) {
        console.error('Failed to load rules:', err);
    }
}

function renderRuleList(elementId, rules, type, action) {
    const container = document.getElementById(elementId);
    
    if (!rules || rules.length === 0) {
        container.innerHTML = '<p class="empty-list">No rules</p>';
        return;
    }
    
    container.innerHTML = rules.map(rule => `
        <div class="rule-item">
            <span class="rule-text">${escapeHtml(rule)}</span>
            <button class="btn-remove" data-rule-type="${type}" data-rule-action="${action}" data-rule-value="${escapeHtml(rule)}">Remove</button>
        </div>
    `).join('');

    container.querySelectorAll('.btn-remove').forEach(button => {
        button.addEventListener('click', () => removeRule(
            button.dataset.ruleType,
            button.dataset.ruleAction,
            button.dataset.ruleValue
        ));
    });
}

async function addRule(type, action) {
    const inputId = `${type}-${action}-input`;
    const input = document.getElementById(inputId);
    const value = input.value.trim();
    
    if (!value) {
        alert('Please enter a value');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/rules/${type}/${action}?${type === 'network' ? 'domain' : 'path'}=${encodeURIComponent(value)}`, {
            method: 'POST'
        });
        
        const data = await res.json();
        
        if (data.status === 'added') {
            input.value = '';
            await loadRules();
        } else if (data.status === 'already_exists') {
            alert('Rule already exists');
        }
    } catch (err) {
        alert('Error adding rule: ' + err.message);
    }
}

async function removeRule(type, action, value) {
    try {
        const endpoint = type === 'network' 
            ? `${API_BASE}/rules/${type}/${action}/${encodeURIComponent(value)}`
            : `${API_BASE}/rules/${type}/${action}?path=${encodeURIComponent(value)}`;
        
        const res = await fetch(endpoint, {
            method: 'DELETE'
        });
        
        if (res.ok) {
            await loadRules();
        }
    } catch (err) {
        alert('Error removing rule: ' + err.message);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// =====================================
// Audit Log Download
// =====================================

async function downloadAuditLog(filtered = false) {
    try {
        let url = `${API_BASE}/audit/download`;
        
        if (filtered) {
            const params = new URLSearchParams();
            
            // Get filter values
            const startTime = document.getElementById('download-start-time').value;
            const endTime = document.getElementById('download-end-time').value;
            const action = document.getElementById('download-action').value;
            const result = document.getElementById('download-result').value;
            
            // Convert datetime-local to Unix timestamp
            if (startTime) {
                const timestamp = new Date(startTime).getTime() / 1000;
                params.append('start_time', timestamp.toString());
            }
            if (endTime) {
                const timestamp = new Date(endTime).getTime() / 1000;
                params.append('end_time', timestamp.toString());
            }
            if (action) {
                params.append('action', action);
            }
            if (result) {
                params.append('result', result);
            }
            
            const queryString = params.toString();
            if (queryString) {
                url += '?' + queryString;
            }
        }
        
        // Fetch the file
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error('Download failed');
        }
        
        // Get the blob
        const blob = await response.blob();
        
        // Extract filename from Content-Disposition header or use default
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = 'clawguard_audit.json';
        if (contentDisposition) {
            const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(contentDisposition);
            if (matches && matches[1]) {
                filename = matches[1].replace(/['"]/g, '');
            }
        }
        
        // Create download link
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        
        // Show success message
        const btn = filtered ? document.getElementById('btn-download-filtered') : document.getElementById('btn-download-log');
        const originalText = btn.textContent;
        btn.textContent = '✅ Downloaded!';
        btn.style.background = '#17bf63';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);
        
    } catch (err) {
        console.error('Download error:', err);
        alert('Failed to download audit log: ' + err.message);
    }
}

function clearDownloadFilters() {
    document.getElementById('download-start-time').value = '';
    document.getElementById('download-end-time').value = '';
    document.getElementById('download-action').value = '';
    document.getElementById('download-result').value = '';
}

// =====================================
// Task Scope Display
// =====================================

function renderTaskScope(taskScope) {
    const badge = document.getElementById('task-scope-badge');
    const inactive = document.getElementById('task-scope-inactive');
    const details = document.getElementById('task-scope-details');
    const clearBtn = document.getElementById('clear-scope-btn');
    const lockBtn = document.getElementById('task-scope-lock-btn');
    const locked = !!(taskScope && taskScope.locked);

    if (lockBtn) {
        lockBtn.textContent = locked ? '🔓 Enable Task Scope' : '🔒 Base Rules Only';
        lockBtn.disabled = !!(taskScope && taskScope.active);
        lockBtn.style.opacity = (taskScope && taskScope.active) ? '0.6' : '1';
        lockBtn.title = (taskScope && taskScope.active)
            ? 'Clear the active task scope before toggling base-rules-only mode'
            : (locked ? 'Allow agents to use task scope again' : 'Prevent future task scope from being set');
    }

    if (!taskScope || !taskScope.active) {
        badge.textContent = locked ? 'Locked (Base Rules Only)' : 'Inactive';
        badge.style.background = locked ? '#f5a623' : '#657786';
        inactive.style.display = '';
        inactive.textContent = locked
            ? 'Task scope is locked. Only base rules are active; future set_task_scope calls will be rejected.'
            : 'No task scope active — agent has not declared per-task restrictions.';
        details.style.display = 'none';
        if (clearBtn) clearBtn.style.display = 'none';
        return;
    }

    badge.textContent = 'Active';
    badge.style.background = '#17bf63';
    inactive.style.display = 'none';
    details.style.display = '';
    if (clearBtn) clearBtn.style.display = '';

    const rules = taskScope.rules || {};

    renderScopeList('task-scope-file-read', rules.file_read);
    renderScopeList('task-scope-file-write', rules.file_write);
    renderScopeList('task-scope-commands', rules.commands);
    renderScopeList('task-scope-network', rules.network);

    const disabled = rules.disabled_tools || rules.disable_tools || [];
    const disabledSection = document.getElementById('task-scope-disabled-tools');
    if (disabled.length > 0) {
        disabledSection.style.display = '';
        renderScopeList('task-scope-disabled-list', disabled);
    } else {
        disabledSection.style.display = 'none';
    }
}

async function toggleTaskScopeLock() {
    try {
        const statusRes = await fetch(`${API_BASE}/status`);
        const status = await statusRes.json();
        const active = !!(status.task_scope && status.task_scope.active);
        const locked = !!(status.task_scope && status.task_scope.locked);

        if (active) {
            alert('Cannot toggle base-rules-only mode while a task scope is active. Clear the current task scope first.');
            return;
        }

        const endpoint = locked ? '/task-scope/unlock' : '/task-scope/lock';
        const res = await fetch(`${API_BASE}${endpoint}`, { method: 'POST' });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            return;
        }
        await refreshStatus();
        await loadRules();
    } catch (err) {
        alert('Failed to toggle task scope lock: ' + err.message);
    }
}

async function clearTaskScope() {
    try {
        const res = await fetch(`${API_BASE}/task-scope/clear`, { method: 'POST' });
        if (!res.ok) {
            // Fallback for older backend: use tool-call route if direct endpoint doesn't exist
            const alt = await fetch(`${API_BASE}/api/tool/call`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tool: 'clear_task_scope', input: {} })
            });
            const altData = await alt.json();
            if (altData.error) throw new Error(altData.error);
        }
        await refreshStatus();
        await loadRules();
    } catch (err) {
        alert('Failed to clear task scope: ' + err.message);
    }
}

function renderScopeList(elementId, items) {
    const el = document.getElementById(elementId);
    if (!items || items.length === 0) {
        el.innerHTML = '<p class="empty-list" style="padding: 0.25rem; font-size: 0.85rem;">None</p>';
        return;
    }
    el.innerHTML = items.map(item => `
        <div class="rule-item" style="padding: 0.25rem 0.5rem;">
            <span class="rule-text" style="font-size: 0.85rem;">${escapeHtml(String(item))}</span>
        </div>
    `).join('');
}

// =====================================
// Rules Download
// =====================================

async function downloadRules() {
    try {
        const res = await fetch(`${API_BASE}/rules/list`);
        const data = await res.json();

        const payload = {
            exported_at: new Date().toISOString(),
            task_scope: data.task_scope || { active: false, rules: {} },
            base_rules: {
                network: data.network,
                file: data.file,
            },
        };

        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `clawguard_rules_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        document.body.removeChild(a);

        const btn = document.getElementById('btn-download-rules');
        const orig = btn.textContent;
        btn.textContent = '\u2705 Downloaded!';
        btn.style.background = '#17bf63';
        setTimeout(() => { btn.textContent = orig; btn.style.background = '#1da1f2'; }, 2000);
    } catch (err) {
        alert('Failed to download rules: ' + err.message);
    }
}

// =====================================
// Start
// =====================================

init();

// Setup download button listeners after init
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-download-log').addEventListener('click', () => downloadAuditLog(false));
    document.getElementById('btn-download-filtered').addEventListener('click', () => downloadAuditLog(true));
    document.getElementById('btn-clear-filters').addEventListener('click', clearDownloadFilters);
    document.getElementById('btn-download-rules').addEventListener('click', downloadRules);
});
