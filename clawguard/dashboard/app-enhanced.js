// ClawGuard Dashboard - Enhanced Edition
// Handles: Stats, Panic, Approvals, Audit Log, Rule Management, Testing

const API_BASE = '';
let refreshInterval = null;
let auditInterval = null;
let skillInterval = null;
let statusRequestVersion = 0;
let latestTaskScope = null;
let taskScopeToggleInFlight = false;
let currentSkillName = null;

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
        } else if (targetTab === 'skills') {
            closeSkillDetail(false);
            loadSkillInspector();
        }
    });
});

// =====================================
// Initialize
// =====================================

async function init() {
    await refreshStatus();
    await refreshAuditLog();
    await refreshApprovalHistory();
    connectApprovalSSE();
    
    startPolling();
    setupEventListeners();
}

// =====================================
// Auto-refresh
// =====================================
// Status (which carries the task scope) every 2s, audit log every 3s, so a new
// decision shows up without reloading.  Polling stops while the tab is hidden
// and resumes with an immediate refresh, so an unwatched dashboard is idle.
function startPolling() {
    if (refreshInterval === null) {
        refreshInterval = setInterval(refreshStatus, 2000);
    }
    if (auditInterval === null) {
        auditInterval = setInterval(refreshAuditLog, 3000);
    }
    if (skillInterval === null) {
        skillInterval = setInterval(() => {
            if (document.getElementById('skills-tab').classList.contains('active')) {
                loadSkillInspector();
            }
        }, 4000);
    }
}

function stopPolling() {
    if (refreshInterval !== null) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
    if (auditInterval !== null) {
        clearInterval(auditInterval);
        auditInterval = null;
    }
    if (skillInterval !== null) {
        clearInterval(skillInterval);
        skillInterval = null;
    }
}

document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopPolling();
        return;
    }
    refreshStatus();
    refreshAuditLog();
    startPolling();
});

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
    document.getElementById('btn-refresh-approval-history').addEventListener(
        'click',
        refreshApprovalHistory,
    );
    
    // Rule management
    document.getElementById('btn-add-network-allow').addEventListener('click', () => addRule('network', 'allow'));
    document.getElementById('btn-add-network-deny').addEventListener('click', () => addRule('network', 'deny'));
    document.getElementById('btn-add-file-allow').addEventListener('click', () => addRule('file', 'allow'));
    document.getElementById('btn-add-file-deny').addEventListener('click', () => addRule('file', 'deny'));
    document.getElementById('btn-add-command-allow').addEventListener('click', () => addCommandRule('allow'));
    document.getElementById('btn-add-command-deny').addEventListener('click', () => addCommandRule('deny'));

    // Skill Inspector
    document.getElementById('btn-refresh-skills').addEventListener('click', loadSkillInspector);
    document.getElementById('btn-close-skill-detail').addEventListener(
        'click',
        () => closeSkillDetail(),
    );
    document.getElementById('btn-override-safe').addEventListener('click', () => setSkillOverride('safe'));
    document.getElementById('btn-override-unsafe').addEventListener('click', () => setSkillOverride('unsafe'));
    document.getElementById('btn-clear-override').addEventListener('click', () => setSkillOverride(null));
}

// =====================================
// Status & Stats
// =====================================

async function refreshStatus() {
    const requestVersion = ++statusRequestVersion;
    try {
        const res = await fetch(`${API_BASE}/status`);
        const data = await res.json();
        if (requestVersion !== statusRequestVersion) return;
        
        // Update status badge
        updateStatusBadge(
            data.panic.state,
            data.agent,
            data.upstream_format,
            data.data_dir,
        );
        
        // Update panic banner
        updatePanicBanner(data.panic);
        
        // Update stats
        // The status endpoint also exposes the native-tool-only view.  Keep
        // transport/audit bookkeeping out of the user-facing counters.
        updateStats(data.native_tool_audit || data.audit);
        
        // The task scope travels in the same payload.  Render it before the
        // independent approval-queue request so lock/unlock controls react
        // immediately even when that request is slow.
        renderTaskScope(data.task_scope);
        void refreshApprovalQueue();

    } catch (err) {
        if (requestVersion !== statusRequestVersion) return;
        console.error('Failed to fetch status:', err);
        document.getElementById('status-badge').innerHTML = `
            <span class="status-dot" style="background: #e0245e;"></span>
            <span class="status-text">Offline</span>
        `;
    }
}

function updateStatusBadge(state, agent, upstreamFormat, dataDir) {
    const badge = document.getElementById('status-badge');
    const dotColor = state === 'panicking' ? '#e0245e' : '#17bf63';
    const agentLabel = String(agent || 'openclaw').toUpperCase();
    const status = state === 'panicking' ? 'PANIC MODE' : 'Running';
    badge.title = `Agent: ${agentLabel}\nUpstream: ${upstreamFormat || 'unknown'}\nData: ${dataDir || 'unknown'}`;
    
    badge.innerHTML = `
        <span class="status-dot" style="background: ${dotColor};"></span>
        <span class="status-text">${agentLabel} · ${status}</span>
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
        <div class="approval-item" id="approval-item-${escapeHtml(req.id)}">
            <div class="approval-header">
                <span class="approval-type">${escapeHtml(req.approval_type || req.type || '')}</span>
                <span class="approval-time">${new Date(req.created_at * 1000).toLocaleTimeString()}</span>
                <span class="approval-countdown" id="countdown-${escapeHtml(req.id)}">60s</span>
            </div>
            <div class="approval-operation" onclick="this.classList.toggle('expanded')" title="Click to expand/collapse">${escapeHtml(req.operation || '')}</div>
            <div class="approval-reason">${escapeHtml(req.reason || '')}</div>
            <div class="approval-actions">
                <button onclick="approveRequest('${escapeHtml(req.id)}')" class="btn btn-success btn-small">✓ Approve</button>
                <button onclick="denyRequest('${escapeHtml(req.id)}')" class="btn btn-danger btn-small">✗ Deny</button>
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

async function refreshApprovalHistory() {
    try {
        // Current-process history is intentional: persistent backend history is
        // available through ?include_previous_runs=true but is not replayed in
        // the live Dashboard after a restart.
        const res = await fetch(`${API_BASE}/approval/history?limit=20`);
        const data = await res.json();
        const rows = data.history || [];
        const tbody = document.getElementById('approval-history-body');
        document.getElementById('approval-history-count').textContent = rows.length;

        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No approval history in this process</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(record => {
            const timestamp = record.created_at
                ? new Date(record.created_at * 1000).toLocaleTimeString()
                : '-';
            const status = String(record.status || 'unknown');
            return `
                <tr>
                    <td>${escapeHtml(timestamp)}</td>
                    <td>${escapeHtml(record.approval_type || '-')}</td>
                    <td><span class="badge badge-${escapeHtml(status)}">${escapeHtml(status)}</span></td>
                    <td style="max-width: 320px; word-break: break-all;">${escapeHtml(record.operation || '-')}</td>
                    <td>${escapeHtml(record.resolution_reason || record.reason || '-')}</td>
                    <td>${escapeHtml(record.resolved_by || '-')}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Failed to fetch approval history:', err);
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
        refreshApprovalHistory();
    });

    es.addEventListener('denied', e => {
        const req = JSON.parse(e.data);
        const item = document.getElementById(`approval-item-${req.id}`);
        if (item) item.remove();
        clearInterval(_approvalCountdownTimers[req.id]);
        delete _approvalCountdownTimers[req.id];
        document.getElementById('queue-count').textContent =
            document.querySelectorAll('.approval-item').length;
        refreshApprovalHistory();
    });

    es.addEventListener('timeout', e => {
        const req = JSON.parse(e.data);
        const item = document.getElementById(`approval-item-${req.id}`);
        if (item) item.remove();
        clearInterval(_approvalCountdownTimers[req.id]);
        delete _approvalCountdownTimers[req.id];
        document.getElementById('queue-count').textContent =
            document.querySelectorAll('.approval-item').length;
        refreshApprovalHistory();
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
        await refreshApprovalHistory();
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
        await refreshApprovalHistory();
    } catch (err) {
        alert('Failed to deny');
    }
}

// =====================================
// Audit Log
// =====================================

async function refreshAuditLog() {
    try {
        const res = await fetch(`${API_BASE}/audit/logs?limit=80`);
        const data = await res.json();
        
        const tbody = document.getElementById('audit-log-body');
        const logs = (data.logs || []).filter(log => {
            if (String(log.action || '').startsWith('skill_')) return true;
            if (log.action !== 'model_tool_call') return false;
            try {
                const details = typeof log.details === 'string'
                    ? JSON.parse(log.details)
                    : (log.details || {});
                return details.native_tool === true;
            } catch (err) {
                return false;
            }
        }).slice(0, 20);
        
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No logs</td></tr>';
            return;
        }
        
        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
                <td>${escapeHtml(log.action || '-')}</td>
                <td><span class="badge badge-${escapeHtml(log.result)}">${escapeHtml(log.result)}</span></td>
                <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(auditOperation(log))}</td>
                <td>${escapeHtml(auditTarget(log) || '-')}</td>
                <td>${escapeHtml(auditReason(log) || '-')}</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to fetch audit log:', err);
    }
}

// =====================================
// Skill Inspector
// =====================================

function skillBadgeClass(verdict) {
    return verdict === 'safe' ? 'skill-badge-safe' : 'skill-badge-unsafe';
}

function setSkillBadge(element, text, className) {
    element.textContent = text;
    element.className = `badge ${className}`;
}

async function loadSkillInspector() {
    const list = document.getElementById('skill-list');
    list.innerHTML = '<tr><td colspan="6" class="skill-empty-cell">Loading Skills...</td></tr>';
    try {
        const res = await fetch(`${API_BASE}/skill-inspector`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error?.message || 'Unable to load Skill Inspector');

        const stats = data.stats || {};
        const status = document.getElementById('skill-inspector-status');
        status.textContent = data.enabled ? 'Active' : 'Disabled';
        status.className = `stat-value ${data.enabled ? 'stat-success' : 'stat-danger'}`;
        document.getElementById('skill-stat-total').textContent = stats.total || 0;
        document.getElementById('skill-stat-safe').textContent = stats.safe || 0;
        document.getElementById('skill-stat-unsafe').textContent = stats.unsafe || 0;
        document.getElementById('skill-stat-overrides').textContent = stats.overridden || 0;
        document.getElementById('skill-roots').textContent = (data.roots || []).join(' · ');

        list.replaceChildren();
        if (!data.skills || data.skills.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.className = 'skill-empty-cell';
            cell.textContent = 'No inspected Skills yet. A Skill appears after load, create, or invocation is detected.';
            row.appendChild(cell);
            list.appendChild(row);
            return;
        }

        data.skills.forEach(skill => {
            const row = document.createElement('tr');

            const nameCell = document.createElement('td');
            const name = document.createElement('div');
            name.className = 'skill-name';
            name.textContent = skill.name;
            const meta = document.createElement('div');
            meta.className = 'skill-path';
            meta.textContent = skill.skill_path || '';
            nameCell.append(name, meta);

            const verdictCell = document.createElement('td');
            const status = document.createElement('span');
            const effective = skill.effective_verdict || 'unsafe';
            setSkillBadge(
                status,
                skill.overridden ? `${effective} · overridden` : effective,
                skillBadgeClass(effective),
            );
            verdictCell.appendChild(status);

            const riskCell = document.createElement('td');
            const risk = document.createElement('span');
            risk.className = 'skill-risk';
            risk.textContent = skill.risk_level || 'unknown';
            riskCell.appendChild(risk);

            const hashCell = document.createElement('td');
            const hash = document.createElement('code');
            hash.className = 'skill-short-hash';
            hash.textContent = String(skill.content_hash || '').slice(0, 20);
            hash.title = skill.content_hash || '';
            hashCell.appendChild(hash);

            const reviewedCell = document.createElement('td');
            reviewedCell.textContent = skill.inspected_at
                ? new Date(skill.inspected_at * 1000).toLocaleString()
                : '-';

            const actionCell = document.createElement('td');
            const details = document.createElement('button');
            details.className = 'btn btn-small';
            details.textContent = 'Details';
            details.addEventListener('click', () => showSkillDetail(skill.name));
            actionCell.appendChild(details);

            row.append(nameCell, verdictCell, riskCell, hashCell, reviewedCell, actionCell);
            list.appendChild(row);
        });
    } catch (err) {
        list.innerHTML = '<tr><td colspan="6" class="skill-empty-cell">Failed to load Skill Inspector.</td></tr>';
        console.error(err);
    }
}

function closeSkillDetail() {
    document.getElementById('skill-detail-view').classList.add('hidden');
    document.getElementById('skill-overview-view').classList.remove('hidden');
    currentSkillName = null;
    document.getElementById('skills-tab').scrollIntoView({ behavior: 'smooth' });
}

async function showSkillDetail(skillName) {
    try {
        const res = await fetch(`${API_BASE}/skill-inspector/${encodeURIComponent(skillName)}`);
        const skill = await res.json();
        if (!res.ok) throw new Error(skill.error?.message || 'Unable to load Skill');
        currentSkillName = skill.name;

        document.getElementById('skill-overview-view').classList.add('hidden');
        document.getElementById('skill-detail-view').classList.remove('hidden');
        document.getElementById('skill-detail-name').textContent = skill.name;
        document.getElementById('skill-breadcrumb-name').textContent = skill.name;
        document.getElementById('skill-detail-path').textContent = skill.skill_path || '';
        setSkillBadge(
            document.getElementById('skill-detail-effective'),
            `effective: ${skill.effective_verdict}`,
            skillBadgeClass(skill.effective_verdict),
        );
        setSkillBadge(
            document.getElementById('skill-detail-model'),
            `judge: ${skill.model_verdict}`,
            skillBadgeClass(skill.model_verdict),
        );
        setSkillBadge(
            document.getElementById('skill-detail-risk'),
            `risk: ${skill.risk_level}`,
            skill.risk_level === 'high' || skill.risk_level === 'critical'
                ? 'skill-badge-unsafe'
                : 'skill-badge-neutral',
        );
        document.getElementById('skill-detail-hash').textContent = skill.content_hash || '';
        document.getElementById('skill-detail-reviewed').textContent = skill.inspected_at
            ? new Date(skill.inspected_at * 1000).toLocaleString()
            : '-';
        document.getElementById('skill-detail-reason').textContent = skill.reason || '';
        document.getElementById('skill-detail-markdown').textContent = skill.markdown || '';
        document.getElementById('skill-override-reason').value = skill.override_reason || '';
        renderSkillFindings(skill.details || {});
        requestAnimationFrame(syncSkillMarkdownHeight);
        document.getElementById('skills-tab').scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert(err.message || 'Failed to open Skill details');
    }
}

function syncSkillMarkdownHeight() {
    const markdown = document.getElementById('skill-detail-markdown');
    const sidePanel = document.querySelector('.skill-side-panel');
    const contentPanel = document.querySelector('.skill-content-panel');
    if (!markdown || !sidePanel || !contentPanel) return;
    if (window.innerWidth <= 900) {
        markdown.style.height = '';
        markdown.style.maxHeight = '';
        return;
    }
    const heading = contentPanel.querySelector('.skill-section-heading');
    const available = sidePanel.getBoundingClientRect().height
        - (heading?.getBoundingClientRect().height || 0)
        - 10;
    markdown.style.height = `${Math.max(220, Math.floor(available))}px`;
    markdown.style.maxHeight = 'none';
}

function renderSkillFindings(details) {
    const container = document.getElementById('skill-detail-findings');
    container.replaceChildren();
    const findings = Array.isArray(details.findings) ? details.findings : [];
    if (findings.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'skill-muted';
        empty.textContent = 'No structured findings were returned.';
        container.appendChild(empty);
        return;
    }
    findings.forEach(finding => {
        const item = document.createElement('article');
        item.className = 'skill-finding';
        const title = document.createElement('strong');
        title.textContent = `${finding.severity || 'unknown'} · ${finding.category || 'finding'}`;
        const evidence = document.createElement('code');
        evidence.textContent = `${finding.file || ''}:${finding.line_start || '?'} ${finding.evidence || ''}`;
        const why = document.createElement('p');
        why.textContent = finding.why || '';
        item.append(title, evidence, why);
        container.appendChild(item);
    });
}

async function setSkillOverride(verdict) {
    if (!currentSkillName) return;
    const reasonInput = document.getElementById('skill-override-reason');
    const reason = reasonInput.value.trim()
        || (verdict === null ? 'Manual override cleared from Skill Inspector.' : '');
    if (!reason) {
        alert('Please enter a reason before overriding the verdict.');
        reasonInput.focus();
        return;
    }
    try {
        const res = await fetch(
            `${API_BASE}/skill-inspector/${encodeURIComponent(currentSkillName)}/override`,
            {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    verdict,
                    reason,
                    actor: 'dashboard',
                }),
            },
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.error?.message || 'Override failed');
        await loadSkillInspector();
        await showSkillDetail(currentSkillName);
        await refreshAuditLog();
    } catch (err) {
        alert(err.message || 'Failed to update Skill verdict');
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

        const commandRules = data.command || {};
        renderCommandRuleList('command-allow-list', commandRules.allowed, 'allow');
        renderCommandRuleList('command-deny-list', commandRules.denied, 'deny');
        
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

function renderCommandRuleList(elementId, rules, category) {
    const container = document.getElementById(elementId);

    if (!rules || rules.length === 0) {
        container.innerHTML = '<p class="empty-list">No rules</p>';
        return;
    }

    container.innerHTML = rules.map(rule => {
        const pattern = typeof rule === 'string' ? rule : String(rule.pattern || '');
        const reason = typeof rule === 'string' ? '' : String(rule.reason || '');
        return `
            <div class="rule-item">
                <span class="rule-text" title="${escapeHtml(reason)}">${escapeHtml(pattern)}</span>
                <button class="btn-remove" data-command-pattern="${escapeHtml(pattern)}">Remove</button>
            </div>
        `;
    }).join('');

    container.querySelectorAll('.btn-remove').forEach(button => {
        button.addEventListener('click', () => removeCommandRule(
            category,
            button.dataset.commandPattern
        ));
    });
}

async function addCommandRule(category) {
    const input = document.getElementById(`command-${category}-input`);
    const pattern = input.value.trim();

    if (!pattern) {
        alert('Please enter a command regex');
        return;
    }

    try {
        const res = await fetch(
            `${API_BASE}/rules/command/${category}?pattern=${encodeURIComponent(pattern)}`,
            {method: 'POST'}
        );
        const data = await res.json();

        if (!res.ok) {
            throw new Error(data.detail || 'Unable to add command rule');
        }
        if (data.status === 'added') {
            input.value = '';
            await loadRules();
        } else if (data.status === 'already_exists') {
            alert('Rule already exists');
        }
    } catch (err) {
        alert('Error adding command rule: ' + err.message);
    }
}

async function removeCommandRule(category, pattern) {
    try {
        const res = await fetch(
            `${API_BASE}/rules/command/${category}?pattern=${encodeURIComponent(pattern)}`,
            {method: 'DELETE'}
        );
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Unable to remove command rule');
        }
        if (data.status === 'removed') {
            await loadRules();
        }
    } catch (err) {
        alert('Error removing command rule: ' + err.message);
    }
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

// 审计表里的"目标"列：域名/路径由后端写在 details.target 上。
function auditTarget(log) {
    try {
        const details = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {});
        return details.target || details.skill_name || '';
    } catch (err) {
        return '';
    }
}

function auditOperation(log) {
    try {
        const details = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {});
        return details.display_operation || log.operation || '';
    } catch (err) {
        return log.operation || '';
    }
}

function auditReason(log) {
    try {
        const details = typeof log.details === 'string'
            ? JSON.parse(log.details)
            : (log.details || {});
        if (String(log.action || '') === 'model_tool_call' && details.skill_inspector) {
            return details.skill_inspector.effective_verdict
                || details.skill_inspector.model_verdict
                || log.result
                || '';
        }
        if (String(log.action || '') !== 'skill_check') {
            return log.reason || '';
        }
        if (details.phase === 'detected') {
            return 'pending';
        }
        const verdict = details.effective_verdict || details.model_verdict;
        if (!verdict) {
            return log.result || '';
        }
        return details.phase === 'override'
            ? `override → ${verdict}`
            : verdict;
    } catch (err) {
        return log.result || '';
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
        const params = new URLSearchParams();
        // Dashboard exports are intentionally scoped to native model-tool
        // calls for the active Agent. Backend audit consumers can omit this filter.
        params.append('native_only', 'true');
        
        if (filtered) {
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
            
        }

        const queryString = params.toString();
        if (queryString) {
            url += '?' + queryString;
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
    latestTaskScope = taskScope || null;
    const badge = document.getElementById('task-scope-badge');
    const inactive = document.getElementById('task-scope-inactive');
    const details = document.getElementById('task-scope-details');
    const clearBtn = document.getElementById('clear-scope-btn');
    const lockBtn = document.getElementById('task-scope-lock-btn');
    const locked = !!(taskScope && taskScope.locked);

    if (lockBtn) {
        lockBtn.textContent = locked ? '🔓 Enable Task Scope' : '🔒 Base Rules Only';
        const unavailable = taskScopeToggleInFlight || !!(taskScope && taskScope.active);
        lockBtn.disabled = unavailable;
        lockBtn.style.opacity = unavailable ? '0.6' : '1';
        lockBtn.title = taskScopeToggleInFlight
            ? 'Updating task scope mode...'
            : (taskScope && taskScope.active)
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
    if (taskScopeToggleInFlight) return;
    taskScopeToggleInFlight = true;
    if (latestTaskScope) renderTaskScope(latestTaskScope);
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
    } finally {
        taskScopeToggleInFlight = false;
        if (latestTaskScope) renderTaskScope(latestTaskScope);
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

window.addEventListener('resize', syncSkillMarkdownHeight);
