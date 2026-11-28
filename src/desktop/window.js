'use strict';

const $ = id => document.getElementById(id);
const request = (action, args = {}) => window.ipc?.postMessage(JSON.stringify({ action, ...args }));
const state = {
    page: 'overview',
    tab: 'findings',
    filter: '',
    scanning: false,
    working: false,
    saved: false,
    report: null,
    settings: {},
    quarantined: new Set()
};
const labels = { overview: 'Overview', scans: 'Scan results', vault: 'Quarantine', history: 'Scan history', settings: 'Settings' };
const number = value => (value ?? 0).toLocaleString();
const formatTime = epoch => epoch ? new Date(epoch * 1000).toLocaleString() : '';
let toastTimer;

function element(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
}

function vaultKey(path, sha256) {
    return String(path || '').toLowerCase() + '\n' + String(sha256 || '').toLowerCase();
}

function page(name) {
    state.page = name;
    for (const section of document.querySelectorAll('.page')) section.hidden = section.id !== name;
    for (const button of document.querySelectorAll('nav [data-page]')) {
        if (button.dataset.page === name) button.setAttribute('aria-current', 'page');
        else button.removeAttribute('aria-current');
    }
    $('section-label').textContent = labels[name];
    $('workspace').scrollTop = 0;
    updateLiveBar();
    if (name === 'vault') request('vault');
    if (name === 'history') request('history');
}

function tab(name) {
    state.tab = name;
    $('findings').hidden = name !== 'findings';
    $('skipped').hidden = name !== 'skipped';
    document.querySelectorAll('[data-tab]').forEach(button => button.classList.toggle('selected', button.dataset.tab === name));
}

function notify(text, error = false) {
    const toast = $('toast');
    toast.textContent = text;
    toast.classList.toggle('error', error);
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, error ? 14000 : 6000);
}

function counts(summary = {}) {
    const scanned = summary.files_scanned ?? 0;
    const findings = summary.files_with_findings ?? 0;
    const incomplete = summary.incomplete ?? 0;
    $('count-files').textContent = number(scanned);
    $('count-findings').textContent = number(findings);
    $('count-incomplete').textContent = number(incomplete);
    $('stat-findings').classList.toggle('alert', findings > 0);
    $('stat-incomplete').classList.toggle('warn', incomplete > 0);
}

function action(label, callback, { operable = true, cls = 'secondary' } = {}) {
    const button = element('button', cls, label);
    if (!operable) button.setAttribute('data-operation', '');
    button.addEventListener('click', callback);
    return button;
}

function record(title, detail, actionsNode = null) {
    const card = element('div', 'record');
    const copy = element('div', 'record-copy');
    copy.append(element('div', 'record-title', title), element('div', 'file-path', detail));
    card.append(copy);
    if (actionsNode) card.append(actionsNode);
    return [card, copy];
}

function list(parent, rows, empty) {
    parent.replaceChildren(...(rows.length ? rows : [element('p', 'empty', empty)]));
}

function status(report) {
    if (report.error) return 'Scan error';
    if (report.summary.cancelled) return 'Stopped';
    return report.summary.incomplete ? 'Completed with incomplete checks' : 'Completed';
}

async function copyHash(sha256) {
    try {
        await navigator.clipboard.writeText(sha256);
        notify('SHA-256 copied to clipboard.');
    } catch {
        notify('Could not copy to clipboard.', true);
    }
}

function matchesFilter(text) {
    if (!state.filter) return true;
    return text.toLowerCase().includes(state.filter);
}

function renderReportRows() {
    const report = state.report;
    if (!report) return;
    const saved = state.saved;

    const findingRows = [];
    report.findings.forEach((item, index) => {
        const haystack = [
            item.path,
            item.sha256,
            ...item.rules.map(rule => rule.id + ' ' + rule.reason)
        ].join('\n');
        if (!matchesFilter(haystack)) return;

        const archived = state.quarantined.has(vaultKey(item.path, item.sha256));
        const buttons = element('div', 'record-actions');
        if (saved) {
            buttons.append(
                archived
                    ? element('span', 'badge', 'In quarantine')
                    : action('Quarantine…', () => request('quarantine', { id: report.id, index }), { operable: false })
            );
        }
        buttons.append(
            action('Copy hash', () => copyHash(item.sha256)),
            action('Show file', () => request('reveal_in_explorer', { path: item.path }))
        );

        const [row, copy] = record(item.path.split(/[\\/]/).at(-1), item.path, buttons);
        for (const rule of item.rules) copy.append(element('p', 'rule', rule.id + ' · ' + rule.reason));
        const meta = ['SHA-256 ' + item.sha256];
        if (item.amsi_result !== null && item.amsi_result !== undefined) meta.push('AMSI ' + item.amsi_result);
        copy.append(element('p', 'hash', meta.join(' · ')));
        findingRows.push(row);
    });

    const emptyFindings = state.filter
        ? 'No findings match the current filter.'
        : (report.error ? 'See the scan error above.' : 'No findings to review.');
    list($('findings'), findingRows, emptyFindings);

    const skippedRows = [];
    for (const item of report.skipped) {
        const haystack = (item.path || '') + '\n' + (item.reason || '');
        if (!matchesFilter(haystack)) continue;
        skippedRows.push(record(item.path || 'Unspecified path', item.reason)[0]);
    }
    const emptySkipped = state.filter
        ? 'No skipped records match the current filter.'
        : 'No incomplete checks were reported.';
    list($('skipped'), skippedRows, emptySkipped);

    if (!state.filter) {
        for (const [key, total] of [['findings', report.summary.files_with_findings], ['skipped', report.summary.incomplete]]) {
            if (report[key].length < total) {
                $(key).append(element('p', 'empty', 'Showing the first ' + report[key].length + ' of ' + number(total) + ' records.'));
            }
        }
    }
    updateButtons();
}

function showReport(report, saved) {
    state.report = report;
    state.saved = saved;
    counts(report.summary);
    const scope = report.targets.join(' · ');
    $('result-subtitle').textContent = report.scope + ' · ' + status(report) + (scope ? '\n' + scope : '');
    $('export').hidden = !saved;
    renderReportRows();
    if (report.error) notify(report.error, true);
}

function showHistory(rows) {
    $('clear-history').hidden = !rows.length;
    const makeRow = (item, allowDelete) => {
        const date = formatTime(item.started);
        const detail = date + ' · ' + number(item.summary.files_scanned) + ' scanned · ' + number(item.summary.files_with_findings) + ' with findings · ' + status(item);
        const buttons = element('div', 'record-actions');
        buttons.append(action('Open report', () => request('open_report', { id: item.id })));
        if (allowDelete) {
            buttons.append(action('Delete', () => request('delete_report', { id: item.id }), { cls: 'secondary danger' }));
        }
        return record(item.scope, detail, buttons)[0];
    };
    list($('history-rows'), rows.map(item => makeRow(item, true)), 'No saved scans yet. Start a scan to create your first report.');
    list($('recent'), rows.slice(0, 3).map(item => makeRow(item, false)), 'Your completed scans will appear here.');
}

function showSettings(settings) {
    state.settings = settings;
    $('amsi').checked = Boolean(settings.amsi);
    $('schedule').value = String(settings.schedule_minutes ?? 0);
    $('rule-file').textContent = settings.rules || 'No custom rule file selected.';
    $('clear-rules').hidden = !settings.rules;
    if (settings.data_dir) $('data-dir').textContent = settings.data_dir;

    const nextText = settings.next_scan_epoch
        ? 'Next scheduled quick scan: ' + formatTime(settings.next_scan_epoch)
        : '';
    $('schedule-next').textContent = nextText;
    $('schedule-next').hidden = !nextText;
    $('overview-schedule').textContent = nextText;
    $('overview-schedule').hidden = !nextText;
    updateButtons();
}

function showVault(report) {
    const items = Array.isArray(report) ? report : (report?.items || []);
    const warnings = Array.isArray(report) ? [] : (report?.warnings || []);
    state.quarantined = new Set(items.map(item => vaultKey(item.original, item.sha256)));

    const warningBox = $('vault-warnings');
    if (warnings.length) {
        warningBox.replaceChildren(
            element('strong', null, warnings.length + ' unreadable archive file(s) skipped in vault'),
            ...warnings.map(w => element('p', 'file-path', w.path + ' — ' + w.reason))
        );
        warningBox.hidden = false;
    } else {
        warningBox.hidden = true;
    }

    list($('archives'), items.map(item => {
        const buttons = element('div', 'record-actions');
        buttons.append(
            action('Restore…', () => request('restore', { id: item.id }), { operable: false }),
            action('Delete…', () => request('delete_archive', { id: item.id }), { operable: false, cls: 'secondary danger' })
        );
        const [row, copy] = record(item.original.split(/[\\/]/).at(-1), item.original, buttons);
        for (const rule of (item.findings || [])) {
            copy.append(element('p', 'rule', rule.id + ' · ' + rule.reason));
        }
        const meta = [number(item.bytes) + ' bytes'];
        if (item.quarantined_at) meta.push('Archived ' + formatTime(item.quarantined_at));
        if (item.zone_identifier_b64) meta.push('Zone.Identifier preserved');
        meta.push('SHA-256 ' + item.sha256);
        copy.append(element('p', 'hash', meta.join(' · ')));
        return row;
    }), 'The quarantine vault is empty.');

    if (state.report) renderReportRows();
    updateButtons();
}

function updateLiveBar() {
    const bar = $('live-bar');
    bar.hidden = !state.scanning || state.page === 'scans';
}

function updateButtons() {
    const busy = state.scanning || state.working;
    document.querySelectorAll('.scan-action,[data-operation]').forEach(button => { button.disabled = busy; });
    const mode = state.scanning ? 'Scan in progress' : state.settings.schedule_minutes ? 'Quick scan scheduled' : 'On-demand scanner';
    $('mode').replaceChildren(element('i'), document.createTextNode(mode));
    updateLiveBar();
}

function setStoppingState() {
    for (const id of ['cancel', 'live-stop']) {
        const btn = $(id);
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Stopping…';
        }
    }
}

window.receive = ({ event, data }) => {
    switch (event) {
        case 'started': {
            const scope = typeof data === 'string' ? data : data.scope;
            const scheduled = typeof data === 'object' && Boolean(data.scheduled);
            state.scanning = true;
            state.report = null;
            $('result-subtitle').textContent = 'LarchScan is reading files in the selected scope.';
            $('scan-scope').textContent = scope;
            $('live-scope').textContent = scope;
            $('live-meta').textContent = 'Starting…';
            $('current-file').textContent = '';
            $('progress').hidden = false;
            for (const id of ['cancel', 'live-stop']) {
                $(id).disabled = false;
                $(id).textContent = 'Stop scan';
            }
            $('export').hidden = true;
            counts();
            list($('findings'), [], 'Findings will appear in the report when this scan ends.');
            list($('skipped'), [], 'Incomplete checks will appear in the report.');
            if (!scheduled) {
                tab('findings');
                page('scans');
            }
            updateButtons();
            break;
        }
        case 'progress':
            counts(data.summary);
            $('current-file').textContent = data.current;
            $('live-meta').textContent =
                number(data.summary.files_scanned) + ' scanned · ' +
                number(data.summary.files_with_findings) + ' with findings · ' +
                (data.current || '');
            break;
        case 'finished':
            state.scanning = false;
            $('progress').hidden = true;
            showReport(data.report, data.saved);
            if (!data.report.error) {
                notify(data.report.summary.cancelled ? 'Scan stopped. Partial results are available.' : 'Scan finished.');
            }
            updateButtons();
            break;
        case 'report':
            if (state.scanning) { notify('Stop or finish the active scan before opening a saved report.', true); break; }
            page('scans');
            tab('findings');
            showReport(data, true);
            break;
        case 'report_deleted':
            if (state.report && state.report.id === data) {
                state.report = null;
                state.saved = false;
                $('export').hidden = true;
                $('result-subtitle').textContent = 'Review findings and files that could not be checked.';
                counts();
                list($('findings'), [], 'Start a scan or open a saved report from Scan history.');
                list($('skipped'), [], 'Incomplete checks from your scan will appear here.');
            }
            break;
        case 'history_cleared':
            if (state.report && state.saved) {
                state.saved = false;
                $('export').hidden = true;
                renderReportRows();
            }
            break;
        case 'history': showHistory(data); break;
        case 'settings': showSettings(data); break;
        case 'vault': showVault(data); break;
        case 'vault_busy': state.working = data; updateButtons(); break;
        case 'quarantined':
            state.quarantined.add(vaultKey(data.original, data.sha256));
            if (state.report) renderReportRows();
            notify('File archived. It is available in Quarantine.');
            break;
        case 'notice': notify(data); break;
        case 'error':
            if (typeof state.settings.amsi === 'boolean') showSettings(state.settings);
            notify(data, true);
            break;
    }
};

for (const button of document.querySelectorAll('[data-page]')) button.onclick = () => page(button.dataset.page);
for (const button of document.querySelectorAll('[data-tab]')) button.onclick = () => tab(button.dataset.tab);
for (const button of document.querySelectorAll('[data-action]')) button.onclick = () => {
    if (button.dataset.action === 'cancel') setStoppingState();
    request(button.dataset.action);
};
$('export').onclick = () => { if (state.report) request('export', { id: state.report.id }); };
$('filter-input').oninput = event => {
    state.filter = event.target.value.trim().toLowerCase();
    renderReportRows();
};
$('amsi').onchange = event => request('set_amsi', { enabled: event.target.checked });
$('schedule').onchange = event => request('set_schedule', { minutes: Number(event.target.value) });
showHistory([]);
list($('findings'), [], 'Start a scan or open a saved report from Scan history.');
list($('skipped'), [], 'Incomplete checks from your scan will appear here.');
request('ready');
