'use strict';

const $ = id => document.getElementById(id);
const request = (action, args = {}) => window.ipc?.postMessage(JSON.stringify({ action, ...args }));
const state = { scanning: false, working: false, saved: false, report: null, settings: {}, quarantined: new Set() };
const labels = { overview: 'Overview', scans: 'Scan results', vault: 'Quarantine', history: 'Scan history', settings: 'Settings' };
const number = value => (value ?? 0).toLocaleString();
let toastTimer;

function element(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
}

function page(name) {
    for (const section of document.querySelectorAll('.page')) section.hidden = section.id !== name;
    for (const button of document.querySelectorAll('nav [data-page]')) {
        if (button.dataset.page === name) button.setAttribute('aria-current', 'page');
        else button.removeAttribute('aria-current');
    }
    $('section-label').textContent = labels[name];
    $('workspace').scrollTop = 0;
    if (name === 'vault') request('vault');
    if (name === 'history') request('history');
}

function tab(name) {
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
    $('count-files').textContent = number(summary.files_scanned);
    $('count-findings').textContent = number(summary.files_with_findings);
    $('count-incomplete').textContent = number(summary.incomplete);
}

function action(label, callback, operable = true) {
    const button = element('button', 'secondary', label);
    if (!operable) button.setAttribute('data-operation', '');
    button.addEventListener('click', callback);
    return button;
}

function record(title, detail, button = null) {
    const card = element('div', 'record');
    const copy = element('div', 'record-copy');
    copy.append(element('div', 'record-title', title), element('div', 'file-path', detail));
    card.append(copy);
    if (button) card.append(button);
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

function showReport(report, saved) {
    state.report = report;
    state.saved = saved;
    counts(report.summary);
    const scope = report.targets.join(' · ');
    $('result-subtitle').textContent = report.scope + ' · ' + status(report) + (scope ? '\n' + scope : '');
    $('export').hidden = !saved;
    list($('findings'), report.findings.map((item, index) => {
        const archived = state.quarantined.has(item.path + '\n' + item.sha256);
        const button = saved && (archived ? element('span', 'muted', 'Archived this session') :
            action('Quarantine…', () => request('quarantine', { id: report.id, index }), false));
        const [row, copy] = record(item.path.split(/[\\/]/).at(-1), item.path, button);
        for (const rule of item.rules) copy.append(element('p', 'rule', rule.id + ' · ' + rule.reason));
        copy.append(element('p', 'hash', 'SHA-256 ' + item.sha256));
        return row;
    }), report.error ? 'See the scan error above.' : 'No findings to review.');
    list($('skipped'), report.skipped.map(item => record(item.path || 'Unspecified path', item.reason)[0]), 'No incomplete checks were reported.');
    for (const [key, total] of [['findings', report.summary.files_with_findings], ['skipped', report.summary.incomplete]]) {
        if (report[key].length < total) $(key).append(element('p', 'empty', 'Showing the first ' + report[key].length + ' of ' + number(total) + ' records.'));
    }
    if (report.error) notify(report.error, true);
    updateButtons();
}

function showHistory(rows) {
    const makeRow = item => {
        const date = new Date(item.started * 1000).toLocaleString();
        const detail = date + ' · ' + number(item.summary.files_scanned) + ' scanned · ' + number(item.summary.files_with_findings) + ' with findings · ' + status(item);
        return record(item.scope, detail, action('Open report', () => request('open_report', {id: item.id})))[0];
    };
    list($('history-rows'), rows.map(makeRow), 'No saved scans yet. Start a scan to create your first report.');
    list($('recent'), rows.slice(0, 3).map(makeRow), 'Your completed scans will appear here.');
}

function showSettings(settings) {
    state.settings = settings;
    $('amsi').checked = settings.amsi;
    $('schedule').value = settings.schedule_minutes;
    $('rule-file').textContent = settings.rules || 'No custom rule file selected.';
    $('clear-rules').hidden = !settings.rules;
    updateButtons();
}

function updateButtons() {
    const busy = state.scanning || state.working;
    document.querySelectorAll('.scan-action,[data-operation]').forEach(button => { button.disabled = busy; });
    const mode = state.scanning ? 'Scan in progress' : state.settings.schedule_minutes ? 'Quick scan scheduled' : 'On-demand scanner';
    $('mode').replaceChildren(element('i'), document.createTextNode(mode));
}

window.receive = ({event, data}) => {
    switch (event) {
        case 'started':
            state.scanning = true;
            state.report = null;
            $('result-subtitle').textContent = 'LarchScan is reading files in the selected scope.';
            $('scan-scope').textContent = data;
            $('current-file').textContent = '';
            $('progress').hidden = false;
            $('cancel').disabled = false;
            $('cancel').textContent = 'Stop scan';
            $('export').hidden = true;
            counts();
            list($('findings'), [], 'Findings will appear in the report when this scan ends.');
            list($('skipped'), [], 'Incomplete checks will appear in the report.');
            tab('findings');
            page('scans');
            updateButtons();
            break;
        case 'progress':
            counts(data.summary);
            $('current-file').textContent = data.current;
            break;
        case 'finished':
            state.scanning = false;
            $('progress').hidden = true;
            showReport(data.report, data.saved);
            if (!data.report.error) notify(data.report.summary.cancelled ? 'Scan stopped. Partial results are available.' : 'Scan finished.');
            break;
        case 'report':
            if (state.scanning) { notify('Stop or finish the active scan before opening a saved report.', true); break; }
            page('scans');
            tab('findings');
            showReport(data, true);
            break;
        case 'history': showHistory(data); break;
        case 'settings': showSettings(data); break;
        case 'vault':
            list($('archives'), data.map(item => {
                const [row, copy] = record(item.original.split(/[\\/]/).at(-1), item.original,
                    action('Restore…', () => request('restore', {id: item.id}), false));
                copy.append(element('p', 'hash', number(item.bytes) + ' bytes · SHA-256 ' + item.sha256));
                return row;
            }), 'The quarantine vault is empty.');
            updateButtons();
            break;
        case 'vault_busy': state.working = data; updateButtons(); break;
        case 'quarantined':
            state.quarantined.add(data.original + '\n' + data.sha256);
            if (state.report) showReport(state.report, state.saved);
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
    if (button.dataset.action === 'cancel') {
        button.disabled = true;
        button.textContent = 'Stopping…';
    }
    request(button.dataset.action);
};
$('export').onclick = () => { if (state.report) request('export', {id: state.report.id}); };
$('amsi').onchange = event => request('set_amsi', {enabled: event.target.checked});
$('schedule').onchange = event => request('set_schedule', {minutes: Number(event.target.value)});
showHistory([]);
list($('findings'), [], 'Start a scan or open a saved report from Scan history.');
list($('skipped'), [], 'Incomplete checks from your scan will appear here.');
request('ready');
