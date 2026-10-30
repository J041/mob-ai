'use strict';

const state = { overview: null, devices: [], selectedJob: null, poll: null, authPoll: null, readiness: null };
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function toast(message, error = false) {
  const element = $('#toast');
  element.textContent = message;
  element.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.className = 'toast'; }, 3800);
}

function option(parent, value, label) {
  const item = document.createElement('option');
  item.value = value;
  item.textContent = label || value;
  parent.append(item);
}

function formatDate(value) {
  if (!value) return 'unknown';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function escapeText(value) {
  const node = document.createElement('span');
  node.textContent = value ?? '';
  return node.innerHTML;
}

function setTab(name) {
  $$('.segment').forEach(button => {
    const active = button.dataset.tab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  $$('.tab-panel').forEach(panel => panel.classList.toggle('active', panel.dataset.panel === name));
}

function renderModelOptions(catalog) {
  const models = catalog?.models || [];
  const authenticationRequired = catalog?.source === 'authentication_required';
  $$('.model-select').forEach(select => {
    const previous = select.value;
    const firstLabel = authenticationRequired
      ? 'Connect ChatGPT account'
      : select.closest('#resumeForm') ? 'Recorded model' : 'Account default';
    select.replaceChildren();
    option(select, '', firstLabel);
    models.forEach(model => option(
      select,
      model.id,
      `${model.display_name}${model.is_default ? ' · recommended' : ''}`,
    ));
    if (previous && ![...select.options].some(item => item.value === previous)) {
      option(select, previous, `${previous} · recorded`);
    }
    select.value = previous;
    select.disabled = authenticationRequired;
    select.title = authenticationRequired
      ? 'Connect your ChatGPT account using the button at the top of the page.'
      : catalog?.source === 'connected_chatgpt_account'
      ? 'Models available to the connected ChatGPT account.'
      : catalog?.source === 'codex_app_server'
        ? 'Fallback catalog reported by this Codex installation.'
        : 'Fallback model catalog; access is verified when a run starts.';
    renderReasoningOptions(select, catalog);
  });
}

function reasoningLabel(level) {
  const names = { none: 'None', minimal: 'Minimal', low: 'Low', medium: 'Medium', high: 'High', xhigh: 'Extra high', max: 'Maximum', ultra: 'Ultra' };
  return names[level.effort] || level.effort;
}

function renderReasoningOptions(modelSelect, catalog = state.overview?.models) {
  const select = modelSelect.form.querySelector('.reasoning-select');
  if (!select) return;
  const previous = select.value;
  const authenticationRequired = catalog?.source === 'authentication_required';
  const model = (catalog?.models || []).find(item => item.id === modelSelect.value);
  let levels = model?.reasoning_levels || [];
  if (!levels.length) {
    const seen = new Map();
    (catalog?.models || []).flatMap(item => item.reasoning_levels || []).forEach(level => seen.set(level.effort, level));
    levels = [...seen.values()];
  }
  const defaultLabel = authenticationRequired
    ? 'Connect ChatGPT account'
    : modelSelect.closest('#resumeForm')
    ? 'Recorded level'
    : `Model default${model?.default_reasoning_effort ? ` · ${reasoningLabel({ effort: model.default_reasoning_effort })}` : ''}`;
  select.replaceChildren();
  option(select, '', defaultLabel);
  levels.forEach(level => {
    option(select, level.effort, reasoningLabel(level));
    select.lastElementChild.title = level.description || '';
  });
  select.value = [...select.options].some(item => item.value === previous) ? previous : '';
  select.disabled = authenticationRequired;
  select.title = authenticationRequired
    ? 'Connect your ChatGPT account to choose a thinking level.'
    : model
    ? `Thinking levels supported by ${model.display_name}.`
    : 'Choose a model first for its exact supported thinking levels.';
}

function renderOverview(data) {
  state.overview = data;
  $('#apkCount').textContent = data.apks.length;
  $('#runCount').textContent = data.runs.length;
  $('#activeCount').textContent = data.jobs.filter(job => job.running).length;
  const auth = $('#codexAuth');
  const ready = Boolean(data.codex?.available && data.codex?.authenticated);
  auth.textContent = ready ? 'CODEX · CHATGPT CONNECTED' : 'CODEX · CONNECT CHATGPT';
  auth.className = `auth-pill ${ready ? 'ready' : 'missing'}`;
  renderModelOptions(data.models);

  const specOptions = $('#specOptions');
  specOptions.replaceChildren();
  data.success_specs.forEach(spec => option(specOptions, spec.path, spec.name));

  const resumeSelect = $('#resumeRun');
  const previous = resumeSelect.value;
  resumeSelect.replaceChildren();
  option(resumeSelect, '', 'Select a continuable run');
  data.runs.filter(run => run.continuable).forEach(run => option(
    resumeSelect,
    run.path,
    `${run.package || run.id} · ${run.iterations} attempts${run.frida_recoverable ? ' · fix Frida' : run.checkpoint_recoverable ? ` · recover ${run.recovery_stage}` : ''}`,
  ));
  if ([...resumeSelect.options].some(item => item.value === previous)) resumeSelect.value = previous;

  renderRuns(data.runs);
  renderJobs(data.jobs);
  $('#lastRefresh').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

function renderRuns(runs) {
  const list = $('#runList');
  if (!runs.length) {
    list.innerHTML = '<div class="empty">No assessment runs found.</div>';
    return;
  }
  list.innerHTML = runs.map(run => `
    <article class="run-row">
      <div class="run-main"><strong>${escapeText(run.package || run.id)}</strong><small>${escapeText(run.id)} · ${run.static_findings} static findings</small></div>
      <div class="run-cell"><span>${escapeText(run.target || 'no target')}</span><small>${escapeText(run.transport || 'analysis only')}</small></div>
      <div class="run-cell"><span>${run.iterations} iterations</span><small>${run.observation_events} observations</small></div>
      <span class="badge ${escapeText(run.status)}">${escapeText(run.status.replaceAll('_', ' '))}</span>
      <button class="resume-button" data-resume="${escapeText(run.path)}" ${run.continuable ? '' : 'disabled'}>${run.frida_recoverable ? 'Fix Frida' : run.checkpoint_recoverable ? 'Recover' : run.resumable ? 'Resume' : 'Closed'}</button>
    </article>`).join('');
  $$('[data-resume]').forEach(button => button.addEventListener('click', () => {
    setTab('resume');
    $('#resumeRun').value = button.dataset.resume;
    updateResumeSummary();
    $('#launch').scrollIntoView({ behavior: 'smooth' });
  }));
}

function renderJobs(jobs) {
  const strip = $('#jobStrip');
  if (!jobs.length) {
    strip.innerHTML = '<p>No jobs started from this dashboard.</p>';
    return;
  }
  if (!state.selectedJob || !jobs.some(job => job.id === state.selectedJob)) state.selectedJob = jobs[0].id;
  strip.innerHTML = jobs.slice(0, 6).map(job => `<button class="job-chip ${job.id === state.selectedJob ? 'active' : ''}" data-job="${job.id}"><span>${escapeText(job.label)}</span><b>${job.running ? 'RUNNING' : escapeText(String(job.status || `exit ${job.exit_code ?? '?'}`).replaceAll('_', ' ').toUpperCase())}</b></button>`).join('');
  $$('[data-job]').forEach(button => button.addEventListener('click', () => { state.selectedJob = button.dataset.job; refreshSelectedJob(); renderJobs(jobs); }));
  refreshSelectedJob();
}

async function refreshSelectedJob() {
  if (!state.selectedJob) return;
  try {
    const job = await api(`/api/jobs/${state.selectedJob}`);
    const output = [job.stdout, job.stderr && `\n[stderr]\n${job.stderr}`].filter(Boolean).join('');
    $('#consoleOutput').textContent = output || 'Process started; waiting for output…';
    $('#consoleOutput').scrollTop = $('#consoleOutput').scrollHeight;
    $('#jobLabel').textContent = `${job.kind} · ${job.label} · PID ${job.pid}`;
    $('#livePill').textContent = job.running ? 'RUNNING' : String(job.status || `exit ${job.exit_code ?? '?'}`).replaceAll('_', ' ').toUpperCase();
    $('#livePill').classList.toggle('running', job.running);
    if (job.running) schedulePoll();
  } catch (error) { toast(error.message, true); }
}

function schedulePoll() {
  clearTimeout(state.poll);
  state.poll = setTimeout(async () => {
    await refreshSelectedJob();
    try { renderOverview(await api('/api/overview')); } catch (_) {}
  }, 2200);
}

async function refreshOverview(showToast = false) {
  const button = $('#refreshAll');
  button.disabled = true;
  try {
    renderOverview(await api('/api/overview'));
    if (showToast) toast('Dashboard refreshed.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

async function discoverDevices() {
  const button = $('#discoverDevices');
  button.disabled = true;
  button.textContent = 'Discovering…';
  try {
    const data = await api('/api/devices');
    state.devices = data.devices;
    const list = $('#deviceOptions');
    list.replaceChildren();
    data.devices.forEach(device => option(list, device.serial, `${device.serial} · ${device.state}`));
    $('#deviceCount').textContent = data.devices.filter(device => device.state === 'device').length;
    $('#deviceCaption').textContent = data.devices.length ? `${data.devices.length} ADB entries` : 'none visible';
    const target = $('#newForm [name="target"]');
    if (!target.value && data.devices.filter(device => device.state === 'device').length === 1) {
      target.value = data.devices.find(device => device.state === 'device').serial;
      resetReadiness();
    }
    toast(`Found ${data.devices.length} ADB device entries.`);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Discover devices'; }
}

function formJson(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  delete data.apk_file;
  delete data.frida_binary;
  delete data.pair_endpoint;
  delete data.pair_code;
  form.querySelectorAll('input[type="checkbox"]').forEach(input => { data[input.name] = input.checked; });
  ['max_iterations', 'observation_seconds', 'run_seconds'].forEach(key => { if (key in data) data[key] = Number(data[key]); });
  return data;
}

function resetReadiness() {
  state.readiness = null;
  $('#readinessToken').value = '';
  $('#readinessState').textContent = 'NOT CHECKED';
  $('#readinessState').className = 'readiness-state';
  $('#readinessResults').innerHTML = '<p>Device settings changed. Run readiness again before starting.</p>';
}

async function runReadiness() {
  const form = $('#newForm');
  const button = $('#runReadiness');
  const target = form.elements.target.value.trim();
  const authorized = form.elements.authorized.checked;
  if (!target) { toast('Enter the exact device target first.', true); return; }
  if (!authorized && (form.elements.start_frida.checked || form.elements.frida_binary.files[0])) {
    toast('Confirm authorization before deploying or starting Frida.', true);
    return;
  }
  const body = new FormData();
  body.append('transport', form.elements.transport.value);
  body.append('target', target);
  body.append('frida_server', form.elements.frida_server.value.trim());
  body.append('start_frida', String(form.elements.start_frida.checked));
  body.append('authorized', String(authorized));
  const binary = form.elements.frida_binary.files[0];
  if (binary) body.append('frida_binary', binary, binary.name);
  button.disabled = true;
  button.textContent = 'Checking…';
  $('#readinessState').textContent = 'RUNNING';
  $('#readinessState').className = 'readiness-state running';
  try {
    const response = await fetch('/api/devices/readiness', { method: 'POST', body });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Readiness failed (${response.status})`);
    state.readiness = result;
    $('#readinessToken').value = result.token || '';
    $('#readinessState').textContent = result.ready ? 'READY' : 'BLOCKED';
    $('#readinessState').className = `readiness-state ${result.ready ? 'ready' : 'blocked'}`;
    $('#readinessResults').innerHTML = result.checks.map(check => `
      <div class="readiness-check ${check.passed ? 'passed' : check.required ? 'failed' : 'info'}">
        <span>${check.passed ? '✓' : check.required ? '×' : 'i'}</span>
        <div><strong>${escapeText(check.name)}</strong><small>${escapeText(check.detail || 'No detail')}</small></div>
      </div>`).join('');
    toast(result.ready ? `Device ready · ${result.abi} · SDK ${result.sdk}` : 'Device readiness is blocked. Review the failed checks.', !result.ready);
  } catch (error) {
    $('#readinessState').textContent = 'ERROR';
    $('#readinessState').className = 'readiness-state blocked';
    $('#readinessResults').innerHTML = `<p>${escapeText(error.message)}</p>`;
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = 'Run readiness';
  }
}

function updateTransport() {
  const wireless = $('#newForm [name="transport"]:checked').value === 'wireless';
  $('#wirelessPairing').hidden = !wireless;
  $('#targetLabel').textContent = wireless ? 'Wireless connection address' : 'Device target';
  const target = $('#newForm [name="target"]');
  target.placeholder = wireless ? '192.168.1.20:CONNECTION_PORT' : 'emulator-5554 or ADB serial';
  $('#targetHint').textContent = wireless
    ? 'Use the separate IP:port shown on the main Wireless debugging screen.'
    : 'Use the exact serial shown by ADB.';
  if (!wireless) $('#newForm [name="pair_code"]').value = '';
}

function updatePolicyBuilder() {
  const preset = $('#policyPreset').value;
  const generated = preset !== 'advanced';
  $('#generatedPolicyFields').hidden = !generated;
  $('#advancedPolicy').hidden = generated;
  const activity = $('.policy-activity');
  const expected = $('.policy-expected');
  const forbidden = $('.policy-forbidden');
  activity.hidden = preset === 'basic' || preset === 'detection_removed';
  expected.hidden = preset === 'basic' || preset === 'detection_removed';
  forbidden.hidden = preset === 'basic' || preset === 'screen_reached';
  const forbiddenInput = $('#newForm [name="forbidden_ui_pattern"]');
  forbiddenInput.required = preset === 'detection_removed';
  const repeat = $('#newForm [name="policy_repeat"]').value;
  const descriptions = {
    basic: `Requires process alive, foreground package, and no crash · ${repeat}/${repeat} repeat passes`,
    detection_removed: `Basic checks + warning absent from UI and logcat · ${repeat}/${repeat} repeat passes`,
    screen_reached: `Basic checks + expected activity or visible text · ${repeat}/${repeat} repeat passes`,
    custom: `Basic checks plus every populated activity/text assertion · ${repeat}/${repeat} repeat passes`,
    advanced: 'Uses the selected JSON policy exactly as written.',
  };
  $('#policySummary').textContent = descriptions[preset];
}

async function pairWirelessDevice() {
  const button = $('#pairDevice');
  const endpoint = $('#newForm [name="pair_endpoint"]').value.trim();
  const codeInput = $('#newForm [name="pair_code"]');
  const code = codeInput.value.trim();
  const status = $('#pairingStatus');
  button.disabled = true;
  status.className = '';
  status.textContent = 'Pairing with the device…';
  try {
    const result = await api('/api/devices/pair', {
      method: 'POST', body: JSON.stringify({ endpoint, code }),
    });
    status.className = 'success';
    status.textContent = `${result.message} Enter the separate connection address below.`;
    toast(result.message);
    await discoverDevices();
  } catch (error) {
    status.className = 'error';
    status.textContent = error.message;
    toast(error.message, true);
  } finally {
    codeInput.value = '';
    button.disabled = false;
  }
}

async function uploadApk(file) {
  const body = new FormData();
  body.append('apk', file, file.name);
  const response = await fetch('/api/apks', { method: 'POST', body });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Upload failed (${response.status})`);
  return payload;
}

async function submitForm(form, endpoint) {
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    if (!state.overview?.codex?.authenticated) throw new Error('Connect your ChatGPT account before starting an assessment.');
    const payload = formJson(form);
    if (endpoint === '/api/start') {
      if (!payload.readiness_token) throw new Error('Run device readiness and resolve every required check before starting.');
      const file = form.elements.apk_file.files[0];
      if (!file) throw new Error('Choose an APK file.');
      $('#apkUploadStatus').textContent = `Uploading ${file.name}…`;
      const uploaded = await uploadApk(file);
      payload.apk = uploaded.path;
      $('#apkUploadStatus').textContent = `${uploaded.name} uploaded · ${(uploaded.size / 1048576).toFixed(1)} MB`;
    }
    const job = await api(endpoint, { method: 'POST', body: JSON.stringify(payload) });
    state.selectedJob = job.id;
    toast(`${job.kind === 'resume' ? 'Resume' : 'Assessment'} job started.`);
    renderOverview(await api('/api/overview'));
    $('#activity').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

function renderAuth(data) {
  const flow = data.device_flow || {};
  const cleanOutput = String(flow.output || '').replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '');
  $('#authStatus').textContent = data.authenticated ? 'ChatGPT account connected' : (flow.running ? 'Waiting for browser authorization…' : 'Not connected');
  $('#authOutput').textContent = data.authenticated ? (data.detail || 'Logged in with ChatGPT.') : (cleanOutput || data.detail || 'Select Continue with ChatGPT to begin.');
  const start = $('#startAuth');
  start.disabled = Boolean(flow.running || data.authenticated);
  start.textContent = data.authenticated ? 'Connected' : (flow.running ? 'Waiting for sign-in…' : 'Continue with ChatGPT');
  const signOut = $('#signOutAuth');
  signOut.hidden = !data.authenticated;
  signOut.disabled = false;
  const match = cleanOutput.match(/https:\/\/auth\.openai\.com\/[^\s\u001b]+/);
  const link = $('#authLink');
  if (match && !data.authenticated) {
    link.href = match[0].replace(/[),.;]+$/, '');
    link.hidden = false;
  } else {
    link.hidden = true;
    link.removeAttribute('href');
  }
  const code = cleanOutput.match(/\b[A-Z0-9]{4,8}-[A-Z0-9]{4,8}\b/)?.[0] || '';
  const copyCode = $('#copyAuthCode');
  copyCode.hidden = !code || data.authenticated;
  copyCode.dataset.code = code;
  clearTimeout(state.authPoll);
  if (flow.running) state.authPoll = setTimeout(refreshAuth, 1500);
  if (data.authenticated) refreshOverview();
}

async function refreshAuth() {
  try { renderAuth(await api('/api/auth')); }
  catch (error) { toast(error.message, true); }
}

async function openAuth() {
  $('#authDialog').showModal();
  await refreshAuth();
}

async function beginAuth() {
  $('#startAuth').disabled = true;
  try { renderAuth(await api('/api/auth/device', { method: 'POST' })); }
  catch (error) { toast(error.message, true); $('#startAuth').disabled = false; }
}

async function signOutAuth() {
  const button = $('#signOutAuth');
  button.disabled = true;
  button.textContent = 'Signing out…';
  try {
    const auth = await api('/api/auth/logout', { method: 'POST' });
    renderAuth(auth);
    await refreshOverview(true);
    toast('ChatGPT account signed out.');
  } catch (error) {
    toast(error.message, true);
    button.disabled = false;
  } finally {
    button.textContent = 'Sign out';
  }
}

function updateResumeSummary() {
  const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
  const summary = $('#resumeSummary');
  const fridaField = $('#resumeFridaField');
  const fridaInput = $('#resumeFridaServer');
  const fridaRecovery = Boolean(run?.frida_recoverable || (run?.checkpoint_recoverable && run?.recovery_stage === 'observation' && run?.frida_server));
  fridaField.hidden = !fridaRecovery;
  fridaInput.disabled = !fridaRecovery;
  fridaInput.required = fridaRecovery;
  if (!run) {
    fridaInput.value = '';
    summary.innerHTML = '<span>↳</span><p>Select a run to see its last known state.</p>';
    return;
  }
  if (fridaRecovery) fridaInput.value = run.frida_server || '/data/local/tmp/frida-server';
  const action = run.frida_recoverable
    ? 'The failed observation will be archived, Frida will restart from this path, and observation will rerun before Codex continues.'
    : run.checkpoint_recoverable
    ? `The failed ${run.recovery_stage} checkpoint will retry without repeating completed analysis.`
    : 'Ready for additional iterations.';
  summary.innerHTML = `<span>↳</span><p><strong>${escapeText(run.package || run.id)}</strong><br>${run.iterations} completed attempts · ${escapeText(run.target || 'unknown target')}<br>${escapeText(run.detail || action)}${run.continuable ? `<br><strong>${escapeText(action)}</strong>` : ''}</p>`;
}

$$('.segment').forEach(button => button.addEventListener('click', () => setTab(button.dataset.tab)));
$('#newForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, '/api/start'); });
$('#resumeForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, '/api/resume'); });
$('#resumeRun').addEventListener('change', updateResumeSummary);
$('#discoverDevices').addEventListener('click', discoverDevices);
$('#runReadiness').addEventListener('click', runReadiness);
$$('#newForm [name="transport"]').forEach(input => input.addEventListener('change', updateTransport));
['target', 'frida_server'].forEach(name => $('#newForm').elements[name].addEventListener('input', resetReadiness));
$('#newForm [name="frida_binary"]').addEventListener('change', resetReadiness);
$('#newForm [name="start_frida"]').addEventListener('change', resetReadiness);
$$('.model-select').forEach(select => select.addEventListener('change', () => renderReasoningOptions(select)));
$('#pairDevice').addEventListener('click', pairWirelessDevice);
$('#policyPreset').addEventListener('change', updatePolicyBuilder);
$('#newForm [name="policy_repeat"]').addEventListener('change', updatePolicyBuilder);
$('#refreshAll').addEventListener('click', () => refreshOverview(true));
$('#copyLog').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#consoleOutput').textContent); toast('Console copied.'); }
  catch (_) { toast('Clipboard access was unavailable.', true); }
});
$('#codexAuth').addEventListener('click', openAuth);
$('#startAuth').addEventListener('click', beginAuth);
$('#signOutAuth').addEventListener('click', signOutAuth);
$('#closeAuth').addEventListener('click', () => { clearTimeout(state.authPoll); $('#authDialog').close(); });
$('#authDialog').addEventListener('click', event => { if (event.target === event.currentTarget) event.currentTarget.close(); });
$('#copyAuthCode').addEventListener('click', async event => {
  try { await navigator.clipboard.writeText(event.currentTarget.dataset.code); toast('One-time code copied.'); }
  catch (_) { toast('Clipboard access was unavailable.', true); }
});

refreshOverview();
updateTransport();
updatePolicyBuilder();
