'use strict';

const state = { overview: null, devices: [], selectedJob: null, poll: null, authPoll: null, authProvider: 'codex', readiness: null, continuationMode: 'resume', expandedRuns: new Set(), knownAttemptRuns: new Set(), jobStripScroll: 0, artifactRun: null, artifactManifest: null, artifactCategory: null, artifactPath: null, artifactPreviewCache: new Map(), assistantRun: null, assistantTurns: [] };
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

function providerCatalog(form) {
  const provider = form?.elements?.provider?.value || 'codex';
  return state.overview?.model_catalogs?.[provider] || (provider === 'codex' ? state.overview?.models : null);
}

function renderModelOptions() {
  $$('.model-select').forEach(select => {
    const catalog = providerCatalog(select.form);
    const provider = select.form?.elements?.provider?.value || 'codex';
    const models = catalog?.models || [];
    const authenticationRequired = catalog?.source === 'authentication_required';
    const defaultModel = models.find(model => model.is_default) || models[0];
    const previous = select.value;
    const firstLabel = authenticationRequired
      ? `Connect ${provider === 'codex' ? 'ChatGPT' : 'Claude'} account`
      : 'Account default';
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
    select.value = [...select.options].some(item => item.value === previous) && previous
      ? previous
      : defaultModel?.id || '';
    select.disabled = authenticationRequired;
    select.title = authenticationRequired
      ? `Connect your ${provider === 'codex' ? 'ChatGPT' : 'Claude'} account using the button at the top of the page.`
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

function renderReasoningOptions(modelSelect, catalog = providerCatalog(modelSelect.form)) {
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
    ? `Connect ${(modelSelect.form?.elements?.provider?.value || 'codex') === 'codex' ? 'ChatGPT' : 'Claude'} account`
    : modelSelect.closest('#resumeForm')
    ? 'Model default'
    : `Model default${model?.default_reasoning_effort ? ` · ${reasoningLabel({ effort: model.default_reasoning_effort })}` : ''}`;
  select.replaceChildren();
  option(select, '', defaultLabel);
  levels.forEach(level => {
    option(select, level.effort, reasoningLabel(level));
    select.lastElementChild.title = level.description || '';
  });
  const actualDefault = model?.default_reasoning_effort || '';
  select.value = [...select.options].some(item => item.value === previous) && previous
    ? previous
    : [...select.options].some(item => item.value === actualDefault) ? actualDefault : '';
  select.disabled = authenticationRequired;
  select.title = authenticationRequired
    ? 'Connect the selected provider account to choose a thinking level.'
    : model
    ? `Thinking levels supported by ${model.display_name}.`
    : 'Choose a model first for its exact supported thinking levels.';
}

function renderOverview(data) {
  state.overview = data;
  $('#apkCount').textContent = data.apks.length;
  $('#runCount').textContent = data.runs.length;
  $('#activeCount').textContent = data.jobs.filter(job => job.running).length;
  [['codex', '#codexAuth', 'CHATGPT'], ['claude', '#claudeAuth', 'CLAUDE']].forEach(([provider, selector, account]) => {
    const auth = $(selector);
    const providerState = data.providers?.[provider] || (provider === 'codex' ? data.codex : null);
    const ready = Boolean(providerState?.available && providerState?.authenticated);
    auth.textContent = ready ? `${provider.toUpperCase()} · ${account} CONNECTED` : `${provider.toUpperCase()} · CONNECT ${account}`;
    auth.className = `auth-pill ${ready ? 'ready' : 'missing'}`;
  });
  renderModelOptions();

  const specOptions = $('#specOptions');
  specOptions.replaceChildren();
  data.success_specs.forEach(spec => option(specOptions, spec.path, spec.name));

  const resumeSelect = $('#resumeRun');
  const previous = resumeSelect.value;
  resumeSelect.replaceChildren();
  option(resumeSelect, '', 'Select an assessment run');
  data.runs.forEach(run => option(
    resumeSelect,
    run.path,
    `${run.package || run.id} · ${run.iterations} iterations${run.continuable ? (run.frida_recoverable ? ' · fix Frida' : run.checkpoint_recoverable ? ` · recover ${run.recovery_stage}` : ' · resumable') : ' · rerun available'}`,
  ));
  if ([...resumeSelect.options].some(item => item.value === previous)) resumeSelect.value = previous;

  renderRuns(data.runs);
  renderJobs(data.jobs);
  updateResumeSummary();
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
      <div class="run-cell"><span>${escapeText(run.target || 'no target')}</span><small>${run.derived_from_run ? `derived from ${escapeText(run.derived_from_run)} - ` : ''}${escapeText(run.transport || 'analysis only')}</small></div>
      <div class="run-cell"><span>${run.iterations} iterations</span><small>${run.reasoning_mode === 'parallel' ? `${run.specialist_count} specialists` : 'single agent'} · ${run.observation_events} observations</small></div>
      <span class="badge ${escapeText(run.status)}">${escapeText(run.status.replaceAll('_', ' '))}</span>
      <div class="run-actions">
        <button class="resume-button assistant" data-assistant="${escapeText(run.id)}">Ask assistant</button>
        <button class="resume-button artifacts" data-artifacts="${escapeText(run.id)}">Artifacts</button>
        ${run.continuable ? `<button class="resume-button" data-resume="${escapeText(run.path)}">${run.frida_recoverable ? 'Fix Frida' : run.checkpoint_recoverable ? 'Recover' : 'Resume'}</button>` : ''}
        <button class="resume-button diagnostic" data-retry="${escapeText(run.path)}" ${run.retryable ? '' : 'disabled'}>Rerun / retry</button>
      </div>
    </article>`).join('');
  $$('[data-resume]').forEach(button => button.addEventListener('click', () => {
    state.continuationMode = 'resume';
    setTab('resume');
    $('#resumeRun').value = button.dataset.resume;
    populateContinuationValues(state.overview?.runs.find(item => item.path === button.dataset.resume));
    updateResumeSummary();
    $('#launch').scrollIntoView({ behavior: 'smooth' });
  }));
  $$('[data-retry]').forEach(button => button.addEventListener('click', () => {
    state.continuationMode = 'retry';
    setTab('resume');
    $('#resumeRun').value = button.dataset.retry;
    populateContinuationValues(state.overview?.runs.find(item => item.path === button.dataset.retry));
    updateResumeSummary();
    $('#launch').scrollIntoView({ behavior: 'smooth' });
  }));
  $$('[data-artifacts]').forEach(button => button.addEventListener('click', () => openArtifactBrowser(button.dataset.artifacts)));
  $$('[data-assistant]').forEach(button => button.addEventListener('click', () => openRunAssistant(button.dataset.assistant)));
}

function clearReassessment() {
  const form = $('#newForm');
  form.elements.source_run.value = '';
  form.elements.apk_file.disabled = false;
  form.elements.apk_file.required = true;
  $('#apkUploadField').classList.remove('reassessment-source');
  $('#reassessmentBanner').hidden = true;
  $('#newRunTab').textContent = 'New run';
  $('#apkUploadStatus').textContent = 'Choose the APK you are authorized to assess.';
  resetReadiness();
}

function beginReassessment(runId) {
  const run = state.overview?.runs.find(item => item.id === runId);
  if (!run) return;
  const form = $('#newForm');
  setTab('new');
  $('#newRunTab').textContent = 'Linked reassessment';
  form.elements.source_run.value = run.id;
  form.elements.apk_file.value = '';
  form.elements.apk_file.required = false;
  form.elements.apk_file.disabled = true;
  $('#apkUploadField').classList.add('reassessment-source');
  $('#reassessmentBanner').hidden = false;
  $('#reassessmentSource').textContent = `${run.package || run.apk_name} - derived from ${run.id} - static analysis reused when the APK hash matches`;
  $('#apkUploadStatus').textContent = `${run.apk_name || 'original.apk'} will be reused from the recorded run.`;

  const policy = run.success_policy || {};
  form.elements.policy_preset.value = ['basic', 'detection_removed', 'screen_reached', 'custom'].includes(policy.preset) ? policy.preset : 'advanced';
  form.elements.policy_repeat.value = String(policy.repeat || 1);
  form.elements.expected_activity.value = policy.expected_activity || '';
  form.elements.expected_ui_pattern.value = policy.expected_ui_pattern || '';
  form.elements.forbidden_ui_pattern.value = policy.forbidden_ui_pattern || '';
  if (policy.path) form.elements.success_spec.value = policy.path;
  updatePolicyBuilder();

  const transport = form.querySelector(`[name="transport"][value="${run.transport || 'adb'}"]`);
  if (transport) transport.checked = true;
  form.elements.target.value = run.target || '';
  form.elements.package.value = run.package || '';
  form.elements.observation_seconds.value = run.observation_seconds || 15;
  form.elements.run_seconds.value = run.run_seconds || 20;
  form.elements.frida_server.value = run.frida_server || '/data/local/tmp/frida-server';
  form.elements.provider.value = run.provider || 'codex';
  renderModelOptions();
  form.elements.model.value = run.model || '';
  renderReasoningOptions(form.elements.model);
  form.elements.reasoning_effort.value = run.reasoning_effort || '';
  form.elements.reasoning_mode.value = run.reasoning_mode || 'single';
  form.elements.specialist_count.value = String(run.specialist_count || 3);
  updateReasoningMode(form.elements.reasoning_mode);
  updateTransport();
  resetReadiness();
  $('#launch').scrollIntoView({ behavior: 'smooth' });
  toast('Policy copied into a new linked assessment. Edit it, then run device readiness.');
}

function renderAssistantTurns() {
  const container = $('#assistantMessages');
  if (!state.assistantTurns.length) {
    container.innerHTML = '<p class="assistant-empty">Ask a question about this run\'s findings, logs, hooks, decisions, or success checks.</p>';
    return;
  }
  container.innerHTML = state.assistantTurns.map(turn => {
    const citations = (turn.citations || []).map(citation => `
      <button class="assistant-citation" type="button" data-chat-citation="${escapeText(citation.path)}" title="${escapeText(citation.note || '')}">${escapeText(citation.path)}</button>`).join('');
    const action = turn.suggested_action || {};
    const groundingWarning = turn.grounded === false ? `<div class="assistant-warning">${escapeText(turn.warning || 'This answer is not grounded in accessible run evidence.')}</div>` : '';
    const run = state.overview?.runs.find(item => item.id === state.assistantRun);
    const actionCard = action.type === 'rerun' ? `
      <section class="assistant-action">
        <strong>Proposed rerun</strong>
        <p>${escapeText(action.reason || 'Use stronger reasoning on the recorded evidence.')}</p>
        <dl>
          <dt>Model</dt><dd>${escapeText(action.model || 'Account default')}</dd>
          <dt>Thinking</dt><dd>${escapeText(action.reasoning_effort || 'Model default')}</dd>
          <dt>Mode</dt><dd>${escapeText(action.reasoning_mode || 'single')}${action.reasoning_mode === 'parallel' ? ` · ${Number(action.specialist_count || 3)} specialists` : ''}</dd>
          <dt>Iterations</dt><dd>${Number(action.additional_iterations || 3)}</dd>
        </dl>
        <button class="button" type="button" data-chat-action="${escapeText(turn.id)}" ${run?.retryable ? '' : 'disabled'}>Review in Continue / retry</button>
      </section>` : '';
    return `
      <article class="assistant-message user"><p>${escapeText(turn.question || '')}</p></article>
      <article class="assistant-message assistant">
        <span class="assistant-meta">${escapeText(turn.provider || 'codex')} · ${escapeText(turn.model || 'account-default')} · ${escapeText(formatDate(turn.created_utc))}</span>
        ${groundingWarning}
        <p>${escapeText(turn.answer || '')}</p>
        ${citations ? `<div class="assistant-citations">${citations}</div>` : ''}
        ${actionCard}
      </article>`;
  }).join('');
  $$('[data-chat-citation]').forEach(button => button.addEventListener('click', () => {
    const runId = state.assistantRun;
    $('#assistantDialog').close();
    if (runId) openArtifactBrowser(runId, button.dataset.chatCitation);
  }));
  $$('[data-chat-action]').forEach(button => button.addEventListener('click', () => prepareAssistantRerun(button.dataset.chatAction)));
  container.scrollTop = container.scrollHeight;
}

async function openRunAssistant(runId) {
  const run = state.overview?.runs.find(item => item.id === runId);
  if (!run) return;
  state.assistantRun = runId;
  state.assistantTurns = [];
  $('#assistantTitle').textContent = run.package || run.id;
  $('#assistantSubtitle').textContent = `${run.id} · ${String(run.status || 'analysis').replaceAll('_', ' ')}`;
  $('#assistantMessages').innerHTML = '<p class="assistant-empty">Loading conversation…</p>';
  const dialog = $('#assistantDialog');
  const form = $('#assistantForm');
  form.elements.provider.value = run.provider || 'codex';
  renderModelOptions();
  if (run.model && [...form.elements.model.options].some(item => item.value === run.model)) form.elements.model.value = run.model;
  renderReasoningOptions(form.elements.model);
  if (!dialog.open) dialog.showModal();
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(runId)}/assistant`);
    if (state.assistantRun !== runId) return;
    state.assistantTurns = payload.turns || [];
    renderAssistantTurns();
  } catch (error) {
    $('#assistantMessages').innerHTML = `<p class="assistant-empty">${escapeText(error.message)}</p>`;
  }
}

function prepareAssistantRerun(turnId) {
  const turn = state.assistantTurns.find(item => item.id === turnId);
  const run = state.overview?.runs.find(item => item.id === state.assistantRun);
  if (!turn || !run || !run.retryable) return;
  const action = turn.suggested_action || {};
  const form = $('#resumeForm');
  state.continuationMode = 'retry';
  setTab('resume');
  $('#resumeRun').value = run.path;
  populateContinuationValues(run);
  form.elements.provider.value = action.provider || run.provider || 'codex';
  renderModelOptions();
  form.elements.max_iterations.value = String(Math.max(1, Math.min(10, Number(action.additional_iterations || 3))));
  if (action.model) {
    if (![...form.elements.model.options].some(item => item.value === action.model)) option(form.elements.model, action.model, `${action.model} · suggested`);
    form.elements.model.value = action.model;
    renderReasoningOptions(form.elements.model);
  }
  if (action.reasoning_effort && [...form.elements.reasoning_effort.options].some(item => item.value === action.reasoning_effort)) {
    form.elements.reasoning_effort.value = action.reasoning_effort;
  }
  form.elements.reasoning_mode.value = action.reasoning_mode === 'parallel' ? 'parallel' : 'single';
  form.elements.specialist_count.value = String(action.specialist_count || 3);
  form.elements.authorized.checked = false;
  updateReasoningMode(form.elements.reasoning_mode);
  updateResumeSummary();
  $('#assistantDialog').close();
  $('#launch').scrollIntoView({ behavior: 'smooth', block: 'start' });
  toast('Rerun proposal loaded. Review it and confirm authorization before submitting.');
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

async function openArtifactBrowser(runId, requestedPath = '') {
  const dialog = $('#artifactDialog');
  state.artifactRun = runId;
  state.artifactManifest = null;
  state.artifactCategory = null;
  state.artifactPath = null;
  $('#artifactTitle').textContent = 'Assessment evidence';
  $('#artifactSubtitle').textContent = `${runId} · loading manifest…`;
  $('#artifactCategories').innerHTML = '<p class="artifact-empty">Loading categories…</p>';
  $('#artifactFileList').innerHTML = '<p class="artifact-empty">Loading artifacts…</p>';
  $('#artifactPreview').textContent = 'No artifact selected.';
  $('#artifactDownload').hidden = true;
  if (!dialog.open) dialog.showModal();
  try {
    const manifest = await api(`/api/runs/${encodeURIComponent(runId)}/artifacts`);
    if (state.artifactRun !== runId) return;
    state.artifactManifest = manifest;
    $('#artifactTitle').textContent = manifest.run.package || manifest.run.id;
    $('#artifactSubtitle').textContent = `${manifest.run.id} · ${String(manifest.run.status || 'analysis').replaceAll('_', ' ')}`;
    $('#artifactCategories').innerHTML = manifest.categories.map(category => `
      <button class="artifact-category" data-artifact-category="${escapeText(category.id)}">
        <strong>${escapeText(category.label)}</strong><span>${category.files.length}</span>
        <small>${escapeText(category.description)}</small>
      </button>`).join('');
    $$('[data-artifact-category]').forEach(button => button.addEventListener('click', () => selectArtifactCategory(button.dataset.artifactCategory)));
    const requestedCategory = requestedPath ? manifest.categories.find(category => category.files.some(file => file.path === requestedPath)) : null;
    const initial = requestedCategory || manifest.categories.find(category => category.files.length) || manifest.categories[0];
    if (initial) {
      selectArtifactCategory(initial.id);
      if (requestedPath && initial.files.some(file => file.path === requestedPath)) selectArtifactFile(requestedPath);
    }
  } catch (error) {
    $('#artifactCategories').innerHTML = `<p class="artifact-empty">${escapeText(error.message)}</p>`;
    $('#artifactFileList').innerHTML = '<p class="artifact-empty">The artifact manifest could not be loaded.</p>';
  }
}

function selectArtifactCategory(categoryId) {
  const category = state.artifactManifest?.categories.find(item => item.id === categoryId);
  if (!category) return;
  state.artifactCategory = categoryId;
  state.artifactPath = null;
  $$('[data-artifact-category]').forEach(button => button.classList.toggle('active', button.dataset.artifactCategory === categoryId));
  $('#artifactCategoryTitle').textContent = category.label;
  $('#artifactCategoryDescription').textContent = category.description;
  $('#artifactFileCount').textContent = `${category.files.length} file${category.files.length === 1 ? '' : 's'}`;
  $('#artifactFileList').innerHTML = category.files.length ? category.files.map(file => `
    <button class="artifact-file" data-artifact-file="${escapeText(file.path)}">
      <strong>${escapeText(file.name)}</strong>
      <small>${escapeText(file.path)} · ${formatBytes(file.size)}</small>
    </button>`).join('') : '<p class="artifact-empty">No artifacts were recorded in this category.</p>';
  $$('[data-artifact-file]').forEach(button => button.addEventListener('click', () => selectArtifactFile(button.dataset.artifactFile)));
  $('#artifactPreviewTitle').textContent = 'Preview';
  $('#artifactPreviewMeta').textContent = category.files.length ? 'Select a file to inspect it.' : 'Nothing was recorded for this run.';
  $('#artifactPreview').textContent = 'No artifact selected.';
  $('#artifactDownload').hidden = true;
  if (category.files.length) selectArtifactFile(category.files[0].path);
}

async function selectArtifactFile(path) {
  const category = state.artifactManifest?.categories.find(item => item.id === state.artifactCategory);
  const file = category?.files.find(item => item.path === path);
  if (!file || !state.artifactRun) return;
  const runId = state.artifactRun;
  state.artifactPath = path;
  $$('[data-artifact-file]').forEach(button => button.classList.toggle('active', button.dataset.artifactFile === path));
  $('#artifactPreviewTitle').textContent = file.name;
  $('#artifactPreviewMeta').textContent = `${file.path} · ${formatBytes(file.size)}`;
  const download = $('#artifactDownload');
  download.href = `/api/runs/${encodeURIComponent(runId)}/artifacts/download?path=${encodeURIComponent(path)}`;
  download.hidden = false;
  if (!file.previewable) {
    $('#artifactPreview').textContent = 'Preview is unavailable for this file type. Use Download to inspect the original artifact.';
    return;
  }
  const cacheKey = `${runId}:${path}`;
  const showPreview = payload => {
    let content = payload.content || '';
    if (path.toLowerCase().endsWith('.json')) {
      try { content = JSON.stringify(JSON.parse(content), null, 2); } catch (_) {}
    }
    $('#artifactPreview').textContent = content || '(empty artifact)';
    if (payload.truncated) $('#artifactPreviewMeta').textContent += ' · preview truncated';
  };
  const cached = state.artifactPreviewCache.get(cacheKey);
  if (cached) {
    showPreview(cached);
    return;
  }
  $('#artifactPreview').textContent = 'Loading preview…';
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(runId)}/artifacts/content?path=${encodeURIComponent(path)}`);
    if (state.artifactRun !== runId || state.artifactPath !== path) return;
    state.artifactPreviewCache.set(cacheKey, payload);
    if (state.artifactPreviewCache.size > 12) state.artifactPreviewCache.delete(state.artifactPreviewCache.keys().next().value);
    showPreview(payload);
  } catch (error) {
    $('#artifactPreview').textContent = `Preview failed: ${error.message}`;
  }
}

function renderJobs(jobs) {
  const strip = $('#jobStrip');
  state.jobStripScroll = strip.scrollTop;
  if (!jobs.length) {
    strip.innerHTML = '<p>No jobs started from this dashboard.</p>';
    return;
  }
  if (!state.selectedJob || !jobs.some(job => job.id === state.selectedJob)) state.selectedJob = jobs[0].id;
  const groups = new Map();
  jobs.forEach(job => {
    const key = job.run_id || `job:${job.id}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(job);
  });
  const attemptName = kind => ({
    initial: 'Initial assessment', resume: 'Resume iterations',
    frida_recovery: 'Fix Frida', observation_recovery: 'Recover observation',
    validation_recovery: 'Recover validation', checkpoint_recovery: 'Recover checkpoint',
    diagnostic_retry: 'Rerun / retry',
  })[kind] || String(kind || 'Assessment').replaceAll('_', ' ');
  const statusClass = value => `status-${String(value || 'unknown').toLowerCase().replaceAll('_', '-').replaceAll(' ', '-')}`;
  strip.innerHTML = [...groups.entries()].slice(0, 6).map(([key, attempts]) => {
    const latest = attempts[0];
    const run = state.overview?.runs.find(item => item.id === latest.run_id);
    const selectedHere = attempts.some(job => job.id === state.selectedJob);
    const status = latest.running ? 'RUNNING' : String(latest.status || `exit ${latest.exit_code ?? '?'}`).replaceAll('_', ' ').toUpperCase();
    const title = run?.package || latest.run_id || latest.label;
    const subtitle = latest.run_id ? `${latest.run_id} · ${attempts.length} attempt${attempts.length === 1 ? '' : 's'}` : 'Preparing run checkpoint';
    if (attempts.length > 1) {
      if (!state.knownAttemptRuns.has(key)) {
        state.knownAttemptRuns.add(key);
        if (selectedHere || state.expandedRuns.size === 0) {
          state.expandedRuns.clear();
          state.expandedRuns.add(key);
        }
      }
      const history = attempts.map(job => `
        <button class="attempt-chip ${job.id === state.selectedJob ? 'active' : ''}" data-job="${job.id}">
          <span><strong>Attempt ${job.attempt_number || 1}</strong><small>${escapeText(attemptName(job.attempt_kind))}</small></span>
          <b class="job-status ${statusClass(job.running ? 'running' : job.status)}">${job.running ? 'RUNNING' : escapeText(String(job.status || 'unknown').replaceAll('_', ' ').toUpperCase())}</b>
        </button>`).join('');
      return `<details class="job-group attempt-group ${selectedHere ? 'active' : ''}" data-run-group="${escapeText(key)}" ${state.expandedRuns.has(key) ? 'open' : ''}>
        <summary class="job-group-summary">
          <span class="job-summary-copy"><strong>${escapeText(title)}</strong><small>${escapeText(latest.run_id)} &middot; ${attempts.length} attempts</small></span>
          <span class="job-summary-meta"><b class="job-status ${statusClass(latest.running ? 'running' : latest.status)}">${escapeText(status)}</b><em class="history-cta"><span class="history-show">View ${attempts.length} attempts</span><span class="history-hide">Hide attempts</span><i aria-hidden="true">&#8250;</i></em></span>
        </summary>
        <div class="attempt-list">${history}</div>
      </details>`;
    }
    return `<div class="job-group ${selectedHere ? 'active' : ''}">
      <button class="job-chip job-group-head active" data-job="${latest.id}"><span><strong>${escapeText(title)}</strong><small>${escapeText(subtitle)}</small></span><b>${escapeText(status)}</b></button>
    </div>`;
  }).join('');
  $$('[data-run-group]').forEach(group => group.addEventListener('toggle', () => {
    if (group.open) {
      state.expandedRuns.clear();
      state.expandedRuns.add(group.dataset.runGroup);
      $$('[data-run-group]').forEach(other => {
        if (other !== group && other.open) other.open = false;
      });
    } else {
      state.expandedRuns.delete(group.dataset.runGroup);
    }
  }));
  strip.scrollTop = state.jobStripScroll;
  $$('[data-job]').forEach(button => button.addEventListener('click', () => { state.selectedJob = button.dataset.job; renderJobs(jobs); }));
  refreshSelectedJob();
}

async function refreshSelectedJob() {
  if (!state.selectedJob) return;
  try {
    const job = await api(`/api/jobs/${state.selectedJob}`);
    const output = [job.stdout, job.stderr && `\n[stderr]\n${job.stderr}`].filter(Boolean).join('');
    $('#consoleOutput').textContent = output || (job.status === 'queued' ? 'Queued; waiting for the durable worker…' : 'Process started; waiting for output…');
    $('#consoleOutput').scrollTop = $('#consoleOutput').scrollHeight;
    const attempt = String(job.attempt_kind || job.kind || 'assessment').replaceAll('_', ' ');
    $('#jobLabel').textContent = `${attempt} · ${job.run_id || job.label} · attempt ${job.attempt_number || 1}`;
    $('#livePill').textContent = job.running ? 'RUNNING' : String(job.status || `exit ${job.exit_code ?? '?'}`).replaceAll('_', ' ').toUpperCase();
    $('#livePill').classList.toggle('running', job.running);
    if (job.running || job.status === 'queued') schedulePoll();
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

async function discoverDevices(showToast = true) {
  const button = $('#discoverDevices');
  button.disabled = true;
  button.textContent = 'Discovering…';
  try {
    const data = await api('/api/devices');
    state.devices = data.devices;
    const wirelessDevices = data.wireless_devices || [];
    const list = $('#deviceOptions');
    list.replaceChildren();
    data.devices.forEach(device => option(list, device.serial, `${device.serial} · ${device.state}`));
    wirelessDevices.filter(device => device.endpoint).forEach(device => {
      if (![...list.options].some(item => item.value === device.endpoint)) {
        option(list, device.endpoint, `${device.endpoint} · ${String(device.status).replaceAll('_', ' ')}`);
      }
    });
    renderWirelessDevices(wirelessDevices);
    const connectedCount = data.devices.filter(device => device.state === 'device').length;
    $('#deviceCount').textContent = connectedCount;
    $('#deviceCaption').textContent = wirelessDevices.length
      ? `${connectedCount} connected · ${wirelessDevices.length} known wireless`
      : data.devices.length ? `${data.devices.length} ADB entries` : 'none visible';
    const target = $('#newForm [name="target"]');
    if (!target.value && data.devices.filter(device => device.state === 'device').length === 1) {
      target.value = data.devices.find(device => device.state === 'device').serial;
      resetReadiness();
    }
    if (showToast) toast(`Found ${data.devices.length} ADB entries and ${wirelessDevices.length} wireless records.`);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Discover devices'; }
}

function wirelessStatusLabel(status) {
  return ({
    connected: 'Connected', previously_paired: 'Previously paired', discovered: 'Discovered',
    unauthorized: 'Unauthorized', offline: 'Offline',
  })[status] || String(status || 'Unknown').replaceAll('_', ' ');
}

function renderWirelessDevices(devices) {
  const container = $('#wirelessDevices');
  if (!devices.length) {
    container.innerHTML = '<p>No paired or discovered wireless devices yet.</p>';
    return;
  }
  container.innerHTML = devices.map(device => {
    const endpoint = device.endpoint || '';
    const timestamp = device.last_connected_utc || device.paired_utc;
    const detail = endpoint || device.host || device.pairing_endpoint || 'Connection address not discovered';
    const action = endpoint
      ? `<button class="text-button wireless-action" type="button" data-wireless-endpoint="${escapeText(endpoint)}" data-wireless-connected="${device.status === 'connected'}">${device.status === 'connected' ? 'Use device' : 'Connect'}</button>`
      : '<small class="wireless-address-needed">Enter its connection address below</small>';
    return `<article class="wireless-device ${escapeText(device.status)}">
      <span class="wireless-dot" aria-hidden="true"></span>
      <div><strong>${escapeText(detail)}</strong><small>${escapeText(timestamp ? `Last known ${formatDate(timestamp)}` : device.details || 'Visible on the local network')}</small></div>
      <b>${escapeText(wirelessStatusLabel(device.status))}</b>${action}
    </article>`;
  }).join('');
  $$('[data-wireless-endpoint]').forEach(button => button.addEventListener('click', () => useWirelessDevice(button)));
}

async function useWirelessDevice(button) {
  const endpoint = button.dataset.wirelessEndpoint;
  const connected = button.dataset.wirelessConnected === 'true';
  button.disabled = true;
  try {
    if (!connected) {
      await api('/api/devices/connect', { method: 'POST', body: JSON.stringify({ endpoint }) });
    }
    const transport = $('#newForm [name="transport"][value="wireless"]');
    transport.checked = true;
    updateTransport();
    $('#newForm [name="target"]').value = endpoint;
    resetReadiness();
    toast(connected ? 'Wireless device selected.' : 'Wireless device connected and selected.');
    await discoverDevices(false);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

function formJson(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  delete data.apk_file;
  delete data.frida_binary;
  delete data.pair_endpoint;
  delete data.pair_code;
  form.querySelectorAll('input[type="checkbox"]').forEach(input => { data[input.name] = input.checked; });
  ['max_iterations', 'observation_seconds', 'run_seconds', 'specialist_count'].forEach(key => { if (key in data) data[key] = Number(data[key]); });
  return data;
}

function updateReasoningMode(select) {
  const field = select.form.querySelector('.specialist-count');
  const parallel = select.value === 'parallel';
  field.hidden = !parallel;
  field.querySelector('select').disabled = !parallel;
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
    status.textContent = result.connection_endpoint
      ? `${result.message} The connection address was discovered automatically.`
      : `${result.message} Enter the separate connection address below.`;
    if (result.connection_endpoint) {
      $('#newForm [name="target"]').value = result.connection_endpoint;
      resetReadiness();
    }
    toast(result.message);
    await discoverDevices(false);
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
    const payload = formJson(form);
    const providerState = state.overview?.providers?.[payload.provider || 'codex'];
    if (!providerState?.authenticated) throw new Error(`Connect your ${(payload.provider || 'codex') === 'codex' ? 'ChatGPT' : 'Claude'} account before starting an assessment.`);
    if (endpoint === '/api/start') {
      if (!payload.readiness_token) throw new Error('Run device readiness and resolve every required check before starting.');
      if (!payload.source_run) {
      const file = form.elements.apk_file.files[0];
      if (!file) throw new Error('Choose an APK file.');
      $('#apkUploadStatus').textContent = `Uploading ${file.name}…`;
      const uploaded = await uploadApk(file);
      payload.apk = uploaded.path;
      $('#apkUploadStatus').textContent = `${uploaded.name} uploaded · ${(uploaded.size / 1048576).toFixed(1)} MB`;
      }
    }
    const job = await api(endpoint, { method: 'POST', body: JSON.stringify(payload) });
    state.selectedJob = job.id;
    toast(`${job.kind === 'retry' ? 'Rerun / retry' : job.kind === 'resume' ? 'Resume' : 'Assessment'} job queued.`);
    renderOverview(await api('/api/overview'));
    $('#activity').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

function renderAuth(data) {
  const provider = data.id || state.authProvider;
  const account = data.account_label || (provider === 'codex' ? 'ChatGPT' : 'Claude');
  const flow = data.device_flow || {};
  const cleanOutput = String(flow.output || '').replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '');
  $('#authKicker').textContent = `${provider.toUpperCase()} AUTHENTICATION`;
  $('#authTitle').textContent = `Connect your ${account} account`;
  $('#authCopy').textContent = `Use your ${account} account for the ${data.label || provider} reasoning provider. Browser authentication persists in a private Docker volume.`;
  $('#authStatus').textContent = data.authenticated ? `${account} account connected` : (flow.running ? 'Waiting for browser authorization…' : 'Not connected');
  $('#authOutput').textContent = data.authenticated ? (data.detail || `Logged in with ${account}.`) : (cleanOutput || data.detail || `Select Continue with ${account} to begin.`);
  const start = $('#startAuth');
  start.disabled = Boolean(flow.running || data.authenticated);
  start.textContent = data.authenticated ? 'Connected' : (flow.running ? 'Waiting for sign-in…' : `Continue with ${account}`);
  const signOut = $('#signOutAuth');
  signOut.hidden = !data.authenticated;
  signOut.disabled = false;
  const match = cleanOutput.match(/https:\/\/[^\s\u001b]+/);
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
  try { renderAuth(await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth`)); }
  catch (error) { toast(error.message, true); }
}

async function openAuth(provider = 'codex') {
  state.authProvider = provider;
  $('#authDialog').showModal();
  await refreshAuth();
}

async function beginAuth() {
  $('#startAuth').disabled = true;
  try { renderAuth(await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth/login`, { method: 'POST' })); }
  catch (error) { toast(error.message, true); $('#startAuth').disabled = false; }
}

async function signOutAuth() {
  const button = $('#signOutAuth');
  button.disabled = true;
  button.textContent = 'Signing out…';
  try {
    const account = state.authProvider === 'codex' ? 'ChatGPT' : 'Claude';
    const auth = await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth/logout`, { method: 'POST' });
    renderAuth(auth);
    await refreshOverview(true);
    toast(`${account} account signed out.`);
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
  const policyPanel = $('#resumePolicy');
  const policyName = $('#resumePolicyName');
  const policyChecks = $('#resumePolicyChecks');
  const policyHash = $('#resumePolicyHash');
  const reassessButton = $('#reassessSelected');
  const fridaRecovery = Boolean(run?.frida_recoverable || (run?.checkpoint_recoverable && run?.recovery_stage === 'observation' && run?.frida_server));
  fridaField.hidden = !fridaRecovery;
  fridaInput.disabled = !fridaRecovery;
  fridaInput.required = fridaRecovery;
  if (!run) {
    fridaInput.value = '';
    policyHash.value = '';
    policyName.textContent = 'Select a run to inspect its recorded policy.';
    policyChecks.replaceChildren();
    policyPanel.classList.remove('invalid');
    reassessButton.disabled = true;
    summary.innerHTML = '<span>↳</span><p>Select a run to see its last known state.</p>';
    return;
  }
  const policy = run.success_policy || {};
  reassessButton.disabled = false;
  policyHash.value = policy.sha256 || '';
  policyName.textContent = policy.valid ? policy.name : `${policy.name || 'Recorded success policy'} - unavailable or modified`;
  policyPanel.classList.toggle('invalid', !policy.valid);
  policyChecks.innerHTML = [
    ...(policy.checks || []).map(check => `<span>${escapeText(check.replaceAll('_', ' '))}</span>`),
    `<span class="policy-meta">${escapeText(`${policy.min_passes || policy.repeat || 1}/${policy.repeat || 1} passes`)}</span>`,
    ...(policy.baseline_required ? ['<span class="policy-meta">baseline differential</span>'] : []),
  ].join('');
  if (state.continuationMode === 'resume' && !run.continuable) state.continuationMode = 'retry';
  if (fridaRecovery) fridaInput.value = run.frida_server || '/data/local/tmp/frida-server';
  const continuationAction = run.frida_recoverable
    ? 'The failed observation will be archived, Frida will restart from this path, and observation will rerun before the reasoning provider continues.'
    : run.checkpoint_recoverable
    ? `The failed ${run.recovery_stage} checkpoint will retry without repeating completed analysis.`
    : 'Ready for additional iterations.';
  const diagnosticAction = 'Existing evidence will be archived. Observation will rerun with Android crash-buffer, process-exit and available tombstone diagnostics before the reasoning provider continues.';
  const action = state.continuationMode === 'retry' ? diagnosticAction : continuationAction;
  $('#continuationSubmit').innerHTML = state.continuationMode === 'retry' ? 'Rerun / retry <span>→</span>' : 'Continue loop <span>→</span>';
  $('#continuationHint').textContent = state.continuationMode === 'retry'
    ? 'Creates a new attempt under this assessment without overwriting earlier evidence.'
    : 'The previous candidate, validation delta, target, and policy hashes will be verified before continuation.';
  const mode = run.reasoning_mode === 'parallel' ? `parallel · ${run.specialist_count} specialists` : 'single agent';
  summary.innerHTML = `<span>↳</span><p><strong>${escapeText(run.package || run.id)}</strong><br>${run.iterations} completed iterations · ${escapeText(run.target || 'unknown target')} · ${escapeText(mode)}<br>${escapeText(run.detail || action)}<br><strong>${escapeText(action)}</strong></p>`;
}

function populateContinuationValues(run) {
  if (!run) return;
  const form = $('#resumeForm');
  form.elements.provider.value = run.provider || 'codex';
  renderModelOptions();
  const model = form.elements.model;
  if (run.model && ![...model.options].some(item => item.value === run.model)) {
    option(model, run.model, run.model);
  }
  model.value = run.model || '';
  renderReasoningOptions(model);
  const effort = form.elements.reasoning_effort;
  if (run.reasoning_effort && ![...effort.options].some(item => item.value === run.reasoning_effort)) {
    option(effort, run.reasoning_effort, reasoningLabel({ effort: run.reasoning_effort }));
  }
  effort.value = run.reasoning_effort || '';
  const mode = form.elements.reasoning_mode;
  mode.value = run.reasoning_mode || 'single';
  form.elements.specialist_count.value = String(run.specialist_count || 3);
  updateReasoningMode(mode);
}

async function askRunAssistant(event) {
  event.preventDefault();
  if (!state.assistantRun) return;
  const form = event.currentTarget;
  const question = form.elements.question.value.trim();
  if (!question) return;
  const button = $('#sendAssistant');
  button.disabled = true;
  button.innerHTML = 'Reviewing evidence…';
  const pending = document.createElement('article');
  pending.className = 'assistant-message assistant pending';
  pending.innerHTML = '<span class="assistant-progress-stage">QUEUED</span><p>Preparing the evidence request…</p><small></small>';
  $('#assistantMessages').append(pending);
  $('#assistantMessages').scrollTop = $('#assistantMessages').scrollHeight;
  try {
    const runId = state.assistantRun;
    const requestState = await api(`/api/runs/${encodeURIComponent(runId)}/assistant`, {
      method: 'POST',
      body: JSON.stringify({
        question,
        provider: form.elements.provider.value,
        model: form.elements.model.value,
        reasoning_effort: form.elements.reasoning_effort.value,
      }),
    });
    let progress = requestState;
    while (!['complete', 'failed'].includes(progress.status)) {
      await new Promise(resolve => setTimeout(resolve, 700));
      progress = await api(`/api/runs/${encodeURIComponent(runId)}/assistant/requests/${encodeURIComponent(requestState.id)}`);
      const stage = pending.querySelector('.assistant-progress-stage');
      const detail = pending.querySelector('p');
      const metrics = pending.querySelector('small');
      if (stage) stage.textContent = String(progress.stage || progress.status || 'working').replaceAll('_', ' ').toUpperCase();
      if (detail) detail.textContent = progress.detail || 'Working on the answer…';
      if (metrics) metrics.textContent = progress.selected_files
        ? `${progress.selected_files} relevant files · ${Number(progress.evidence_characters || 0).toLocaleString()} evidence characters`
        : '';
    }
    if (progress.status === 'failed') throw new Error(progress.error || progress.detail || 'The run assistant failed.');
    const turn = progress.turn;
    if (!turn) throw new Error('The run assistant completed without returning an answer.');
    state.assistantTurns.push(turn);
    form.elements.question.value = '';
    renderAssistantTurns();
  } catch (error) {
    pending.remove();
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Ask assistant <span>→</span>';
  }
}

$$('.segment').forEach(button => button.addEventListener('click', () => setTab(button.dataset.tab)));
$('#newForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, '/api/start'); });
$('#resumeForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, state.continuationMode === 'retry' ? '/api/retry' : '/api/resume'); });
$('#resumeRun').addEventListener('change', () => {
  const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
  state.continuationMode = run?.continuable ? 'resume' : 'retry';
  populateContinuationValues(run);
  updateResumeSummary();
});
$('#discoverDevices').addEventListener('click', () => discoverDevices(true));
$('#runReadiness').addEventListener('click', runReadiness);
$$('#newForm [name="transport"]').forEach(input => input.addEventListener('change', updateTransport));
['target', 'frida_server'].forEach(name => $('#newForm').elements[name].addEventListener('input', resetReadiness));
$('#newForm [name="frida_binary"]').addEventListener('change', resetReadiness);
$('#newForm [name="start_frida"]').addEventListener('change', resetReadiness);
$$('.model-select').forEach(select => select.addEventListener('change', () => {
  const reasoning = select.form.querySelector('.reasoning-select');
  if (reasoning) reasoning.value = '';
  renderReasoningOptions(select);
}));
$$('.provider-select').forEach(select => select.addEventListener('change', () => {
  const model = select.form.querySelector('.model-select');
  if (model) model.value = '';
  renderModelOptions();
}));
$$('.reasoning-mode').forEach(select => {
  select.addEventListener('change', () => updateReasoningMode(select));
  updateReasoningMode(select);
});
$('#pairDevice').addEventListener('click', pairWirelessDevice);
$('#policyPreset').addEventListener('change', updatePolicyBuilder);
$('#clearReassessment').addEventListener('click', clearReassessment);
$('#reassessSelected').addEventListener('click', () => {
  const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
  if (run) beginReassessment(run.id);
});
$('#newForm [name="policy_repeat"]').addEventListener('change', updatePolicyBuilder);
$('#refreshAll').addEventListener('click', () => refreshOverview(true));
$('#copyLog').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#consoleOutput').textContent); toast('Console copied.'); }
  catch (_) { toast('Clipboard access was unavailable.', true); }
});
$('#codexAuth').addEventListener('click', () => openAuth('codex'));
$('#claudeAuth').addEventListener('click', () => openAuth('claude'));
$('#startAuth').addEventListener('click', beginAuth);
$('#signOutAuth').addEventListener('click', signOutAuth);
$('#closeArtifacts').addEventListener('click', () => { state.artifactRun = null; $('#artifactDialog').close(); });
$('#artifactDialog').addEventListener('click', event => {
  if (event.target === event.currentTarget) { state.artifactRun = null; event.currentTarget.close(); }
});
$('#assistantForm').addEventListener('submit', askRunAssistant);
$('#closeAssistant').addEventListener('click', () => { state.assistantRun = null; $('#assistantDialog').close(); });
$('#assistantDialog').addEventListener('click', event => {
  if (event.target === event.currentTarget) { state.assistantRun = null; event.currentTarget.close(); }
});
$$('[data-assistant-prompt]').forEach(button => button.addEventListener('click', () => {
  $('#assistantQuestion').value = button.dataset.assistantPrompt;
  $('#assistantQuestion').focus();
}));
$('#closeAuth').addEventListener('click', () => { clearTimeout(state.authPoll); $('#authDialog').close(); });
$('#authDialog').addEventListener('click', event => { if (event.target === event.currentTarget) event.currentTarget.close(); });
$('#copyAuthCode').addEventListener('click', async event => {
  try { await navigator.clipboard.writeText(event.currentTarget.dataset.code); toast('One-time code copied.'); }
  catch (_) { toast('Clipboard access was unavailable.', true); }
});

refreshOverview();
discoverDevices(false);
updateTransport();
updatePolicyBuilder();
