'use strict';

import { $, $$, api, option, state, toast } from './core.js';
import { openArtifactBrowser } from './artifacts.js';
import { renderModelOptions, renderReasoningOptions } from './models.js';
import { createRunController } from './runs.js';
import { createAuthController } from './auth.js';
import { createAssistantController } from './assistant.js';
import { createDeviceController } from './devices.js';
import { connectOverviewEvents } from './events.js';
import {
  bindAdvancedPolicyEditor, ensureAdvancedPolicyReady, loadAdvancedPolicy,
  updatePolicyBuilder,
} from './policy-builder.js';
import { createActivityController } from './activity.js';
import { createTrashController } from './trash.js';
import { createRunLedgerController } from './run-ledger.js';

function tokenLabel(usage) {
  const total = Number(usage?.total_tokens || 0);
  if (!total) return 'no reported tokens';
  return `${total.toLocaleString()} tokens${usage?.complete ? '' : ' (total only)'}`;
}

function jobTypeLabel(kind, fallback) {
  return state.overview?.job_types?.[kind]?.label || fallback;
}

function setTab(name) {
  $$('.segment').forEach(button => {
    const active = button.dataset.tab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  $$('.tab-panel').forEach(panel => panel.classList.toggle('active', panel.dataset.panel === name));
}

function renderOverview(data) {
  if (state.activityHistoryLoaded) {
    const merged = new Map([
      ...state.activityJobs.map(job => [job.id, job]),
      ...(data.jobs || []).map(job => [job.id, job]),
    ]);
    state.activityJobs = [...merged.values()];
  } else {
    state.activityJobs = [...(data.jobs || [])];
    state.activityHasMore = Boolean(data.jobs_has_more);
  }
  data.jobs = state.activityJobs;
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
  $$('.frida-version').forEach(select => {
    const previous = select.value;
    select.replaceChildren();
    (data.frida_runtimes || []).forEach(runtime => option(
      select, runtime.version,
      `${runtime.version}${runtime.default ? ' (container default)' : ' (isolated)'}`,
    ));
    if ([...select.options].some(item => item.value === previous)) select.value = previous;
    else {
      const preferred = (data.frida_runtimes || []).find(runtime => runtime.default) || (data.frida_runtimes || [])[0];
      select.value = preferred?.version || '';
    }
  });

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
    `${run.package || run.id} · ${run.iterations} iterations${run.continuable ? (run.usage_recoverable ? ' · usage checkpoint' : run.frida_recoverable ? ' · fix Frida' : run.checkpoint_recoverable ? ` · recover ${run.recovery_stage}` : ' · resumable') : ' · rerun available'}`,
  ));
  if ([...resumeSelect.options].some(item => item.value === previous)) resumeSelect.value = previous;

  renderRuns(data.runs);
  renderJobs(data.jobs);
  updateResumeSummary();
  $('#lastRefresh').textContent = `Updated ${new Date().toLocaleTimeString()}`;
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
  form.elements.policy_min_passes.value = String(policy.min_passes || policy.repeat || 1);
  form.elements.expected_activity.value = policy.expected_activity || '';
  form.elements.expected_ui_pattern.value = policy.expected_ui_pattern || '';
  form.elements.policy_use_regex.checked = policy.pattern_mode !== 'phrases';
  if (policy.pattern_mode === 'phrases') {
    form.elements.forbidden_ui_phrases.value = policy.forbidden_ui_input || '';
    form.elements.forbidden_log_phrases.value = policy.forbidden_log_input || '';
  } else {
    form.elements.forbidden_ui_pattern.value = policy.forbidden_ui_input || policy.forbidden_ui_pattern || '';
    form.elements.forbidden_log_pattern.value = policy.forbidden_log_input || policy.forbidden_log_pattern || '';
  }
  if (policy.path) form.elements.success_spec.value = policy.path;
  updatePolicyBuilder();
  if (form.elements.policy_preset.value === 'advanced') {
    $('#policyJsonDocument').value = '';
    loadAdvancedPolicy().catch(() => {});
  }

  const transport = form.querySelector(`[name="transport"][value="${run.transport || 'adb'}"]`);
  if (transport) transport.checked = true;
  form.elements.target.value = run.target || '';
  form.elements.package.value = run.package || '';
  form.elements.observation_seconds.value = run.observation_seconds || 15;
  form.elements.run_seconds.value = run.run_seconds || 20;
  form.elements.frida_server.value = run.frida_server || '/data/local/tmp/frida-server';
  form.elements.frida_version.value = run.frida_version || form.elements.frida_version.value;
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

async function refreshOverview(showToast = false) {
  const button = $('#refreshAll');
  button.disabled = true;
  try {
    renderOverview(await api('/api/overview'));
    if (showToast) toast('Dashboard refreshed.');
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
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
    if (endpoint === '/api/start') await ensureAdvancedPolicyReady(form);
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
    toast(`${job.job_type?.label || jobTypeLabel(job.kind, 'Assessment')} job queued.`);
    renderOverview(await api('/api/overview'));
    $('#activity').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

const {
  discoverDevices, pairWirelessDevice, resetReadiness, resetResumeReadiness,
  runReadiness, runResumeReadiness, updateResumeTransport, updateTransport,
} = createDeviceController();

const { populateContinuationValues, updateResumeSummary } = createRunController({
  renderModelOptions, renderReasoningOptions, updateReasoningMode, updateResumeTransport,
});

const { askRunAssistant, openRunAssistant } = createAssistantController({
  openArtifactBrowser, populateContinuationValues, renderModelOptions,
  renderReasoningOptions, setTab, updateReasoningMode, updateResumeSummary,
});

const { renderRuns } = createRunLedgerController({
  jobTypeLabel, openArtifactBrowser, openRunAssistant, populateContinuationValues,
  renderOverviewSnapshot: renderOverview, setTab, tokenLabel, updateResumeSummary,
});

const { beginAuth, openAuth, signOutAuth } = createAuthController({ refreshOverview });

const { openTrash } = createTrashController({ renderOverviewSnapshot: renderOverview });

const { bindActivityControls, renderJobs, schedulePoll } = createActivityController({
  tokenLabel, renderOverviewSnapshot: renderOverview,
});

$$('.segment').forEach(button => button.addEventListener('click', () => setTab(button.dataset.tab)));
$('#newForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, '/api/start'); });
$('#resumeForm').addEventListener('submit', event => { event.preventDefault(); submitForm(event.currentTarget, state.continuationMode === 'retry' ? '/api/retry' : '/api/resume'); });
$('#resumeRun').addEventListener('change', () => {
  const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
  state.continuationMode = run?.continuable ? 'resume' : 'retry';
  populateContinuationValues(run);
  updateResumeTransport();
  updateResumeSummary();
});
$('#discoverDevices').addEventListener('click', () => discoverDevices(true));
$('#runReadiness').addEventListener('click', runReadiness);
$('#runResumeReadiness').addEventListener('click', runResumeReadiness);
$$('#newForm [name="transport"]').forEach(input => input.addEventListener('change', updateTransport));
$('#resumeTransport').addEventListener('change', updateResumeTransport);
['target', 'frida_server', 'frida_version'].forEach(name => $('#newForm').elements[name].addEventListener('input', resetReadiness));
$('#newForm [name="frida_binary"]').addEventListener('change', resetReadiness);
$('#newForm [name="start_frida"]').addEventListener('change', resetReadiness);
['target', 'frida_server', 'frida_version', 'transport'].forEach(name => $('#resumeForm').elements[name].addEventListener('input', resetResumeReadiness));
$('#resumeForm [name="frida_binary"]').addEventListener('change', resetResumeReadiness);
$('#resumeForm [name="start_frida"]').addEventListener('change', resetResumeReadiness);
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
$('#pairDevice').addEventListener('click', () => pairWirelessDevice(false));
$('#resumePairDevice').addEventListener('click', () => pairWirelessDevice(true));
$('#policyPreset').addEventListener('change', updatePolicyBuilder);
bindAdvancedPolicyEditor();
$('#clearReassessment').addEventListener('click', clearReassessment);
$('#reassessSelected').addEventListener('click', () => {
  const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
  if (run) beginReassessment(run.id);
});
$$('#newForm .policy-builder input').forEach(input => input.addEventListener('input', updatePolicyBuilder));
$$('#newForm .policy-builder select').forEach(select => {
  if (select.id !== 'policyPreset') select.addEventListener('change', updatePolicyBuilder);
});
$('#refreshAll').addEventListener('click', () => refreshOverview(true));
$('#manageTrash').addEventListener('click', openTrash);
bindActivityControls();
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
$('#closeTrash').addEventListener('click', () => $('#trashDialog').close());
$('#trashDialog').addEventListener('click', event => { if (event.target === event.currentTarget) event.currentTarget.close(); });
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
connectOverviewEvents({
  onOverview: renderOverview,
  onFallback: () => schedulePoll(1200),
});
discoverDevices(false);
updateTransport();
updateResumeTransport();
updatePolicyBuilder();
