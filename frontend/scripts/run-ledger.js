'use strict';

import { $, $$, api, escapeText, state, toast } from './core.js';

export function createRunLedgerController({
  jobTypeLabel, openArtifactBrowser, openRunAssistant, populateContinuationValues,
  renderOverviewSnapshot, setTab, tokenLabel, updateResumeSummary,
}) {
  function renderRuns(runs) {
    const list = $('#runList');
    if (!runs.length) {
      list.innerHTML = '<div class="empty">No assessment runs found.</div>';
      return;
    }
    list.innerHTML = runs.map(run => {
      const native = run.native_queue || {};
      const terminal = run.terminal || {};
      const nativeProgress = native.total ? ` · native batch ${native.batch}/${native.batches} · ${native.processed}/${native.total} processed` : '';
      return `
      <article class="run-row">
        <div class="run-main"><strong>${escapeText(run.package || run.id)}</strong><small>${escapeText(run.id)} · ${run.static_findings} static findings${escapeText(nativeProgress)}</small></div>
        <div class="run-cell"><span>${escapeText(run.target || 'no target')}</span><small>${run.derived_from_run ? `derived from ${escapeText(run.derived_from_run)} - ` : ''}${escapeText(run.transport || 'analysis only')}</small></div>
        <div class="run-cell"><span>${run.iterations} iterations</span><small title="${escapeText(tokenLabel(run.token_usage))}">${run.reasoning_mode === 'parallel' ? `${run.specialist_count} specialists` : 'single agent'} · ${run.observation_events} observations · ${escapeText(tokenLabel(run.token_usage))}</small></div>
        <div class="run-outcome">
          <span class="badge ${escapeText(run.status)}">${escapeText(run.status.replaceAll('_', ' '))}</span>
          ${terminal.label ? `<small title="${escapeText(terminal.explanation || '')}">${escapeText(terminal.label)}</small>` : ''}
          ${terminal.recommended_action ? `<span class="outcome-action" title="${escapeText(terminal.recommended_action)}">${escapeText(terminal.recommended_action)}</span>` : ''}
        </div>
        <div class="run-actions">
          <button class="resume-button assistant" data-assistant="${escapeText(run.id)}">Ask assistant</button>
          <button class="resume-button artifacts" data-artifacts="${escapeText(run.id)}">Artifacts</button>
          ${run.successful_script ? `<a class="resume-button download-script" href="/api/runs/${encodeURIComponent(run.id)}/artifacts/download?path=${encodeURIComponent(run.successful_script)}" download>Download script</a>` : ''}
          ${run.successful_script ? `<button class="resume-button launch-bypass" data-launch-bypass="${escapeText(run.id)}">${escapeText(jobTypeLabel('launch_bypass', 'Run APK + bypass'))}</button>` : ''}
          ${run.continuable ? `<button class="resume-button" data-resume="${escapeText(run.path)}">${run.usage_recoverable ? 'Resume after reset' : run.frida_recoverable ? 'Fix Frida' : run.checkpoint_recoverable ? 'Recover' : 'Resume'}</button>` : ''}
          <button class="resume-button diagnostic" data-retry="${escapeText(run.path)}" ${run.retryable ? '' : 'disabled'}>Rerun / retry</button>
          ${run.deep_investigation_eligible ? `<button class="resume-button deep-goal" data-deep-goal="${escapeText(run.id)}">${run.deep_investigation_count ? 'Investigate again' : escapeText(jobTypeLabel('deep_goal', 'Deep investigation'))}</button>` : ''}
          <button class="resume-button delete-run" data-delete-run="${escapeText(run.id)}">Delete</button>
        </div>
      </article>`;
    }).join('');
    bindRunActions();
  }

  function selectContinuation(path, mode) {
    state.continuationMode = mode;
    setTab('resume');
    $('#resumeRun').value = path;
    populateContinuationValues(state.overview?.runs.find(item => item.path === path));
    updateResumeSummary();
    $('#launch').scrollIntoView({ behavior: 'smooth' });
  }

  function bindRunActions() {
    $$('[data-resume]').forEach(button => button.addEventListener('click', () => selectContinuation(button.dataset.resume, 'resume')));
    $$('[data-retry]').forEach(button => button.addEventListener('click', () => selectContinuation(button.dataset.retry, 'retry')));
    $$('[data-artifacts]').forEach(button => button.addEventListener('click', () => openArtifactBrowser(button.dataset.artifacts)));
    $$('[data-assistant]').forEach(button => button.addEventListener('click', () => openRunAssistant(button.dataset.assistant)));
    $$('[data-delete-run]').forEach(button => button.addEventListener('click', () => deleteRun(button)));
    $$('[data-launch-bypass]').forEach(button => button.addEventListener('click', () => launchBypass(button)));
    $$('[data-deep-goal]').forEach(button => button.addEventListener('click', () => startDeepInvestigation(button)));
  }

  async function deleteRun(button) {
    const run = state.overview?.runs.find(item => item.id === button.dataset.deleteRun);
    if (!run || !window.confirm(
      `Delete ${run.package || run.id}?\n\nRun ID: ${run.id}\n\n` +
      'The run and its completed job history will leave the UI and move to recoverable runtime trash. ' +
      'Active jobs or assistant requests must finish first.'
    )) return;
    button.disabled = true;
    try {
      await api(`/api/runs/${encodeURIComponent(run.id)}`, {
        method: 'DELETE', body: JSON.stringify({ confirm_run_id: run.id }),
      });
      if (state.assistantRun === run.id) state.assistantRun = null;
      toast('Assessment moved to recoverable runtime trash.');
      renderOverviewSnapshot(await api('/api/overview'));
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  async function launchBypass(button) {
    const run = state.overview?.runs.find(item => item.id === button.dataset.launchBypass);
    if (!run || !window.confirm(
      `Launch ${run.package || run.id} on ${run.target} with its validated Frida bypass? ` +
      'Confirm that authorization remains valid. The session stays attached until the app exits or you cancel the job.'
    )) return;
    button.disabled = true;
    try {
      const job = await api(`/api/runs/${encodeURIComponent(run.id)}/launch-bypass`, {
        method: 'POST', body: JSON.stringify({ confirmed: true, authorized: true }),
      });
      state.selectedJob = job.id;
      toast('Bypass session queued. Use Cancel session in Live activity to stop it.');
      renderOverviewSnapshot(await api('/api/overview'));
      $('#activity').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  async function startDeepInvestigation(button) {
    const run = state.overview?.runs.find(item => item.id === button.dataset.deepGoal);
    if (!run) return;
    const budget = Number(state.overview?.deep_goal?.default_token_budget || 75000);
    if (!window.confirm(
      `Start an optional read-only Codex Goal investigation for ${run.package || run.id}? ` +
      `It may use up to ${budget.toLocaleString()} tokens and will not run ADB, Frida, or change the assessment result.`
    )) return;
    button.disabled = true;
    try {
      const job = await api(`/api/runs/${encodeURIComponent(run.id)}/deep-investigation`, {
        method: 'POST', body: JSON.stringify({ confirmed: true, token_budget: budget }),
      });
      state.selectedJob = job.id;
      toast('Deep investigation queued.');
      renderOverviewSnapshot(await api('/api/overview'));
      $('#activity').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  return { renderRuns };
}
