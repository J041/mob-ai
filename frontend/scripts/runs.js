'use strict';

import { $, escapeText, option, state } from './core.js';
import { reasoningLabel } from './models.js';

export function createRunController({ renderModelOptions, renderReasoningOptions, updateReasoningMode }) {
  function updateResumeSummary() {
    const run = state.overview?.runs.find(item => item.path === $('#resumeRun').value);
    const summary = $('#resumeSummary');
    const policyPanel = $('#resumePolicy');
    const policyName = $('#resumePolicyName');
    const policyChecks = $('#resumePolicyChecks');
    const policyHash = $('#resumePolicyHash');
    const reassessButton = $('#reassessSelected');
    const fridaRecovery = Boolean(run?.frida_recoverable || (run?.checkpoint_recoverable && run?.recovery_stage === 'observation' && run?.frida_server));
    if (!run) {
      $('#resumeTarget').value = '';
      $('#resumeFridaServer').value = '';
      policyHash.value = '';
      policyName.textContent = 'Select a run to inspect its recorded policy.';
      policyChecks.replaceChildren();
      policyPanel.classList.remove('invalid');
      reassessButton.disabled = true;
      summary.innerHTML = '<span>↳</span><p>Select a run to see its last known state.</p>';
      return;
    }
    const policy = run.success_policy || {};
    const terminal = run.terminal || {};
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
    const continuationAction = run.frida_recoverable
      ? 'The failed observation will be archived, Frida will restart from this path, and observation will rerun before the reasoning provider continues.'
      : run.checkpoint_recoverable
      ? `The failed ${run.recovery_stage} checkpoint will retry without repeating completed analysis.`
      : run.usage_recoverable
      ? (run.usage_reset_utc
        ? `Provider usage was exhausted. Resume after ${new Date(run.usage_reset_utc).toLocaleString()}${run.usage_auto_resume ? '; automatic resume is enabled.' : '.'}`
        : 'Provider usage was exhausted without a reported reset time. Resume manually after checking account Usage settings.')
      : 'Ready for additional iterations.';
    const diagnosticAction = 'Existing evidence will be archived. Observation will rerun with Android crash-buffer, process-exit and available tombstone diagnostics before the reasoning provider continues.';
    const action = state.continuationMode === 'retry' ? diagnosticAction : continuationAction;
    $('#continuationSubmit').innerHTML = state.continuationMode === 'retry' ? 'Rerun / retry <span>→</span>' : 'Continue loop <span>→</span>';
    $('#continuationHint').textContent = state.continuationMode === 'retry'
      ? 'Creates a new attempt under this assessment without overwriting earlier evidence.'
      : 'The previous candidate, validation delta, target, and policy hashes will be verified before continuation.';
    const mode = run.reasoning_mode === 'parallel' ? `parallel · ${run.specialist_count} specialists` : 'single agent';
    const outcome = terminal.label
      ? `<br><strong>${escapeText(terminal.label)}</strong> — ${escapeText(terminal.explanation || run.detail || '')}<br><span class="recommended-action">Recommended: ${escapeText(terminal.recommended_action || action)}</span>`
      : `<br>${escapeText(run.detail || action)}<br><strong>${escapeText(action)}</strong>`;
    summary.innerHTML = `<span>↳</span><p><strong>${escapeText(run.package || run.id)}</strong><br>${run.iterations} completed iterations · ${escapeText(run.target || 'unknown target')} · ${escapeText(mode)}${outcome}</p>`;
  }
  
  function populateContinuationValues(run) {
    if (!run) return;
    const form = $('#resumeForm');
    form.elements.transport.value = run.transport === 'wireless' ? 'wireless' : 'adb';
    form.elements.target.value = run.target || '';
    form.elements.frida_server.value = run.frida_server || '/data/local/tmp/frida-server';
    form.elements.readiness_token.value = '';
    $('#resumeReadinessState').textContent = 'RECORDED';
    $('#resumeReadinessState').className = 'readiness-state';
    $('#resumeReadinessResults').innerHTML = '<p>The recorded target may be reused. Run readiness after selecting a different device.</p>';
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
    form.elements.auto_resume_usage_limit.checked = Boolean(run.usage_auto_resume);
    updateReasoningMode(mode);
  }
  
  
  return { populateContinuationValues, updateResumeSummary };
}
