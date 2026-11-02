'use strict';

import { $, $$, api, escapeText, formatDate, option, state, toast } from './core.js';

export function createAssistantController({
  openArtifactBrowser, populateContinuationValues, renderModelOptions,
  renderReasoningOptions, setTab, updateReasoningMode, updateResumeSummary,
}) {
  function renderAssistantTurns() {
    const container = $('#assistantMessages');
    if (!state.assistantTurns.length && !state.assistantFailures.length) {
      container.innerHTML = '<p class="assistant-empty">Ask a question about this run\'s findings, logs, hooks, decisions, or success checks.</p>';
      return;
    }
    const turns = state.assistantTurns.map(turn => {
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
    const failures = state.assistantFailures.map(failure => `
      <article class="assistant-message user"><p>${escapeText(failure.question || 'Assistant request')}</p></article>
      <article class="assistant-message assistant failed">
        <span class="assistant-progress-stage">FAILED</span>
        <p>${escapeText(failure.error || 'The run assistant failed.')}</p>
        <small>${escapeText(formatDate(failure.completed_utc || failure.created_utc))}</small>
      </article>`).join('');
    container.innerHTML = turns + failures;
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
    state.assistantFailures = [];
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
      state.assistantFailures = payload.failures || [];
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
  
  
  async function askRunAssistant(event) {
    event.preventDefault();
    if (!state.assistantRun) return;
    const form = event.currentTarget;
    const question = form.elements.question.value.trim();
    if (!question) return;
    const button = $('#sendAssistant');
    button.disabled = true;
    button.innerHTML = 'Reviewing evidence…';
    const userMessage = document.createElement('article');
    userMessage.className = 'assistant-message user';
    userMessage.innerHTML = `<p>${escapeText(question)}</p>`;
    const pending = document.createElement('article');
    pending.className = 'assistant-message assistant pending';
    pending.innerHTML = '<span class="assistant-progress-stage">QUEUED</span><p>Preparing the evidence request…</p><small></small>';
    $('#assistantMessages .assistant-empty')?.remove();
    $('#assistantMessages').append(userMessage, pending);
    form.elements.question.value = '';
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
      renderAssistantTurns();
    } catch (error) {
      pending.classList.remove('pending');
      pending.classList.add('failed');
      pending.innerHTML = `<span class="assistant-progress-stage">FAILED</span><p>${escapeText(error.message)}</p><small>The request did not produce an answer. Try again with a faster model.</small>`;
      $('#assistantMessages').scrollTop = $('#assistantMessages').scrollHeight;
      toast(error.message, true);
    } finally {
      button.disabled = false;
      button.innerHTML = 'Ask assistant <span>→</span>';
    }
  }
  
  
  return { askRunAssistant, openRunAssistant };
}
