'use strict';

import { $, $$, api, escapeText, state, toast } from './core.js';

function jobType(job) {
  return job?.job_type || state.overview?.job_types?.[job?.kind] || {
    label: 'Assessment', counts_as_attempt: true, supports_pause: false,
    control_noun: 'assessment', sequence_noun: 'Attempt', history_noun: 'attempt',
    attempt_labels: {},
  };
}

function attemptName(job) {
  const type = jobType(job);
  return type.attempt_labels?.[job.attempt_kind]
    || type.label
    || String(job.attempt_kind || 'Assessment').replaceAll('_', ' ');
}

function statusClass(value) {
  return `status-${String(value || 'unknown').toLowerCase().replaceAll('_', '-').replaceAll(' ', '-')}`;
}

function displayStatus(job) {
  return String(job.status || `exit ${job.exit_code ?? '?'}`).replaceAll('_', ' ').toUpperCase();
}

function sequenceLabel(job, index, attempts) {
  const type = jobType(job);
  if (!type.counts_as_attempt) {
    const sameType = attempts.filter(item => item.kind === job.kind).length;
    const prior = attempts.slice(0, index).filter(item => item.kind === job.kind).length;
    return `${type.sequence_noun || type.label} ${sameType - prior}`;
  }
  return `Attempt ${job.attempt_number || 1}`;
}

export function createActivityController({ tokenLabel, renderOverviewSnapshot }) {
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
    const groupEntries = [...groups.entries()];
    const visibleGroups = groupEntries.slice(0, state.jobGroupLimit);
    strip.innerHTML = visibleGroups.map(([key, attempts]) => {
      const latest = attempts[0];
      const assessmentAttempts = attempts.filter(job => jobType(job).counts_as_attempt);
      const auxiliaryCounts = new Map();
      attempts.filter(job => !jobType(job).counts_as_attempt).forEach(job => {
        const type = jobType(job);
        const key = job.kind || job.attempt_kind;
        auxiliaryCounts.set(key, { count: (auxiliaryCounts.get(key)?.count || 0) + 1, type });
      });
      const activityCount = [
        assessmentAttempts.length ? `${assessmentAttempts.length} attempt${assessmentAttempts.length === 1 ? '' : 's'}` : '',
        ...[...auxiliaryCounts.values()].map(({ count, type }) => `${count} ${type.history_noun}${count === 1 ? '' : 's'}`),
      ].filter(Boolean).join(' · ');
      const run = state.overview?.runs.find(item => item.id === latest.run_id);
      const terminal = run?.terminal || {};
      const selectedHere = attempts.some(job => job.id === state.selectedJob);
      const status = displayStatus(latest);
      const title = run?.package || latest.run_id || latest.label;
      const subtitle = latest.run_id
        ? `${latest.run_id} · ${activityCount} · ${tokenLabel(run?.token_usage)}`
        : 'Preparing run checkpoint';
      if (attempts.length > 1) {
        if (!state.knownAttemptRuns.has(key)) {
          state.knownAttemptRuns.add(key);
          if (selectedHere || state.expandedRuns.size === 0) {
            state.expandedRuns.clear();
            state.expandedRuns.add(key);
          }
        }
        const history = attempts.map((job, index) => `
          <button class="attempt-chip ${job.id === state.selectedJob ? 'active' : ''}" data-job="${job.id}">
            <span><strong>${sequenceLabel(job, index, attempts)}</strong><small>${escapeText(attemptName(job))} · ${escapeText(tokenLabel(job.token_usage))}</small></span>
            <b class="job-status ${statusClass(job.status)}">${escapeText(displayStatus(job))}</b>
          </button>`).join('');
        return `<details class="job-group attempt-group ${selectedHere ? 'active' : ''}" data-run-group="${escapeText(key)}" ${state.expandedRuns.has(key) ? 'open' : ''}>
          <summary class="job-group-summary">
            <span class="job-summary-copy"><strong>${escapeText(title)}</strong><small>${escapeText(latest.run_id)} &middot; ${escapeText(activityCount)} &middot; ${escapeText(tokenLabel(run?.token_usage))}</small></span>
            <span class="job-summary-meta"><b class="job-status ${statusClass(latest.status)}">${escapeText(status)}</b>${!latest.running && terminal.label ? `<small class="job-terminal-reason">${escapeText(terminal.label)}</small>` : ''}<em class="history-cta"><span class="history-show">View history</span><span class="history-hide">Hide history</span><i aria-hidden="true">&#8250;</i></em></span>
          </summary>
          <div class="attempt-list">${history}</div>
        </details>`;
      }
      return `<div class="job-group ${selectedHere ? 'active' : ''}">
        <button class="job-chip job-group-head active" data-job="${latest.id}"><span><strong>${escapeText(title)}</strong><small>${escapeText(subtitle)}</small></span><b class="job-status ${statusClass(latest.status)}">${escapeText(status)}</b></button>
      </div>`;
    }).join('') + (
      groupEntries.length > state.jobGroupLimit || state.activityHasMore
        ? '<button class="load-older-jobs" id="loadOlderJobs" type="button">Load older activity</button>'
        : ''
    );
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
    $$('[data-job]').forEach(button => button.addEventListener('click', () => {
      state.selectedJob = button.dataset.job;
      renderJobs(jobs);
    }));
    $('#loadOlderJobs')?.addEventListener('click', async event => {
      const button = event.currentTarget;
      button.disabled = true;
      button.textContent = 'Loading older activity…';
      state.jobGroupLimit += 6;
      if (state.jobGroupLimit > groupEntries.length && state.activityHasMore) {
        try {
          const page = await api(`/api/jobs?limit=20&offset=${state.activityJobs.length}`);
          const merged = new Map(state.activityJobs.map(job => [job.id, job]));
          (page.jobs || []).forEach(job => merged.set(job.id, job));
          state.activityJobs = [...merged.values()];
          state.activityHasMore = Boolean(page.has_more);
          state.activityHistoryLoaded = true;
          state.overview.jobs = state.activityJobs;
        } catch (error) {
          state.jobGroupLimit -= 6;
          toast(error.message, true);
        }
      } else {
        state.activityHistoryLoaded = true;
      }
      renderJobs(state.activityJobs);
    });
    refreshSelectedJob();
  }

  async function refreshSelectedJob() {
    if (!state.selectedJob) return;
    try {
      const job = await api(`/api/jobs/${state.selectedJob}`);
      const output = [job.stdout, job.stderr && `\n[stderr]\n${job.stderr}`].filter(Boolean).join('');
      $('#consoleOutput').textContent = output || (job.status === 'queued' ? 'Queued; waiting for the durable worker…' : 'Process started; waiting for output…');
      $('#consoleOutput').scrollTop = $('#consoleOutput').scrollHeight;
      const type = jobType(job);
      $('#jobLabel').textContent = `${attemptName(job)} · ${job.run_id || job.label} · ${sequenceLabel(job, 0, [job]).toLowerCase()}`;
      $('#livePill').textContent = displayStatus(job);
      $('#livePill').className = `live-pill${job.status === 'running' ? ' running' : ''}${job.status === 'pausing' || job.status === 'cancelling' ? ` ${job.status}` : ''}`;
      $('#pauseJob').disabled = !type.supports_pause || !job.running || job.status !== 'running' || Boolean(job.pause_requested);
      $('#cancelJob').disabled = !job.running && job.status !== 'queued';
      $('#cancelJob').textContent = `Cancel ${type.control_noun || 'job'}`;
      if (job.auto_resume_job_id) {
        state.selectedJob = job.auto_resume_job_id;
        if (state.eventsConnected) refreshSelectedJob();
        else schedulePoll(500);
        return;
      }
      if (!state.eventsConnected && (job.running || job.status === 'queued')) schedulePoll();
      else if (!state.eventsConnected && job.status === 'usage_limited' && job.auto_resume && job.resume_after_utc) schedulePoll(15000);
    } catch (error) {
      toast(error.message, true);
    }
  }

  async function controlSelectedJob(action) {
    if (!state.selectedJob) return;
    const selected = state.activityJobs.find(job => job.id === state.selectedJob);
    const noun = jobType(selected).control_noun || 'assessment';
    if (action === 'cancel' && !window.confirm(
      `Cancel this ${noun}? The active provider or device process will stop and completed evidence will be preserved.`
    )) return;
    const button = action === 'pause' ? $('#pauseJob') : $('#cancelJob');
    button.disabled = true;
    try {
      const job = await api(`/api/jobs/${state.selectedJob}/${action}`, { method: 'POST' });
      toast(action === 'pause' ? 'Pause requested; waiting for the current stage to finish.' : 'Cancellation requested.');
      $('#livePill').textContent = String(job.status || action).replaceAll('_', ' ').toUpperCase();
      renderOverviewSnapshot(await api('/api/overview'));
    } catch (error) {
      toast(error.message, true);
      await refreshSelectedJob();
    }
  }

  function schedulePoll(delay = 2200) {
    if (state.eventsConnected) return;
    clearTimeout(state.poll);
    state.poll = setTimeout(async () => {
      await refreshSelectedJob();
      try { renderOverviewSnapshot(await api('/api/overview')); } catch (_) {}
    }, delay);
  }

  function bindActivityControls() {
    $('#pauseJob').addEventListener('click', () => controlSelectedJob('pause'));
    $('#cancelJob').addEventListener('click', () => controlSelectedJob('cancel'));
    $('#copyLog').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('#consoleOutput').textContent);
        toast('Console copied.');
      } catch (_) {
        toast('Clipboard access was unavailable.', true);
      }
    });
  }

  return { bindActivityControls, controlSelectedJob, refreshSelectedJob, renderJobs, schedulePoll };
}
