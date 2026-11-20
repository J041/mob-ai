'use strict';

import { $, $$, api, escapeText, formatDate, state, toast } from './core.js';

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

export function createTrashController({ renderOverviewSnapshot }) {
  function renderTrash() {
    const list = $('#trashList');
    $('#trashCount').textContent = state.trashArchives.length ? String(state.trashArchives.length) : '';
    if (!state.trashArchives.length) {
      list.innerHTML = '<p class="assistant-empty">Trash is empty.</p>';
      return;
    }
    list.innerHTML = state.trashArchives.map(archive => `
      <article class="trash-row">
        <div class="trash-main">
          <strong>${escapeText(archive.package || archive.run_id)}</strong>
          <code>${escapeText(archive.run_id)}</code>
          <small>Deleted ${escapeText(formatDate(archive.archived_utc))} &middot; ${escapeText(formatBytes(archive.size_bytes))} &middot; ${Number(archive.job_count || 0)} job records</small>
        </div>
        <div class="trash-actions">
          <button class="resume-button" type="button" data-trash-restore="${escapeText(archive.archive_id)}">Restore</button>
          <button class="resume-button delete-run" type="button" data-trash-purge="${escapeText(archive.archive_id)}">Delete permanently</button>
        </div>
      </article>`).join('');
    $$('[data-trash-restore]').forEach(button => button.addEventListener('click', () => restoreArchive(button.dataset.trashRestore, button)));
    $$('[data-trash-purge]').forEach(button => button.addEventListener('click', () => purgeArchive(button.dataset.trashPurge, button)));
  }

  async function loadTrash() {
    const payload = await api('/api/trash/runs');
    state.trashArchives = payload.archives || [];
    renderTrash();
  }

  async function openTrash() {
    const dialog = $('#trashDialog');
    $('#trashList').innerHTML = '<p class="assistant-empty">Loading deleted assessments&hellip;</p>';
    if (!dialog.open) dialog.showModal();
    try { await loadTrash(); }
    catch (error) { $('#trashList').innerHTML = `<p class="assistant-warning">${escapeText(error.message)}</p>`; }
  }

  async function restoreArchive(archiveId, button) {
    const archive = state.trashArchives.find(item => item.archive_id === archiveId);
    if (!archive || !window.confirm(`Restore ${archive.package || archive.run_id}?\n\nRun ID: ${archive.run_id}`)) return;
    button.disabled = true;
    try {
      const result = await api(`/api/trash/runs/${encodeURIComponent(archive.archive_id)}/restore`, {
        method: 'POST', body: JSON.stringify({ confirm_run_id: archive.run_id }),
      });
      const warning = (result.warnings || []).join(' ');
      toast(warning ? `Assessment restored. ${warning}` : 'Assessment and job history restored.');
      renderOverviewSnapshot(await api('/api/overview'));
      await loadTrash();
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  async function purgeArchive(archiveId, button) {
    const archive = state.trashArchives.find(item => item.archive_id === archiveId);
    if (!archive) return;
    const confirmation = window.prompt(
      `Permanently delete ${archive.package || archive.run_id} and free ${formatBytes(archive.size_bytes)}?\n\n` +
      `This cannot be recovered. Type the run ID to continue:\n${archive.run_id}`,
    );
    if (confirmation !== archive.run_id) {
      if (confirmation !== null) toast('Run ID did not match. Nothing was deleted.', true);
      return;
    }
    button.disabled = true;
    try {
      const result = await api(`/api/trash/runs/${encodeURIComponent(archive.archive_id)}`, {
        method: 'DELETE', body: JSON.stringify({ confirm_run_id: confirmation }),
      });
      toast(`Deleted permanently; freed ${formatBytes(result.bytes_freed)}.`);
      await loadTrash();
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  return { loadTrash, openTrash };
}
