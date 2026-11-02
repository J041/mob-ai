import { $, $$, api, escapeText, state } from './core.js';

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export async function openArtifactBrowser(runId, requestedPath = '') {
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
    const terminal = manifest.run.terminal || {};
    $('#artifactSubtitle').textContent = `${manifest.run.id} · ${String(manifest.run.status || 'analysis').replaceAll('_', ' ')}${terminal.label ? ` · ${terminal.label}` : ''}`;
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

