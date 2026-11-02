export const state = {
  overview: null, devices: [], selectedJob: null, poll: null, authPoll: null,
  authProvider: 'codex', readiness: null, continuationMode: 'resume',
  expandedRuns: new Set(), knownAttemptRuns: new Set(), jobStripScroll: 0,
  artifactRun: null, artifactManifest: null, artifactCategory: null,
  artifactPath: null, artifactPreviewCache: new Map(), assistantRun: null,
  assistantTurns: [], assistantFailures: [],
  eventSource: null, eventsConnected: false,
};

export const $ = selector => document.querySelector(selector);
export const $$ = selector => [...document.querySelectorAll(selector)];

export async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

export function toast(message, error = false) {
  const element = $('#toast');
  element.textContent = message;
  element.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.className = 'toast'; }, 3800);
}

export function option(parent, value, label) {
  const item = document.createElement('option');
  item.value = value;
  item.textContent = label || value;
  parent.append(item);
}

export function formatDate(value) {
  if (!value) return 'unknown';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export function escapeText(value) {
  const node = document.createElement('span');
  node.textContent = value ?? '';
  return node.innerHTML;
}
