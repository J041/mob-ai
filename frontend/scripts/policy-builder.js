'use strict';

import { $, api, escapeText } from './core.js';

const BASE_CHECKS = ['Process alive', 'Foreground package', 'No crash or ANR'];
const SUPPORTED_CHECKS = new Set([
  'process_alive', 'foreground_package', 'activity_reached', 'no_crash',
  'ui_text_regex', 'ui_text_not_regex', 'log_regex', 'log_not_regex',
  'frida_regex', 'output_regex',
]);
const REGEX_CHECKS = new Set([
  'ui_text_regex', 'ui_text_not_regex', 'log_regex', 'log_not_regex',
  'frida_regex', 'output_regex',
]);
let advancedPolicy = null;
let savedPolicyDocument = '';

function policyCheckDescription(check) {
  const detail = check.activity || check.package || check.pattern || '';
  return `${check.type}${detail ? `: ${detail}` : ''}`;
}

function setPolicyJsonStatus(message, kind = '') {
  const status = $('#policyJsonStatus');
  status.textContent = message;
  status.className = `policy-json-status${kind ? ` ${kind}` : ''}`;
}

function renderAdvancedPolicy(policy) {
  advancedPolicy = policy;
  const preview = $('#policyJsonPreview');
  if (!policy) {
    preview.hidden = true;
    preview.replaceChildren();
    updatePolicyBuilder();
    return;
  }
  const checks = policy.checks || [];
  preview.hidden = false;
  preview.innerHTML = `
    <div class="policy-json-meta">
      <span>${escapeText(policy.name || 'Success policy')}</span>
      <span>${escapeText(String(policy.mode || 'all').toUpperCase())} checks</span>
      <span>${policy.baseline_required ? 'Baseline required' : 'No baseline requirement'}</span>
      <span>${escapeText(`${policy.min_passes || policy.repeat || 1}/${policy.repeat || 1} passes`)}</span>
    </div>
    <div class="policy-json-checks">${checks.map((check, index) => `
      <div class="policy-json-check"><i>${index + 1}</i><span>${escapeText(policyCheckDescription(check))}</span></div>
    `).join('')}</div>`;
  updatePolicyBuilder();
}

function validatePolicyInBrowser(content) {
  let policy;
  try { policy = JSON.parse(content); }
  catch (error) { throw new Error(`Invalid JSON: ${error.message}`); }
  if (!policy || Array.isArray(policy) || typeof policy !== 'object') throw new Error('The policy must be a JSON object.');
  if (!['all', 'any'].includes(policy.mode || 'all')) throw new Error('mode must be "all" or "any".');
  if (!Array.isArray(policy.checks) || !policy.checks.length) throw new Error('checks must be a non-empty array.');
  policy.checks.forEach((check, index) => {
    if (!check || !SUPPORTED_CHECKS.has(check.type)) throw new Error(`Check ${index + 1} has an unsupported type.`);
    if (check.type === 'activity_reached' && !check.activity) throw new Error(`Check ${index + 1} requires activity.`);
    if (REGEX_CHECKS.has(check.type)) {
      if (!check.pattern) throw new Error(`Check ${index + 1} requires pattern.`);
      try { new RegExp(check.pattern, 'im'); }
      catch (error) { throw new Error(`Check ${index + 1} has an invalid regex: ${error.message}`); }
    }
  });
  const repeat = policy.repeat ?? 1;
  const minPasses = policy.min_passes ?? repeat;
  if (!Number.isInteger(repeat) || repeat < 1 || repeat > 3) throw new Error('repeat must be an integer from 1 to 3.');
  if (!Number.isInteger(minPasses) || minPasses < 1 || minPasses > repeat) throw new Error('min_passes must be between 1 and repeat.');
  return { ...policy, mode: policy.mode || 'all', repeat, min_passes: minPasses, baseline_required: Boolean(policy.baseline_required), name: policy.name || 'Success policy' };
}

function previewEditorContent() {
  const content = $('#policyJsonDocument').value.trim();
  savedPolicyDocument = '';
  if (!content) {
    renderAdvancedPolicy(null);
    setPolicyJsonStatus('Load an existing policy or paste JSON to begin.');
    return;
  }
  try {
    const policy = validatePolicyInBrowser(content);
    renderAdvancedPolicy(policy);
    setPolicyJsonStatus('JSON is structurally valid in the browser. Validate and save to confirm it against the pipeline schema.', 'valid');
  } catch (error) {
    renderAdvancedPolicy(null);
    setPolicyJsonStatus(error.message, 'error');
  }
}

export async function loadAdvancedPolicy() {
  const path = $('#policyJsonPath').value.trim();
  if (!path) throw new Error('Enter a workspace-relative JSON policy path.');
  setPolicyJsonStatus('Loading and validating policy...');
  try {
    const result = await api(`/api/policies/preview?path=${encodeURIComponent(path)}`);
    $('#policyJsonDocument').value = result.document;
    savedPolicyDocument = result.document;
    renderAdvancedPolicy(result.policy);
    setPolicyJsonStatus(`Validated ${result.path}.`, 'valid');
    return result;
  } catch (error) {
    renderAdvancedPolicy(null);
    setPolicyJsonStatus(error.message, 'error');
    throw error;
  }
}

export async function saveAdvancedPolicy() {
  const editor = $('#policyJsonDocument');
  const content = editor.value.trim();
  validatePolicyInBrowser(content);
  setPolicyJsonStatus('Validating and saving policy...');
  try {
    const sourceName = $('#policyJsonFile').dataset.filename || $('#policyJsonPath').value.split(/[\\/]/).pop() || 'custom-success-policy.json';
    const result = await api('/api/policies', { method: 'POST', body: JSON.stringify({ name: sourceName, content }) });
    $('#policyJsonPath').value = result.path;
    editor.value = result.document;
    savedPolicyDocument = result.document;
    renderAdvancedPolicy(result.policy);
    setPolicyJsonStatus(`Valid and saved as ${result.path}.`, 'valid');
    return result;
  } catch (error) {
    setPolicyJsonStatus(error.message, 'error');
    throw error;
  }
}

export async function ensureAdvancedPolicyReady(form) {
  if (form.elements.policy_preset.value !== 'advanced') return;
  const content = $('#policyJsonDocument').value.trim();
  if (!content) await loadAdvancedPolicy();
  else if (content !== savedPolicyDocument || !form.elements.success_spec.value.trim()) await saveAdvancedPolicy();
  else validatePolicyInBrowser(content);
}

export function bindAdvancedPolicyEditor() {
  $('#loadPolicyJson').addEventListener('click', () => loadAdvancedPolicy().catch(() => {}));
  $('#savePolicyJson').addEventListener('click', () => saveAdvancedPolicy().catch(() => {}));
  $('#policyJsonDocument').addEventListener('input', previewEditorContent);
  $('#policyJsonFile').addEventListener('change', async event => {
    const file = event.currentTarget.files[0];
    if (!file) return;
    if (file.size > 256 * 1024) {
      setPolicyJsonStatus('Success-policy JSON must be 256 KB or smaller.', 'error');
      return;
    }
    event.currentTarget.dataset.filename = file.name;
    $('#policyJsonPath').value = '';
    $('#policyJsonDocument').value = await file.text();
    previewEditorContent();
  });
  $('#policyPreset').addEventListener('change', () => {
    if ($('#policyPreset').value === 'advanced' && !$('#policyJsonDocument').value.trim()) {
      loadAdvancedPolicy().catch(() => {});
    }
  });
}

function setInputsEnabled(container, enabled) {
  container.querySelectorAll('input, select').forEach(input => { input.disabled = !enabled; });
}

function updatePassOptions(repeat, select) {
  const previous = Math.min(repeat, Number(select.value || repeat));
  select.replaceChildren();
  for (let value = 1; value <= repeat; value += 1) {
    const option = document.createElement('option');
    option.value = String(value);
    option.textContent = `${value} ${value === 1 ? 'pass' : 'passes'}`;
    select.append(option);
  }
  select.value = String(previous || repeat);
}

function broadPatternWarning(value, regexMode) {
  if (!value.trim()) return '';
  const items = regexMode ? value.split('|') : value.split(/[,\r\n]+/);
  const broad = items.map(item => item.trim().replace(/[^a-z0-9 ]/gi, '').toLowerCase())
    .filter(item => ['root', 'frida', 'hook', 'debug', 'magisk'].includes(item));
  return broad.length
    ? `Broad term “${broad[0]}” may match unrelated framework output. Use a complete warning phrase or restrict it to visible UI.`
    : '';
}

function regexError(value) {
  if (!value.trim()) return '';
  try { new RegExp(value, 'im'); return ''; }
  catch (error) { return error.message; }
}

export function updatePolicyBuilder() {
  const form = $('#newForm');
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

  const regexMode = form.elements.policy_use_regex.checked;
  const phraseFields = $('#policyPhraseFields');
  const regexFields = $('#policyRegexFields');
  phraseFields.hidden = regexMode;
  regexFields.hidden = !regexMode;
  setInputsEnabled(phraseFields, generated && !forbidden.hidden && !regexMode);
  setInputsEnabled(regexFields, generated && !forbidden.hidden && regexMode);

  const repeat = Number(form.elements.policy_repeat.value || 1);
  updatePassOptions(repeat, form.elements.policy_min_passes);
  const minPasses = Number(form.elements.policy_min_passes.value || repeat);
  const checks = [...BASE_CHECKS];
  if (!activity.hidden && form.elements.expected_activity.value.trim()) checks.push('Expected activity reached');
  if (!expected.hidden && form.elements.expected_ui_pattern.value.trim()) checks.push('Expected visible text');
  if (!forbidden.hidden) {
    const uiValue = regexMode ? form.elements.forbidden_ui_pattern.value : form.elements.forbidden_ui_phrases.value;
    const logValue = regexMode ? form.elements.forbidden_log_pattern.value : form.elements.forbidden_log_phrases.value;
    if (uiValue.trim()) checks.push('Visible warning absent');
    if (logValue.trim()) checks.push('Application-log warning absent');
  }
  const advancedChecks = advancedPolicy?.checks?.map(policyCheckDescription) || [];
  $('#policyCheckList').innerHTML = generated
    ? checks.map(check => `<span>${escapeText(check)}</span>`).join('')
    : advancedChecks.length
      ? advancedChecks.map(check => `<span>${escapeText(check)}</span>`).join('')
      : '<span>Load or enter a JSON policy to preview its checks</span>';

  const warnings = [];
  if (generated && !forbidden.hidden) {
    const uiValue = regexMode ? form.elements.forbidden_ui_pattern.value : form.elements.forbidden_ui_phrases.value;
    const logValue = regexMode ? form.elements.forbidden_log_pattern.value : form.elements.forbidden_log_phrases.value;
    const broad = broadPatternWarning(uiValue, regexMode) || broadPatternWarning(logValue, regexMode);
    if (broad) warnings.push(broad);
    if (regexMode) {
      const invalid = regexError(uiValue) || regexError(logValue);
      if (invalid) warnings.push(`Invalid regular expression: ${invalid}`);
    }
    if (!uiValue.trim() && !logValue.trim()) warnings.push('Add at least one visible-UI or application-log warning.');
  }
  if (generated && preset === 'screen_reached' && !form.elements.expected_activity.value.trim() && !form.elements.expected_ui_pattern.value.trim()) {
    warnings.push('Specify an expected activity or visible text for this preset.');
  }
  const warning = $('#policyWarning');
  warning.hidden = !warnings.length;
  warning.textContent = warnings.join(' ');

  const descriptions = {
    basic: 'the app remains alive, foreground, and crash-free',
    detection_removed: 'the app remains usable and configured detection warnings are absent',
    screen_reached: 'the app remains usable and reaches the expected screen',
    custom: 'the app satisfies every populated activity, text, and warning check',
    advanced: 'the selected JSON policy passes exactly as written',
  };
  const effectiveRepeat = generated ? repeat : (advancedPolicy?.repeat || 1);
  const effectiveMinPasses = generated ? minPasses : (advancedPolicy?.min_passes || effectiveRepeat);
  const threshold = `${effectiveMinPasses} of ${effectiveRepeat} validation ${effectiveRepeat === 1 ? 'attempt' : 'attempts'}`;
  $('#policySummary').innerHTML = `<b>Success means:</b> ${escapeText(descriptions[preset])}. <strong>${escapeText(threshold)} must pass.</strong>`;
  $('#policyBaselineText').textContent = preset === 'detection_removed'
    ? 'Without the bypass, a configured warning must be observed or another required check must fail. Hooked validation must then remove that warning and meet the pass threshold.'
    : 'Without the bypass, at least one required check must fail before the hooked attempt can demonstrate improvement.';
}
