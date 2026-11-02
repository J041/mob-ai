import { $$, option, state } from './core.js';

function providerCatalog(form) {
  const provider = form?.elements?.provider?.value || 'codex';
  return state.overview?.model_catalogs?.[provider] || (provider === 'codex' ? state.overview?.models : null);
}

export function renderModelOptions() {
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

export function reasoningLabel(level) {
  const names = { none: 'None', minimal: 'Minimal', low: 'Low', medium: 'Medium', high: 'High', xhigh: 'Extra high', max: 'Maximum', ultra: 'Ultra' };
  return names[level.effort] || level.effort;
}

export function renderReasoningOptions(modelSelect, catalog = providerCatalog(modelSelect.form)) {
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

