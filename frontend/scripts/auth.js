'use strict';

import { $, api, state, toast } from './core.js';

export function createAuthController({ refreshOverview }) {
  function renderAuth(data) {
    const provider = data.id || state.authProvider;
    const account = data.account_label || (provider === 'codex' ? 'ChatGPT' : 'Claude');
    const flow = data.device_flow || {};
    const cleanOutput = String(flow.output || '').replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '');
    $('#authKicker').textContent = `${provider.toUpperCase()} AUTHENTICATION`;
    $('#authTitle').textContent = `Connect your ${account} account`;
    $('#authCopy').textContent = `Use your ${account} account for the ${data.label || provider} reasoning provider. Browser authentication persists in a private Docker volume.`;
    $('#authStatus').textContent = data.authenticated ? `${account} account connected` : (flow.running ? 'Waiting for browser authorization…' : 'Not connected');
    $('#authOutput').textContent = data.authenticated ? (data.detail || `Logged in with ${account}.`) : (cleanOutput || data.detail || `Select Continue with ${account} to begin.`);
    const start = $('#startAuth');
    start.disabled = Boolean(flow.running || data.authenticated);
    start.textContent = data.authenticated ? 'Connected' : (flow.running ? 'Waiting for sign-in…' : `Continue with ${account}`);
    const signOut = $('#signOutAuth');
    signOut.hidden = !data.authenticated;
    signOut.disabled = false;
    const match = cleanOutput.match(/https:\/\/[^\s\u001b]+/);
    const link = $('#authLink');
    if (match && !data.authenticated) {
      link.href = match[0].replace(/[),.;]+$/, '');
      link.hidden = false;
    } else {
      link.hidden = true;
      link.removeAttribute('href');
    }
    const code = cleanOutput.match(/\b[A-Z0-9]{4,8}-[A-Z0-9]{4,8}\b/)?.[0] || '';
    const copyCode = $('#copyAuthCode');
    copyCode.hidden = !code || data.authenticated;
    copyCode.dataset.code = code;
    clearTimeout(state.authPoll);
    if (flow.running) state.authPoll = setTimeout(refreshAuth, 1500);
    if (data.authenticated) refreshOverview();
  }

  async function refreshAuth() {
    try { renderAuth(await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth`)); }
    catch (error) { toast(error.message, true); }
  }

  async function openAuth(provider = 'codex') {
    state.authProvider = provider;
    $('#authDialog').showModal();
    await refreshAuth();
  }

  async function beginAuth() {
    $('#startAuth').disabled = true;
    try { renderAuth(await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth/login`, { method: 'POST' })); }
    catch (error) { toast(error.message, true); $('#startAuth').disabled = false; }
  }

  async function signOutAuth() {
    const button = $('#signOutAuth');
    button.disabled = true;
    button.textContent = 'Signing out…';
    try {
      const account = state.authProvider === 'codex' ? 'ChatGPT' : 'Claude';
      const auth = await api(`/api/providers/${encodeURIComponent(state.authProvider)}/auth/logout`, { method: 'POST' });
      renderAuth(auth);
      await refreshOverview(true);
      toast(`${account} account signed out.`);
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    } finally {
      button.textContent = 'Sign out';
    }
  }

  return { beginAuth, openAuth, refreshAuth, renderAuth, signOutAuth };
}
