'use strict';

import { $, $$, api, escapeText, formatDate, option, state, toast } from './core.js';

export function createDeviceController() {
  async function discoverDevices(showToast = true) {
    const button = $('#discoverDevices');
    button.disabled = true;
    button.textContent = 'Discovering…';
    try {
      const data = await api('/api/devices');
      state.devices = data.devices;
      const wirelessDevices = data.wireless_devices || [];
      const list = $('#deviceOptions');
      list.replaceChildren();
      data.devices.forEach(device => option(list, device.serial, `${device.serial} · ${device.state}`));
      wirelessDevices.filter(device => device.endpoint).forEach(device => {
        if (![...list.options].some(item => item.value === device.endpoint)) {
          option(list, device.endpoint, `${device.endpoint} · ${String(device.status).replaceAll('_', ' ')}`);
        }
      });
      renderWirelessDevices(wirelessDevices);
      const connectedCount = data.devices.filter(device => device.state === 'device').length;
      $('#deviceCount').textContent = connectedCount;
      $('#deviceCaption').textContent = wirelessDevices.length
        ? `${connectedCount} connected · ${wirelessDevices.length} known wireless`
        : data.devices.length ? `${data.devices.length} ADB entries` : 'none visible';
      const target = $('#newForm [name="target"]');
      if (!target.value && data.devices.filter(device => device.state === 'device').length === 1) {
        target.value = data.devices.find(device => device.state === 'device').serial;
        resetReadiness();
      }
      if (showToast) toast(`Found ${data.devices.length} ADB entries and ${wirelessDevices.length} wireless records.`);
    } catch (error) { toast(error.message, true); }
    finally { button.disabled = false; button.textContent = 'Discover devices'; }
  }
  
  function wirelessStatusLabel(status) {
    return ({
      connected: 'Connected', previously_paired: 'Previously paired', discovered: 'Discovered',
      unauthorized: 'Unauthorized', offline: 'Offline',
    })[status] || String(status || 'Unknown').replaceAll('_', ' ');
  }
  
  function renderWirelessDevices(devices) {
    const container = $('#wirelessDevices');
    if (!devices.length) {
      container.innerHTML = '<p>No paired or discovered wireless devices yet.</p>';
      return;
    }
    container.innerHTML = devices.map(device => {
      const endpoint = device.endpoint || '';
      const pairedIsLatest = Boolean(device.paired_utc && (!device.last_connected_utc || new Date(device.paired_utc) > new Date(device.last_connected_utc)));
      const timestamp = pairedIsLatest ? device.paired_utc : (device.last_connected_utc || device.paired_utc);
      const timestampLabel = pairedIsLatest ? 'Paired' : device.last_connected_utc ? 'Last connected' : 'Last known';
      const detail = endpoint || (device.pairing_endpoint ? `${device.pairing_endpoint} · pairing address` : device.host) || 'Connection address not discovered';
      const action = endpoint
        ? `<button class="text-button wireless-action" type="button" data-wireless-endpoint="${escapeText(endpoint)}" data-wireless-connected="${device.status === 'connected'}">${device.status === 'connected' ? 'Use device' : 'Connect'}</button>`
        : '<small class="wireless-address-needed">Enter its connection address below</small>';
      return `<article class="wireless-device ${escapeText(device.status)}">
        <span class="wireless-dot" aria-hidden="true"></span>
        <div><strong>${escapeText(detail)}</strong><small>${escapeText(timestamp ? `${timestampLabel} ${formatDate(timestamp)}` : device.details || 'Visible on the local network')}</small></div>
        <b>${escapeText(wirelessStatusLabel(device.status))}</b>${action}
      </article>`;
    }).join('');
    $$('[data-wireless-endpoint]').forEach(button => button.addEventListener('click', () => useWirelessDevice(button)));
  }
  
  async function useWirelessDevice(button) {
    const endpoint = button.dataset.wirelessEndpoint;
    const connected = button.dataset.wirelessConnected === 'true';
    button.disabled = true;
    try {
      if (!connected) {
        await api('/api/devices/connect', { method: 'POST', body: JSON.stringify({ endpoint }) });
      }
      const transport = $('#newForm [name="transport"][value="wireless"]');
      transport.checked = true;
      updateTransport();
      $('#newForm [name="target"]').value = endpoint;
      resetReadiness();
      toast(connected ? 'Wireless device selected.' : 'Wireless device connected and selected.');
      await discoverDevices(false);
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }
  
  
  function resetReadiness() {
    state.readiness = null;
    $('#readinessToken').value = '';
    $('#readinessState').textContent = 'NOT CHECKED';
    $('#readinessState').className = 'readiness-state';
    $('#readinessResults').innerHTML = '<p>Device settings changed. Run readiness again before starting.</p>';
  }
  
  function resetResumeReadiness() {
    $('#resumeReadinessToken').value = '';
    $('#resumeReadinessState').textContent = 'NOT CHECKED';
    $('#resumeReadinessState').className = 'readiness-state';
    $('#resumeReadinessResults').innerHTML = '<p>Continuation device settings changed. Run readiness before submitting.</p>';
  }
  
  async function runReadinessFor(form, controls) {
    const button = $(controls.button);
    const stateElement = $(controls.state);
    const resultsElement = $(controls.results);
    const tokenElement = $(controls.token);
    const target = form.elements.target.value.trim();
    const authorized = form.elements.authorized.checked;
    if (!target) { toast('Enter the exact device target first.', true); return; }
    if (!authorized && (form.elements.start_frida.checked || form.elements.frida_binary.files[0])) {
      toast('Confirm authorization before deploying or starting Frida.', true);
      return;
    }
    const body = new FormData();
    body.append('transport', form.elements.transport.value);
    body.append('target', target);
    body.append('frida_server', form.elements.frida_server.value.trim());
    body.append('frida_version', form.elements.frida_version.value);
    body.append('start_frida', String(form.elements.start_frida.checked));
    body.append('authorized', String(authorized));
    const binary = form.elements.frida_binary.files[0];
    if (binary) body.append('frida_binary', binary, binary.name);
    button.disabled = true;
    button.textContent = 'Checking…';
    stateElement.textContent = 'RUNNING';
    stateElement.className = 'readiness-state running';
    try {
      const response = await fetch('/api/devices/readiness', { method: 'POST', body });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Readiness failed (${response.status})`);
      tokenElement.value = result.token || '';
      stateElement.textContent = result.ready ? 'READY' : 'BLOCKED';
      stateElement.className = `readiness-state ${result.ready ? 'ready' : 'blocked'}`;
      resultsElement.innerHTML = result.checks.map(check => `
        <div class="readiness-check ${check.passed ? 'passed' : check.required ? 'failed' : 'info'}">
          <span>${check.passed ? '✓' : check.required ? '×' : 'i'}</span>
          <div><strong>${escapeText(check.name)}</strong><small>${escapeText(check.detail || 'No detail')}</small></div>
        </div>`).join('');
      toast(result.ready ? `Device ready · ${result.abi} · SDK ${result.sdk}` : 'Device readiness is blocked. Review the failed checks.', !result.ready);
    } catch (error) {
      stateElement.textContent = 'ERROR';
      stateElement.className = 'readiness-state blocked';
      resultsElement.innerHTML = `<p>${escapeText(error.message)}</p>`;
      toast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = 'Run readiness';
    }
  }
  
  function runReadiness() {
    state.readiness = null;
    return runReadinessFor($('#newForm'), {
      button: '#runReadiness', state: '#readinessState',
      results: '#readinessResults', token: '#readinessToken',
    });
  }
  
  function runResumeReadiness() {
    return runReadinessFor($('#resumeForm'), {
      button: '#runResumeReadiness', state: '#resumeReadinessState',
      results: '#resumeReadinessResults', token: '#resumeReadinessToken',
    });
  }
  
  function updateTransport() {
    const wireless = $('#newForm [name="transport"]:checked').value === 'wireless';
    $('#wirelessPairing').hidden = !wireless;
    $('#targetLabel').textContent = wireless ? 'Wireless connection address' : 'Device target';
    const target = $('#newForm [name="target"]');
    target.placeholder = wireless ? '192.168.1.20:CONNECTION_PORT' : 'emulator-5554 or ADB serial';
    $('#targetHint').textContent = wireless
      ? 'Use the separate IP:port shown on the main Wireless debugging screen.'
      : 'Use the exact serial shown by ADB.';
    if (!wireless) $('#newForm [name="pair_code"]').value = '';
  }
  
  async function pairWirelessDevice() {
    const button = $('#pairDevice');
    const endpoint = $('#newForm [name="pair_endpoint"]').value.trim();
    const codeInput = $('#newForm [name="pair_code"]');
    const code = codeInput.value.trim();
    const status = $('#pairingStatus');
    button.disabled = true;
    status.className = '';
    status.textContent = 'Pairing with the device…';
    try {
      const result = await api('/api/devices/pair', {
        method: 'POST', body: JSON.stringify({ endpoint, code }),
      });
      status.className = 'success';
      status.textContent = result.connection_endpoint
        ? `${result.message} The connection address was discovered automatically.`
        : `${result.message} Enter the separate connection address below.`;
      if (result.connection_endpoint) {
        $('#newForm [name="target"]').value = result.connection_endpoint;
        resetReadiness();
      }
      toast(result.message);
      await discoverDevices(false);
    } catch (error) {
      status.className = 'error';
      status.textContent = error.message;
      toast(error.message, true);
    } finally {
      codeInput.value = '';
      button.disabled = false;
    }
  }
  
  
  return {
    discoverDevices, pairWirelessDevice, resetReadiness, resetResumeReadiness,
    runReadiness, runResumeReadiness, updateTransport,
  };
}
