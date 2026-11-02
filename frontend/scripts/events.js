'use strict';

import { state } from './core.js';

export function connectOverviewEvents({ onOverview, onFallback }) {
  if (!('EventSource' in window)) {
    state.eventsConnected = false;
    onFallback();
    return null;
  }
  state.eventSource?.close();
  const source = new EventSource('/api/events');
  state.eventSource = source;
  source.onopen = () => {
    state.eventsConnected = true;
    clearTimeout(state.poll);
  };
  source.addEventListener('overview', event => {
    try {
      const payload = JSON.parse(event.data);
      state.eventsConnected = true;
      clearTimeout(state.poll);
      onOverview(payload);
    } catch (_) {
      // Ignore one malformed event; EventSource remains connected for the next snapshot.
    }
  });
  source.onerror = () => {
    state.eventsConnected = false;
    onFallback();
  };
  return source;
}
