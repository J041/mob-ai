'use strict';

import { $ } from './core.js';

export function updatePolicyBuilder() {
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
  $('#newForm [name="forbidden_ui_pattern"]').required = preset === 'detection_removed';
  const repeat = $('#newForm [name="policy_repeat"]').value;
  const descriptions = {
    basic: `Requires process alive, foreground package, and no crash · ${repeat}/${repeat} repeat passes`,
    detection_removed: `Basic checks + warning absent from UI and logcat · ${repeat}/${repeat} repeat passes`,
    screen_reached: `Basic checks + expected activity or visible text · ${repeat}/${repeat} repeat passes`,
    custom: `Basic checks plus every populated activity/text assertion · ${repeat}/${repeat} repeat passes`,
    advanced: 'Uses the selected JSON policy exactly as written.',
  };
  $('#policySummary').textContent = descriptions[preset];
}
