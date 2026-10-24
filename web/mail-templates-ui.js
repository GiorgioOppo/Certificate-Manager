(() => {
  'use strict';
  const core = () => window.CertificateCore;
  const t = (key, values = []) => window.CertificateI18n.t(`mailTemplates.${key}`, values);
  const el = (tag, cls, text) => core().element(tag, cls, text);
  const api = (path, body, method = 'POST') => core().request(`/api/mail-templates/${path}`, { method, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const bool = value => value === true || value === 1 || value === '1';
  const storageKey = 'certificate-manager-mail-template-drafts-v1';
  let mounted = false, loading = false, busy = false, state = null, fields, controls, status, notice, previewBox, settingsForm, settingsFields, settingsStatus, variableList;
  let selected = '', drafts = {}, settingsDraft = null, persisted = true, previewGeneration = 0, certificateSignature = '', eventSignature = '';
  let activeEditor = null;
  try {
    const saved = JSON.parse(window.sessionStorage.getItem(storageKey) || 'null');
    if (saved && saved.version === 1) { selected = typeof saved.selected === 'string' ? saved.selected : ''; drafts = saved.drafts && typeof saved.drafts === 'object' && !Array.isArray(saved.drafts) ? saved.drafts : {}; settingsDraft = saved.settings && typeof saved.settings === 'object' ? saved.settings : null; }
  } catch (_) { persisted = false; }
  function persist() {
    try { window.sessionStorage.setItem(storageKey, JSON.stringify({ version: 1, selected, drafts, settings: settingsDraft })); persisted = true; }
    catch (_) { persisted = false; }
  }
  const dirty = () => Object.keys(drafts).length > 0 || !!settingsDraft;
  const valueKey = (alert, audience) => `${alert}|${audience}`;
  const savedTemplate = () => (state?.templates || []).find(item => valueKey(item.alert, item.audience) === selected);
  function templateValues(item) { return { subject: String(item?.subject || ''), body: String(item?.body || ''), copy_enabled: bool(item?.copy_enabled) }; }
  function currentValues() { return { subject: fields.subject.input.value, body: fields.body.input.value, copy_enabled: controls.copy.checked }; }
  function equals(a, b) { return a.subject === b.subject && a.body === b.body && a.copy_enabled === b.copy_enabled; }
  function selectedParts() { return { alert: controls.alert.value, audience: controls.audience.value }; }
  function say(text, error = false) { notice.textContent = text; notice.classList.toggle('import-chain-warning', error); }
  function invalidatePreview() { previewGeneration++; previewBox.replaceChildren(); }
  function showStatus() {
    const item = savedTemplate();
    status.textContent = drafts[selected] ? t('draft_status') : bool(item?.customized) ? t('custom_status') : t('default_status');
    status.classList.toggle('mail-template-draft', !!drafts[selected]);
    controls.discard.hidden = !drafts[selected];
    controls.draftSummary.textContent = Object.keys(drafts).length ? t('drafts_preserved', [Object.keys(drafts).length]) : '';
    controls.save.disabled = busy || !drafts[selected];
    settingsStatus.textContent = settingsDraft ? t('draft_status') : t('settings_saved_status');
    settingsForm.querySelector('[type="submit"]').disabled = busy || !settingsDraft;
    controls.discardSettings.hidden = !settingsDraft;
  }
  function remember() {
    if (!state || !selected) return;
    const values = currentValues();
    if (equals(values, templateValues(savedTemplate()))) delete drafts[selected]; else drafts[selected] = values;
    persist(); showStatus(); invalidatePreview(); say('');
  }
  function fillTemplate() {
    selected = valueKey(controls.alert.value, controls.audience.value);
    const item = savedTemplate(), values = drafts[selected] || templateValues(item);
    fields.subject.input.value = String(values.subject || ''); fields.body.input.value = String(values.body || ''); controls.copy.checked = controls.audience.value !== 'other' && bool(values.copy_enabled);
    controls.copy.disabled = busy || controls.audience.value === 'other';
    controls.copyHelp.textContent = controls.audience.value === 'other' ? t('copy_other_help') : controls.audience.value === 'self' ? t('copy_self_help') : t('copy_group_help');
    controls.audienceHelp.textContent = t(`audience_${controls.audience.value}_help`);
    persist(); showStatus(); invalidatePreview(); say('');
  }
  function fillSettings() {
    const values = settingsDraft || state.settings || {};
    settingsFields.self_name.input.value = String(values.self_name || ''); settingsFields.self_email.input.value = String(values.self_email || '');
    showStatus();
  }
  function rememberSettings() {
    const values = { self_name: settingsFields.self_name.input.value, self_email: settingsFields.self_email.input.value };
    settingsDraft = values.self_name === String(state.settings?.self_name || '') && values.self_email === String(state.settings?.self_email || '') ? null : values;
    persist(); showStatus();
  }
  function lock(value) {
    busy = value;
    for (const input of document.querySelectorAll('#mail-templates-content input, #mail-templates-content textarea, #mail-templates-content select, #mail-templates-content button')) input.disabled = value;
    if (!value) { controls.copy.disabled = controls.audience.value === 'other'; showStatus(); }
  }
  function makeSelect(labelText, id) {
    const wrapper = el('label', 'workflow-form-field'), title = el('span', '', labelText), input = el('select'); input.id = id; wrapper.append(title, input); return { wrapper, input };
  }
  function addVariables() {
    variableList.replaceChildren();
    for (const name of state.variables || []) {
      const token = `{{${name}}}`;
      const insert = core().action(token, () => {
        const input = activeEditor || fields.body.input;
        input.focus(); const start = input.selectionStart ?? input.value.length, end = input.selectionEnd ?? start;
        const next = input.value.slice(0, start) + token + input.value.slice(end);
        if (next.length > input.maxLength) { say(t('field_too_long'), true); return; }
        input.value = next; input.setSelectionRange(start + token.length, start + token.length); remember();
      });
      insert.className = 'mail-template-variable'; insert.title = t('insert_variable', [token]); variableList.append(insert);
    }
  }
  async function load({ keepSelection = true } = {}) {
    if (loading) return; loading = true;
    // A refresh holds the same UI lock as a mutation, so an older read cannot
    // overwrite the state reloaded after saving. Draft values stay in memory.
    const wasBusy = busy;
    if (mounted) lock(true);
    try {
      const data = await core().request('/api/mail-templates/state'); state = data;
      if (!mounted) mount();
      const previous = keepSelection ? selected.split('|') : [];
      controls.alert.replaceChildren(); controls.audience.replaceChildren();
      for (const item of data.alerts || []) core().appendOption(controls.alert, item.id, t(`alert_${item.id}`));
      for (const item of data.audiences || []) core().appendOption(controls.audience, item.id, t(`audience_${item.id}`));
      if ([...controls.alert.options].some(item => item.value === previous[0])) controls.alert.value = previous[0];
      if ([...controls.audience.options].some(item => item.value === previous[1])) controls.audience.value = previous[1];
      for (const [key, draft] of Object.entries(drafts)) { const saved = data.templates.find(item => valueKey(item.alert, item.audience) === key); if (!saved || equals(templateValues(draft), templateValues(saved))) delete drafts[key]; }
      fillTemplate(); fillSettings(); addVariables(); updateContext();
    } catch (error) {
      if (mounted) say(error.message, true);
      else { const host = core().byId('mail-templates-content'); host.replaceChildren(el('p', 'import-chain-warning', error.message), core().action(t('reload'), () => load())); }
    } finally { loading = false; if (mounted) lock(wasBusy); }
  }
  async function saveTemplate(event) {
    event.preventDefault(); if (busy || !controls.form.reportValidity()) return;
    const parts = selectedParts(), key = selected, values = currentValues();
    const body = new URLSearchParams({ ...parts, subject: values.subject, body: values.body, copy_enabled: values.copy_enabled ? '1' : '0' });
    lock(true);
    try { await api('template', body, 'PUT'); delete drafts[key]; persist(); await load(); say(t('saved')); }
    catch (error) { say(error.message, true); }
    finally { lock(false); }
  }
  async function resetTemplate() {
    if (busy) return;
    const content = el('p', '', t('reset_help'));
    const confirmed = window.CertificateUI ? await window.CertificateUI.modal(t('reset_title'), content, t('reset')) : window.confirm(t('reset_help'));
    if (!confirmed) return;
    const key = selected, parts = selectedParts(); lock(true);
    try { await api('reset', new URLSearchParams(parts)); delete drafts[key]; persist(); await load(); say(t('reset_done')); }
    catch (error) { say(error.message, true); }
    finally { lock(false); }
  }
  async function previewTemplate() {
    if (busy || !controls.form.reportValidity()) return;
    const generation = ++previewGeneration;
    const body = new URLSearchParams({ ...selectedParts(), subject: fields.subject.input.value, body: fields.body.input.value });
    if (controls.certificate.value) body.set('certificate_id', controls.certificate.value);
    if (controls.event.value) body.set('event_id', controls.event.value);
    controls.preview.disabled = true; say(t('preview_loading'));
    try {
      const data = await api('preview', body);
      if (generation !== previewGeneration) return;
      const heading = el('h4', '', t('preview_title')), subject = el('p', 'mail-template-preview-subject', data.subject), message = el('pre', 'mail-template-preview-body', data.body);
      previewBox.replaceChildren(heading, el('p', 'workflow-help', data.sample ? t('sample_preview') : t('certificate_preview')), subject, message, el('p', 'workflow-help', data.attachment ? t('attachment_yes') : t('attachment_no'))); say(t('preview_ready'));
    } catch (error) { if (generation === previewGeneration) say(error.message, true); }
    finally { controls.preview.disabled = busy; }
  }
  function updateContext() {
    if (!mounted) return;
    const next = core().getState(), certificates = next.certificates || [], events = next.monitor_events || [];
    const certKey = JSON.stringify(certificates.map(item => [item.id, item.common_name, item.not_after]));
    const evtKey = JSON.stringify(events.map(item => [item.id, item.kind, item.target, item.created_at]));
    if (certKey !== certificateSignature) {
      certificateSignature = certKey; const chosen = controls.certificate.value;
      controls.certificate.replaceChildren(); core().appendOption(controls.certificate, '', t('sample_certificate'));
      for (const cert of certificates) core().appendOption(controls.certificate, cert.id, `${core().name(cert)} · ID ${cert.id} · ${core().date(cert.not_after)}`);
      if ([...controls.certificate.options].some(item => item.value === chosen)) controls.certificate.value = chosen;
    }
    if (evtKey !== eventSignature) {
      eventSignature = evtKey; const chosen = controls.event.value;
      controls.event.replaceChildren(); core().appendOption(controls.event, '', t('sample_event'));
      for (const event of events) core().appendOption(controls.event, event.id, `${core().date(event.created_at, true)} · ${event.target} · ${t(`alert_${event.kind}`)}`);
      if ([...controls.event.options].some(item => item.value === chosen)) controls.event.value = chosen;
    }
  }
  function mount() {
    const host = core().byId('mail-templates-content'); if (!host || mounted) return; mounted = true; controls = {};
    const intro = el('p', 'workflow-help', t('intro')), impact = el('p', 'mail-template-impact', t('future_only'));
    const settings = el('details', 'mail-template-self-settings'); settings.append(el('summary', '', t('self_settings_title')));
    settingsForm = el('form', 'workflow-form'); settingsForm.autocomplete = 'off';
    settingsFields = { self_name: core().formField(t('self_name'), 'text', '', { maxLength: 120 }), self_email: core().formField(t('self_email'), 'email', '', { maxLength: 254 }) };
    settingsFields.self_name.input.id = 'mail-template-self-name'; settingsFields.self_email.input.id = 'mail-template-self-email';
    const settingsGrid = el('div', 'workflow-form-grid'); settingsGrid.append(...Object.values(settingsFields).map(field => field.wrapper));
    const settingsActions = el('div', 'action-row'), saveSettings = el('button', 'button button-primary', t('save_settings')); saveSettings.type = 'submit';
    controls.discardSettings = core().action(t('discard_draft'), () => { settingsDraft = null; persist(); fillSettings(); });
    settingsStatus = el('span', 'mail-template-status'); settingsStatus.setAttribute('role', 'status');
    settingsActions.append(saveSettings, controls.discardSettings, settingsStatus); settingsForm.append(el('p', 'workflow-help', t('self_settings_help')), settingsGrid, settingsActions);
    settingsForm.addEventListener('input', rememberSettings);
    settingsForm.addEventListener('submit', async event => {
      event.preventDefault(); if (busy || !settingsForm.reportValidity()) return;
      const body = new URLSearchParams({ self_name: settingsFields.self_name.input.value.trim(), self_email: settingsFields.self_email.input.value.trim() }); lock(true);
      try { await api('settings', body, 'PUT'); settingsDraft = null; persist(); await load(); say(t('settings_saved')); }
      catch (error) { say(error.message, true); } finally { lock(false); }
    }); settings.append(settingsForm);
    controls.form = el('form', 'mail-template-editor'); controls.form.autocomplete = 'off';
    const selectors = el('div', 'workflow-form-grid');
    const alert = makeSelect(t('alert_label'), 'mail-template-alert'), audience = makeSelect(t('audience_label'), 'mail-template-audience'); controls.alert = alert.input; controls.audience = audience.input; selectors.append(alert.wrapper, audience.wrapper);
    controls.audienceHelp = el('p', 'workflow-help'); status = el('p', 'mail-template-status'); status.setAttribute('role', 'status'); controls.draftSummary = el('p', 'workflow-help');
    fields = { subject: core().formField(t('subject'), 'text', '', { required: true, maxLength: 998 }), body: core().formField(t('body'), 'textarea', '', { required: true, maxLength: 16384 }) };
    fields.subject.input.id = 'mail-template-subject'; fields.body.input.id = 'mail-template-body'; fields.body.input.rows = 11;
    for (const field of Object.values(fields)) { field.input.addEventListener('input', remember); field.input.addEventListener('focus', () => { activeEditor = field.input; }); }
    const copyLabel = el('label', 'checkbox-field'); controls.copy = el('input'); controls.copy.id = 'mail-template-copy'; controls.copy.type = 'checkbox'; copyLabel.append(controls.copy, el('span', '', t('copy_enabled'))); controls.copy.addEventListener('change', remember);
    controls.copyHelp = el('p', 'workflow-help');
    const variables = el('details', 'mail-template-variables'); variables.append(el('summary', '', t('variables_title')), el('p', 'workflow-help', t('variables_help'))); variableList = el('div', 'mail-template-variable-list'); variables.append(variableList);
    const actions = el('div', 'action-row'); controls.save = el('button', 'button button-primary', t('save')); controls.save.type = 'submit';
    controls.discard = core().action(t('discard_draft'), () => { delete drafts[selected]; persist(); fillTemplate(); });
    controls.reset = core().action(t('reset'), resetTemplate); controls.reload = core().action(t('reload'), () => load());
    actions.append(controls.save, controls.discard, controls.reset, controls.reload);
    controls.form.append(selectors, controls.audienceHelp, status, controls.draftSummary, fields.subject.wrapper, fields.body.wrapper, copyLabel, controls.copyHelp, variables, actions);
    controls.alert.addEventListener('change', fillTemplate); controls.audience.addEventListener('change', fillTemplate); controls.form.addEventListener('submit', saveTemplate);
    const preview = el('section', 'mail-template-preview'); preview.append(el('h4', '', t('preview_title')), el('p', 'workflow-help', t('preview_help')));
    const previewGrid = el('div', 'workflow-form-grid'); const cert = makeSelect(t('preview_certificate'), 'mail-template-certificate'), event = makeSelect(t('preview_event'), 'mail-template-event'); controls.certificate = cert.input; controls.event = event.input;
    core().appendOption(controls.certificate, '', t('sample_certificate')); core().appendOption(controls.event, '', t('sample_event'));
    controls.certificate.addEventListener('change', invalidatePreview); controls.event.addEventListener('change', invalidatePreview);
    previewGrid.append(cert.wrapper, event.wrapper); controls.preview = core().action(t('preview'), previewTemplate); previewBox = el('div', 'mail-template-preview-output'); preview.append(previewGrid, controls.preview, previewBox);
    notice = el('p', 'ops-feedback'); notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
    host.replaceChildren(intro, impact, settings, controls.form, preview, notice, el('p', 'workflow-help', t('smtp_help')));
    window.addEventListener('certificate-language-change', event => { if (dirty() || busy) { event.preventDefault(); say(t(busy ? 'busy_help' : 'unsaved_help'), true); } });
    window.addEventListener('beforeunload', event => { if (busy || (dirty() && !persisted)) { event.preventDefault(); event.returnValue = ''; } });
  }
  function render() {
    const c = core(); if (!c || c.currentPage !== 'delivery' || !c.byId('mail-templates-content')) return;
    if (mounted) updateContext(); else if (c.getState().csrf_token) void load();
  }
  window.CertificateMailTemplatesUI = { render };
  document.addEventListener('DOMContentLoaded', render);
})();
